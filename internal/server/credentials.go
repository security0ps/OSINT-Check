package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type passwordRecord struct {
	Salt []byte
	Hash []byte
}

type Credentials struct {
	dir      string
	mu       sync.Mutex
	password passwordRecord
	setup    string
	keys     map[string]string
}

func OpenCredentials(dir string, existingPassword string) (*Credentials, error) {
	c := &Credentials{dir: dir, keys: make(map[string]string)}
	for name, dest := range map[string]any{"password.json": &c.password, "keys.json": &c.keys} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, dest); err != nil {
			return nil, fmt.Errorf("invalid %s", name)
		}
		if name == "password.json" && (len(c.password.Hash) != 32 || len(c.password.Salt) != 16) {
			return nil, errors.New("invalid password record")
		}
	}
	if existingPassword == "" && c.password.Hash == nil {
		var token [24]byte
		rand.Read(token[:])
		c.setup = hex.EncodeToString(token[:])
		if err := c.write("setup-code", []byte(c.setup+"\n")); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Credentials) write(name string, data []byte) error {
	f, err := os.CreateTemp(c.dir, ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(c.dir, name))
}

// ApplyKeys runs once before serving requests. Web entries override config defaults.
func (c *Credentials) ApplyKeys(keys map[string]string) {
	for name, value := range c.keys {
		keys[name] = value
	}
}

func derive(password string, salt []byte) []byte {
	hash, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		panic(err)
	}
	return hash
}

func (s *Server) setupRequired() bool {
	c := s.opt.Credentials
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setup != ""
}

func (s *Server) validPassword(value string) bool {
	if s.opt.Password != "" {
		a, b := sha256.Sum256([]byte(value)), sha256.Sum256([]byte(s.opt.Password))
		return subtle.ConstantTimeCompare(a[:], b[:]) == 1
	}
	c := s.opt.Credentials
	if c == nil {
		return false
	}
	c.mu.Lock()
	record := c.password
	c.mu.Unlock()
	if record.Hash == nil || len(value) > 1024 {
		return false
	}
	return subtle.ConstantTimeCompare(derive(value, record.Salt), record.Hash) == 1
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var body struct{ Code, Password string }
	if !readJSON(w, r, &body) {
		return
	}
	c := s.opt.Credentials
	if c == nil {
		writeError(w, 403, "setup_closed", "Einrichtung geschlossen")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.setup == "" || subtle.ConstantTimeCompare([]byte(c.setup), []byte(body.Code)) != 1 {
		writeError(w, 403, "setup_denied", "Einrichtungscode ungültig oder bereits verwendet")
		return
	}
	if len([]rune(body.Password)) < 12 || len(body.Password) > 1024 {
		writeError(w, 400, "password_length", "Mindestens 12 Zeichen und höchstens 1024 Bytes verwenden")
		return
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	record := passwordRecord{salt, derive(body.Password, salt)}
	data, _ := json.Marshal(record)
	if err := c.write("password.json", data); err != nil {
		writeError(w, 500, "save_failed", "Einstellungen konnten nicht gespeichert werden")
		return
	}
	c.password, c.setup = record, ""
	os.Remove(filepath.Join(c.dir, "setup-code"))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name, Value string }
	if !readJSON(w, r, &body) {
		return
	}
	body.Value = strings.TrimSpace(body.Value)
	valid := false
	for _, source := range s.eng.Sources() {
		if body.Name != "" && source.Source.KeyName == body.Name {
			valid = true
			break
		}
	}
	if !valid || body.Value == "" || len(body.Value) > 4096 || strings.ContainsAny(body.Value, "\r\n") {
		writeError(w, 400, "invalid_request", "Ungültige Anfrage")
		return
	}
	c := s.opt.Credentials
	if c == nil {
		writeError(w, 403, "settings_managed", "Schlüsselverwaltung deaktiviert")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make(map[string]string, len(c.keys)+1)
	for k, v := range c.keys {
		keys[k] = v
	}
	keys[body.Name] = body.Value
	data, _ := json.Marshal(keys)
	if err := c.write("keys.json", data); err != nil {
		writeError(w, 500, "save_failed", "Einstellungen konnten nicht gespeichert werden")
		return
	}
	c.keys = keys
	s.eng.SetKey(body.Name, body.Value)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
