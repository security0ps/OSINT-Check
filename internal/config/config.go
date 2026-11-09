// Package config lädt und speichert die Einstellungen.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"osint-check/internal/sources"
)

// Config entspricht der Datei config.json.
type Config struct {
	Keys            map[string]string        `json:"keys"`
	InternalDomains []string                 `json:"internal_domains"`
	DisabledSources []string                 `json:"disabled_sources"`
	Limits          map[string]sources.Limit `json:"limits"`
	Password        string                   `json:"password,omitempty"`

	mu   sync.Mutex
	path string
}

// Umgebungsvariablen haben Vorrang vor der Datei (praktisch für Docker).
var envKeys = map[string]string{
	"virustotal": "OSINT_VIRUSTOTAL_KEY",
	"abuseipdb":  "OSINT_ABUSEIPDB_KEY",
	"urlscan":    "OSINT_URLSCAN_KEY",
	"abusech":    "OSINT_ABUSECH_KEY",
	"otx":        "OSINT_OTX_KEY",
}

// DefaultPath verwendet unter Linux $XDG_CONFIG_HOME, sonst ~/.config.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "osint-check-config.json"
	}
	return filepath.Join(dir, "OSINT-Check", "config.json")
}

// Load liest die Datei. Eine fehlende Datei ist kein Fehler.
func Load(path string) (*Config, error) {
	c := &Config{Keys: map[string]string{}, Limits: map[string]sources.Limit{}, path: path}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, c); err != nil {
			return nil, errors.New("config.json ist kein gültiges JSON: " + path)
		}
	}
	if c.Keys == nil {
		c.Keys = map[string]string{}
	}
	for name, env := range envKeys {
		if v := os.Getenv(env); v != "" {
			c.Keys[name] = v
		}
	}
	if v := os.Getenv("OSINT_PASSWORD"); v != "" {
		c.Password = v
	}
	return c, nil
}

// Path liefert den Dateipfad.
func (c *Config) Path() string { return c.path }

// Update ändert Keys und speichert atomar. Leere Werte löschen einen Key.
// Geschrieben wird nur der Dateiinhalt, damit Werte aus Umgebungsvariablen
// nicht in der Datei landen.
func (c *Config) Update(keys map[string]string, internal *[]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	onDisk := map[string]any{}
	data, err := os.ReadFile(c.path)
	if err == nil {
		if err := json.Unmarshal(data, &onDisk); err != nil {
			return errors.New("config.json ist kein gültiges JSON: " + c.path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	stored, _ := onDisk["keys"].(map[string]any)
	if stored == nil {
		stored = map[string]any{}
	}
	for k, v := range keys {
		if v == "" {
			delete(stored, k)
			delete(c.Keys, k)
		} else {
			stored[k] = v
			c.Keys[k] = v
		}
	}
	onDisk["keys"] = stored
	if internal != nil {
		onDisk["internal_domains"] = *internal
		c.InternalDomains = *internal
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	out, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Disabled meldet, ob eine Quelle abgeschaltet ist.
func (c *Config) Disabled(id string) bool {
	for _, d := range c.DisabledSources {
		if d == id {
			return true
		}
	}
	return false
}

// KeyNames liefert die bekannten Key-Namen.
func KeyNames() map[string]bool {
	out := map[string]bool{}
	for k := range envKeys {
		out[k] = true
	}
	return out
}
