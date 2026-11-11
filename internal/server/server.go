// Package server stellt Oberfläche und JSON-API bereit.
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"osint-check/internal/engine"
	"osint-check/internal/ioc"
	"osint-check/internal/sources"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie = "osint_session"
	sessionTTL    = 12 * time.Hour
	maxBody       = 1 << 20
	loginWindow   = time.Minute
	loginAttempts = 5
	// Bremst auch verteilte Angriffe, ohne bei einzelnen Tippfehlern alle auszusperren.
	loginAttemptsGlobal = 30
	maxTrackedIPs       = 10000
	// Ein Gerät, das sich schon einmal erfolgreich angemeldet hat, erhält ein
	// signiertes Cookie. Es zählt nur gegen sein eigenes Fehlerkontingent, nicht
	// gegen die globale Grenze. So können verteilte Fehlversuche Unbekannter
	// das Team nicht aussperren, die globale Grenze für Unbekannte bleibt aber.
	deviceCookie = "osint_device"
	deviceTTL    = 90 * 24 * time.Hour
	maxDevices   = 10000
)

// Options beschreibt den Betriebsmodus.
type Options struct {
	Password string
	// TrustProxy wertet X-Forwarded-* aus. Nur setzen, wenn der Dienst
	// ausschließlich über einen eigenen Reverse Proxy erreichbar ist.
	TrustProxy bool
}

// Server ist der HTTP-Handler.
type Server struct {
	eng  *engine.Engine

	opt  Options
	mux  *http.ServeMux
	mu   sync.Mutex
	sess map[string]time.Time
	fail map[string][]time.Time
	all  []time.Time // Fehlversuche unbekannter Geräte
	// devKey signiert Geräte-Cookies. Er lebt nur im Speicher, nach einem
	// Neustart gelten Geräte wieder als unbekannt.
	devKey  []byte
	devFail map[string][]time.Time
}

// New baut den Server.
func New(eng *engine.Engine, opt Options) *Server {
	s := &Server{eng: eng, opt: opt, mux: http.NewServeMux(), sess: map[string]time.Time{}, fail: map[string][]time.Time{},
		devKey: make([]byte, 32), devFail: map[string][]time.Time{}}
	if _, err := rand.Read(s.devKey); err != nil {
		panic(err)
	}
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	s.mux.Handle("GET /", http.FileServerFS(static))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	s.mux.HandleFunc("GET /api/meta", s.handleMeta)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/check", s.auth(s.handleCheck))
	s.mux.HandleFunc("GET /api/jobs/{id}", s.auth(s.handleJob))
	s.mux.HandleFunc("DELETE /api/jobs/{id}", s.auth(s.handleCancel))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if s.secure(r) {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross_site", "Anfrage von fremder Seite abgelehnt")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) secure(r *http.Request) bool {
	return r.TLS != nil || (s.opt.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, key, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "error_code": key})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "json_required", "JSON erwartet")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "input_too_large", "Eingabe ist zu groß")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "Ungültige Anfrage")
		}
		return false
	}
	return true
}

// --- Anmeldung ----------------------------------------------------------

func (s *Server) authed(r *http.Request) bool {
	if s.opt.Password == "" {
		return true
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sess[hashToken(c.Value)]
	if !ok || time.Now().After(exp) {
		delete(s.sess, hashToken(c.Value))
		return false
	}
	return true
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeError(w, http.StatusUnauthorized, "login_required", "Anmeldung erforderlich")
			return
		}
		next(w, r)
	}
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// clientIP nimmt hinter einem Proxy den letzten Eintrag von X-Forwarded-For.
// Nur diesen trägt der eigene Proxy ein, alles davor kann der Client fälschen.
func (s *Server) clientIP(r *http.Request) string {
	if s.opt.TrustProxy {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func recentOnly(list []time.Time, cut time.Time) []time.Time {
	kept := list[:0]
	for _, t := range list {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}

func (s *Server) deviceMAC(id string) string {
	m := hmac.New(sha256.New, s.devKey)
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))
}

// knownDevice liefert die Geräte-ID, wenn der Request ein von diesem Prozess
// ausgestelltes Geräte-Cookie trägt, sonst "".
func (s *Server) knownDevice(r *http.Request) string {
	c, err := r.Cookie(deviceCookie)
	if err != nil {
		return ""
	}
	id, mac, ok := strings.Cut(c.Value, ".")
	if !ok || len(id) != 32 || !hmac.Equal([]byte(mac), []byte(s.deviceMAC(id))) {
		return ""
	}
	return id
}

// throttled prüft das passende Kontingent: bekannte Geräte nur ihr eigenes,
// unbekannte die Grenze pro IP und die globale Grenze.
func (s *Server) throttled(ip, dev string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-loginWindow)
	if dev != "" {
		d := recentOnly(s.devFail[dev], cut)
		if len(d) == 0 {
			delete(s.devFail, dev)
		} else {
			s.devFail[dev] = d
		}
		return len(d) >= loginAttempts
	}
	s.all = recentOnly(s.all, cut)
	recent := recentOnly(s.fail[ip], cut)
	if len(recent) == 0 {
		delete(s.fail, ip)
	} else {
		s.fail[ip] = recent
	}
	return len(recent) >= loginAttempts || len(s.all) >= loginAttemptsGlobal
}

func (s *Server) recordFailure(ip, dev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if dev != "" {
		if len(s.devFail) >= maxDevices {
			pruneStale(s.devFail, now.Add(-loginWindow))
		}
		s.devFail[dev] = append(s.devFail[dev], now)
		return
	}
	if len(s.fail) >= maxTrackedIPs {
		pruneStale(s.fail, now.Add(-loginWindow))
		if len(s.fail) >= maxTrackedIPs {
			s.fail = map[string][]time.Time{}
		}
	}
	s.fail[ip] = append(s.fail[ip], now)
	s.all = append(s.all, now)
}

// pruneStale entfernt nur abgelaufene Einträge statt alle Sperren zu löschen.
func pruneStale(m map[string][]time.Time, cut time.Time) {
	for k, v := range m {
		if len(v) == 0 || !v[len(v)-1].After(cut) { // Einträge sind zeitlich sortiert
			delete(m, k)
		}
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.opt.Password == "" {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	ip := s.clientIP(r)
	dev := s.knownDevice(r)
	if s.throttled(ip, dev) {
		log.Printf("Anmeldung gesperrt: %s", ip)
		writeError(w, http.StatusTooManyRequests, "login_throttled", "Zu viele Fehlversuche, bitte eine Minute warten")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	a, b := sha256.Sum256([]byte(body.Password)), sha256.Sum256([]byte(s.opt.Password))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		s.recordFailure(ip, dev)
		log.Printf("Anmeldung fehlgeschlagen: %s", ip)
		writeError(w, http.StatusUnauthorized, "wrong_password", "Passwort ist falsch")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, 500, "internal_error", "Interner Fehler")
		return
	}
	token := hex.EncodeToString(raw)
	s.mu.Lock()
	now := time.Now()
	for k, exp := range s.sess {
		if now.After(exp) {
			delete(s.sess, k)
		}
	}
	s.sess[hashToken(token)] = now.Add(sessionTTL)
	if dev != "" {
		delete(s.devFail, dev)
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.secure(r), MaxAge: int(sessionTTL.Seconds())})
	if dev == "" {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err == nil {
			v := hex.EncodeToString(id)
			http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: v + "." + s.deviceMAC(v), Path: "/api/login", HttpOnly: true,
				SameSite: http.SameSiteStrictMode, Secure: s.secure(r), MaxAge: int(deviceTTL.Seconds())})
		}
	}
	log.Printf("Anmeldung erfolgreich: %s", ip)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sess, hashToken(c.Value))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- API ----------------------------------------------------------------

type sourceInfo struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	KeyName    string        `json:"key_name,omitempty"`
	Configured bool          `json:"configured"`
	Types      []ioc.Type    `json:"types"`
	Limit      sources.Limit `json:"limit"`
	UsedToday  int           `json:"used_today"`
	License    string        `json:"license"`
	Signup     string        `json:"signup"`
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"auth_required": s.opt.Password != "", "authenticated": s.authed(r), "demo": false, "team": true, "max_indicators": engine.MaxIndicators}
	if s.authed(r) {
		list := []sourceInfo{}
		for _, c := range s.eng.Sources() {
			list = append(list, sourceInfo{ID: c.Source.ID, Name: c.Source.Name, KeyName: c.Source.KeyName,
				Configured: c.Source.KeyName == "" || c.Key != "", Types: c.Source.Types, Limit: c.Source.Limit,
				UsedToday: c.Limiter.UsedToday(), License: c.Source.License, Signup: c.Source.Signup})
		}
		out["sources"] = list
		out["editable"] = false
		out["internal_domains"] = s.eng.InternalDomains()
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Input string `json:"input"`
		Fresh bool   `json:"fresh"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	job, err := s.eng.Submit(body.Input, body.Fresh)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "busy", err.Error())
		return
	}
	view := job.View()
	log.Printf("Prüfung gestartet: %s, %d Werte", s.clientIP(r), len(view.Items)) // Werte selbst bleiben aus dem Log
	writeJSON(w, http.StatusAccepted, view)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	job := s.eng.Job(r.PathValue("id"))
	if job == nil {
		writeError(w, http.StatusNotFound, "job_expired", "Prüfung nicht gefunden, vermutlich wurde der Dienst neu gestartet")
		return
	}
	writeJSON(w, 200, job.View())
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	job := s.eng.Job(r.PathValue("id"))
	if job == nil {
		writeError(w, http.StatusNotFound, "job_missing", "Prüfung nicht gefunden")
		return
	}
	job.Cancel()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
