// Package config lädt und speichert die Einstellungen.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	"osint-check/internal/sources"
)

// Config entspricht der Datei config.json.
type Config struct {
	Keys            map[string]string        `json:"keys"`
	InternalDomains []string                 `json:"internal_domains"`
	DisabledSources []string                 `json:"disabled_sources"`
	Limits          map[string]sources.Limit `json:"limits"`
	Password        string                   `json:"password,omitempty"`
}

// Umgebungsvariablen haben Vorrang vor der Datei (praktisch für Docker).
var envKeys = map[string]string{
	"virustotal": "OSINT_VIRUSTOTAL_KEY",
	"abuseipdb":  "OSINT_ABUSEIPDB_KEY",
	"urlscan":    "OSINT_URLSCAN_KEY",
	"abusech":    "OSINT_ABUSECH_KEY",
	"otx":        "OSINT_OTX_KEY",
}

// Load liest die Datei. Eine fehlende Datei ist kein Fehler.
func Load(path string) (*Config, error) {
	c := &Config{Keys: map[string]string{}, Limits: map[string]sources.Limit{}}
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

// Disabled meldet, ob eine Quelle abgeschaltet ist.
func (c *Config) Disabled(id string) bool {
	for _, d := range c.DisabledSources {
		if d == id {
			return true
		}
	}
	return false
}
