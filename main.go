//go:build linux

// OSINT-Check prüft URLs, Hashes, IPs und Domains parallel bei mehreren
// Threat-Intelligence-Diensten. Docker-Dienst mit Weboberfläche
// hinter einem HTTPS-Proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"osint-check/internal/config"
	"osint-check/internal/engine"
	"osint-check/internal/ioc"
	"osint-check/internal/server"
	"osint-check/internal/sources"
)

var version = "1.3.1"

func main() {
	trustProxy := flag.Bool("trust-proxy", false, "Dienst läuft hinter eigenem Reverse Proxy, der HTTPS beendet")
	flag.Parse()
	if err := run(*trustProxy); err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

func run(trustProxy bool) error {
	cfg, err := config.Load("/config/config.json")
	if err != nil {
		return err
	}
	if !trustProxy || cfg.Password == "" {
		return errors.New("Team-Passwort und HTTPS-Proxy (--trust-proxy) erforderlich")
	}
	listener, err := net.Listen("tcp", ":8484")
	if err != nil {
		return err
	}
	defer listener.Close()

	var cfgs []*engine.SourceConfig
	for _, src := range sources.All() {
		if cfg.Disabled(src.ID) {
			continue
		}
		if l, ok := cfg.Limits[src.ID]; ok {
			src.Limit = l
		}
		key := cfg.Keys[src.KeyName]
		cfgs = append(cfgs, &engine.SourceConfig{Source: src, Key: key, Limiter: engine.NewLimiter(src.Limit)})
	}
	eng := engine.New(sources.NewClient(nil), cfgs, ioc.Options{InternalDomains: cfg.InternalDomains})
	handler := server.New(eng, server.Options{Password: cfg.Password, TrustProxy: trustProxy})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	log.Printf("OSINT-Check %s läuft auf Port 8484", version)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		errc <- srv.Serve(listener)
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Println("Beende …")
		return srv.Shutdown(shutdown)
	}
}
