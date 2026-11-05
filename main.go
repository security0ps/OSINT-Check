// OSINT-Check prüft URLs, Hashes, IPs und Domains parallel bei mehreren
// Threat-Intelligence-Diensten. Dieselbe Datei läuft lokal unter Windows und
// als Team-Server.
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
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"osint-check/internal/config"
	"osint-check/internal/engine"
	"osint-check/internal/ioc"
	"osint-check/internal/server"
	"osint-check/internal/sources"
)

var version = "1.1.0"

const minPasswordLength = 12

func main() {
	trustProxy := flag.Bool("trust-proxy", false, "Dienst läuft hinter eigenem Reverse Proxy, der HTTPS beendet")
	allowHTTP := flag.Bool("allow-http", false, "Unverschlüsselten Netzbetrieb erlauben (nur für Tests)")
	serverMode := flag.Bool("server", false, "Team-Betrieb: Anmeldung per Passwort, Keys nur über Konfiguration")
	listen := flag.String("listen", "", "Adresse, z. B. 0.0.0.0:8484 (Standard lokal: 127.0.0.1:8484)")
	configPath := flag.String("config", config.DefaultPath(), "Pfad zur config.json")
	tlsCert := flag.String("tls-cert", "", "TLS-Zertifikat (PEM)")
	tlsKey := flag.String("tls-key", "", "TLS-Schlüssel (PEM)")
	demo := flag.Bool("demo", false, "Demo mit erfundenen Daten, keine Anfrage verlässt den Rechner")
	noBrowser := flag.Bool("no-browser", false, "Browser nicht automatisch öffnen")
	showVersion := flag.Bool("version", false, "Version anzeigen")
	flag.Parse()
	if *showVersion {
		fmt.Println("OSINT-Check", version)
		return
	}
	if err := run(*serverMode, *listen, *configPath, *tlsCert, *tlsKey, *demo, *noBrowser, *trustProxy, *allowHTTP); err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		if runtime.GOOS == "windows" && !*serverMode {
			fmt.Fprintln(os.Stderr, "\nZum Beenden Enter drücken.")
			fmt.Scanln()
		}
		os.Exit(1)
	}
}

func run(team bool, listen, configPath, tlsCert, tlsKey string, demo, noBrowser, trustProxy, allowHTTP bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("--tls-cert und --tls-key müssen zusammen gesetzt werden")
	}
	if listen == "" {
		listen = "127.0.0.1:8484"
	}
	listener, err := bind(listen, team)
	if err != nil {
		return err
	}
	// Auch hinter einem Reverse Proxy kommt der Zugriff scheinbar von localhost,
	// daher braucht jeder Serverbetrieb ein Passwort.
	if !isLoopback(listener.Addr()) {
		team = true
	}
	if team && cfg.Password == "" {
		listener.Close()
		return errors.New("Für den Serverbetrieb muss ein Passwort gesetzt sein (OSINT_PASSWORD oder \"password\" in der config.json)")
	}
	if team && len(cfg.Password) < minPasswordLength {
		listener.Close()
		return fmt.Errorf("Das Passwort braucht mindestens %d Zeichen", minPasswordLength)
	}
	if team && !isLoopback(listener.Addr()) && tlsCert == "" && !trustProxy && !allowHTTP {
		listener.Close()
		return errors.New("Unverschlüsselter Netzbetrieb ist gesperrt. Nutze --tls-cert/--tls-key, oder --trust-proxy hinter einem HTTPS-Proxy")
	}

	var transport http.RoundTripper
	if demo {
		transport = sources.DemoTransport{}
	}
	var cfgs []*engine.SourceConfig
	for _, src := range sources.All() {
		if cfg.Disabled(src.ID) {
			continue
		}
		if l, ok := cfg.Limits[src.ID]; ok {
			src.Limit = l
		}
		key := cfg.Keys[src.KeyName]
		if demo {
			key = "demo"
			src.Limit = sources.Limit{}
		}
		cfgs = append(cfgs, &engine.SourceConfig{Source: src, Key: key, Limiter: engine.NewLimiter(src.Limit)})
	}
	eng := engine.New(sources.NewClient(transport), cfgs, ioc.Options{InternalDomains: cfg.InternalDomains, AllowDocumentation: demo})
	handler := server.New(eng, cfg, server.Options{Team: team, Demo: demo, Password: cfg.Password, TrustProxy: trustProxy})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	scheme := "http"
	if tlsCert != "" {
		scheme = "https"
	}
	addr := listener.Addr().String()
	display := scheme + "://" + addr
	fmt.Printf("OSINT-Check %s läuft: %s\n", version, display)
	if demo {
		fmt.Println("DEMO-MODUS: Alle Ergebnisse sind erfunden.")
	}
	if team {
		fmt.Println("Team-Betrieb: Anmeldung aktiv.")
		if allowHTTP {
			fmt.Println("WARNUNG: Passwort und Daten werden unverschlüsselt übertragen. Nur zum Testen verwenden.")
		}
	} else {
		fmt.Println("Zum Beenden dieses Fenster schließen oder Strg+C drücken.")
		fmt.Println("Einstellungen:", cfg.Path())
		if !noBrowser {
			go func() {
				time.Sleep(300 * time.Millisecond)
				if err := openBrowser(display); err != nil {
					fmt.Println("Bitte im Browser öffnen:", display)
				}
			}()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if tlsCert != "" {
			errc <- srv.ServeTLS(listener, tlsCert, tlsKey)
		} else {
			errc <- srv.Serve(listener)
		}
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

// bind versucht lokal bei belegtem Port die nächsten Ports.
func bind(addr string, team bool) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err == nil || team {
		return l, err
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	port, atoiErr := strconv.Atoi(portStr)
	if splitErr != nil || atoiErr != nil {
		return nil, err
	}
	for i := 1; i <= 10; i++ {
		if l, e := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port+i))); e == nil {
			return l, nil
		}
	}
	return nil, err
}

func isLoopback(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	}
	if strings.Contains(url, "://") {
		return exec.Command("xdg-open", url).Start()
	}
	return errors.New("unbekanntes System")
}
