# OSINT-Check

Prüft URLs, Hashes, IPs, Domains und lokale Dateien parallel bei mehreren Threat-Intelligence-Diensten. Linux-Anwendung mit Browseroberfläche, lokal oder als Team-Server. Unterstützte Release-Ziele: Linux amd64 und arm64. Es ist kein reines Terminalprogramm.

```text
Eingabe (Text oder Datei)
        │  Datei: SHA-256 entsteht im Browser, die Datei bleibt lokal
        ▼
Erkennung und Normalisierung ──► interne Werte: keine Abfrage
        │
        ▼
Warteschlange je Dienst (Limits, Zwischenspeicher 1 h)
        │
        ▼
VirusTotal · AbuseIPDB · urlscan.io · URLhaus · MalwareBazaar
ThreatFox · AlienVault OTX · CIRCL hashlookup · Feodo Tracker
Spamhaus DROP
        │
        ▼
Regelbewertung · Details je Quelle · Export (CSV, JSON, Bericht)
```

## Schnellstart unter Linux

Voraussetzungen: eine aktuell unterstützte Go-Version (mindestens die Version aus
`go.mod`) und optional `make`. Zum Kompilieren werden keine externen Go-Module benötigt.

```bash
make build
./dist/osint-check-linux-amd64 --demo --no-browser
# Im Browser öffnen: http://127.0.0.1:8484
```

Auf einem ARM64-Rechner `make build GOARCH=arm64` verwenden und anschließend
`./dist/osint-check-linux-arm64` starten. Ohne Make:

```bash
CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -o osint-check .
./osint-check --demo --no-browser
```

Für echte Prüfungen `--demo` weglassen und unter **Quellen** die API-Keys eintragen.
Ohne `--no-browser` versucht der lokale Modus, die Oberfläche mit `xdg-open` zu
öffnen. Auf Servern `--no-browser` beziehungsweise `--server` verwenden.
Beenden mit Strg+C oder SIGTERM.

Die Konfiguration liegt unter `$XDG_CONFIG_HOME/OSINT-Check/config.json`, sonst
unter `~/.config/OSINT-Check/config.json`. API-Keys werden dort im Klartext mit
Dateirechten `0600` gespeichert. Einen anderen Pfad setzt `--config`.
Der Programmeinstieg ist durch einen Go-Build-Tag auf Linux beschränkt.

## Lizenzen der Gratis-Zugänge

Vor dem Einsatz im Unternehmen unbedingt prüfen. Stand der Angaben: November 2026.

| Dienst | Key | Gratis-Limit | Nutzung im Unternehmen |
|---|---|---|---|
| VirusTotal | ja | 4/Minute, 500/Tag | Public API nicht für kommerzielle Produkte oder Geschäftsprozesse, die keine neuen Dateien beitragen |
| AbuseIPDB | ja | 1.000 Checks/Tag | Gratis-Plan nur nicht-kommerziell, Paid-Plan nötig |
| urlscan.io | ja | je Konto, siehe API Quotas | Kommerzielle Nutzung braucht laut AGB eine schriftliche Erlaubnis |
| URLhaus, MalwareBazaar, ThreatFox | ja, ein gemeinsamer abuse.ch-Key | Fair Use | Gratis für nicht gewinnorientierte Nutzung, Firmen brauchen ggf. ein Abo über Spamhaus |
| AlienVault OTX | ja | keine festen Angaben gefunden | Laut EULA kostenlos für nicht-kommerzielle Nutzung |
| CIRCL hashlookup | nein | keine festen Angaben gefunden | Bedingungen vor Einsatz prüfen |
| Feodo Tracker | nein | Download, 1 h zwischengespeichert | CC0, frei nutzbar |
| Spamhaus DROP | nein | Download, 12 h zwischengespeichert | Kostenlos für jede Nutzung, auch in Firmen. Automatische Downloads höchstens stündlich |

Das Tool setzt keine Lizenz durch. Bezahlte Limits trägst du unter `limits` in der `config.json` ein, einzelne Dienste schaltest du mit `disabled_sources` ab. Mehrere Gratis-Konten zur Limit-Umgehung sind bei VirusTotal und AbuseIPDB verboten.

## Team-Server

Empfohlen ist Docker Compose mit Caddy als HTTPS-Proxy. Die Vorlage liegt in `deploy/`.

**Erstinstallation**

```bash
cd deploy
cp -i .env.example .env
chmod 600 .env                    # danach Hostname, Passwort und Keys eintragen
mkdir -p config
cp -i config.example.json config/config.json   # eigene Domains eintragen
chmod 644 config/config.json      # enthält keine Geheimnisse, der Dienst läuft ohne Root
docker compose up -d --build
docker compose logs -f app
```

**Vor dem Start:**

1. DNS-Eintrag des Hostnamens auf den Server zeigen lassen.
2. In der Firewall nur 80 und 443 öffnen. Port 8484 bleibt intern.
3. Bei einem rein internen Hostnamen in `deploy/Caddyfile` die Zeile `tls internal` aktivieren oder ein Firmenzertifikat nutzen.
4. Das Tool möglichst nicht offen ins Internet stellen, sondern nur über Firmennetz oder VPN. Die Vorlage für eine IP-Sperre steht im `Caddyfile`.
5. Unter `internal_domains` alle eigenen Domains eintragen, auch `*.firma.de` und Umlaut-Domains funktionieren.

**Betrieb:**

- Passwort ändern: `.env` anpassen und `docker compose up -d`. Dabei werden alle abgemeldet.
- Logs enthalten Anmeldungen und Anzahl der geprüften Werte mit IP, aber nie die Werte selbst.

**Eigener Proxy statt Caddy:** Mit `--trust-proxy` starten und den Dienst nur für den Proxy erreichbar machen. Der Proxy muss den originalen `Host` weitergeben sowie `X-Forwarded-Proto` und `X-Forwarded-For` setzen, bei nginx etwa `proxy_set_header Host $host`.

**Ohne Docker und Proxy:**

```bash
read -rsp 'Team-Passwort: ' OSINT_PASSWORD; echo
export OSINT_PASSWORD
./dist/osint-check-linux-amd64 --server --listen 0.0.0.0:8484 --tls-cert cert.pem --tls-key key.pem
```

**Im Serverbetrieb gilt:**

- Der Dienst startet nur mit gesetztem Passwort und im Netz nur mit TLS oder `--trust-proxy`. Das Passwort ist frei wählbar.
- Alle teilen sich ein Team-Passwort. Es gibt keine einzelnen Konten und kein Protokoll, wer was geprüft hat.
- Anmeldebremse: 5 Fehlversuche pro Minute je IP und 30 insgesamt. Browser, die sich schon einmal erfolgreich angemeldet haben, bekommen ein Geräte-Cookie und zählen nur gegen ihr eigenes Limit, Angriffe von außen sperren das Team also nicht aus. Nach einem Neustart des Dienstes gelten alle Browser wieder als neu.
- API-Keys liegen nur auf dem Server und erscheinen nie in der Oberfläche.
- Limits und Zwischenspeicher gelten für das ganze Team.

## Linux-Dienst mit systemd (ohne Docker)

Die Unit in `deploy/osint-check.service` verwendet einen dynamischen Benutzer,
ein schreibgeschütztes Dateisystem und bindet nur an `127.0.0.1:8484`.
Ein **lokaler HTTPS-Reverse-Proxy** muss vorgeschaltet werden. Beim vorhandenen
Caddy-Beispiel dafür `reverse_proxy app:8484` durch
`reverse_proxy 127.0.0.1:8484` ersetzen. Das Compose-Netzwerk verwendet weiterhin
`app:8484`. Port 8484 nicht öffentlich weiterleiten.

```bash
make build
sudo install -m 0755 dist/osint-check-linux-amd64 /usr/local/bin/osint-check
sudo install -d -m 0755 /etc/osint-check
sudo install -m 0644 deploy/config.example.json /etc/osint-check/config.json
sudo install -m 0600 deploy/systemd.env.example /etc/osint-check/osint-check.env
sudoedit /etc/osint-check/osint-check.env
sudoedit /etc/osint-check/config.json
sudo install -m 0644 deploy/osint-check.service /etc/systemd/system/osint-check.service
sudo systemctl daemon-reload
sudo systemctl enable --now osint-check
sudo systemctl status osint-check
```

Auf ARM64 das entsprechende Binary installieren. In der Environment-Datei vor
dem Start mindestens `OSINT_PASSWORD` setzen; API-Keys sind optional.
`config.json` enthält in diesem Beispiel nur nicht geheime Einstellungen.
Nach Konfigurationsänderungen `sudo systemctl restart osint-check` ausführen.
Logs: `journalctl -u osint-check`. Es werden keine Dateien von Nutzern auf dem
Server gespeichert; die Datei-Hashes entstehen im Browser.

## Weiter analysieren

In den Details jedes Werts gibt es Buttons zu ANY.RUN TI Lookup, zu ANY.RUN Safebrowsing (URLs und Domains, startet direkt eine Sitzung mit dem Wert) und zu Joe Sandbox. Sie öffnen die Seite des Dienstes und kopieren den Wert in die Zwischenablage. Ob der Suchlink von ANY.RUN den Wert direkt einträgt, ist nicht garantiert, er steht dann zum Einfügen bereit. Ein Konto beim jeweiligen Dienst ist nötig. Gratis-Analysen sind dort öffentlich, deshalb keine vertraulichen Dateien oder URLs einreichen. Interne Werte bekommen keine Buttons.

## Was an wen geht

- **Dateien:** Nur der SHA-256-Hash verlässt den Browser. Dateiname und Inhalt bleiben lokal.
- **Interne Werte:** Private IPs, Hostnamen wie `.local` oder `.corp` und alle Domains aus `internal_domains` werden nicht abgefragt.
- **Alles andere:** Der Wert geht an die Dienste und wird dort vermutlich protokolliert. URLs aus E-Mails enthalten oft Token oder Adressen, das Tool warnt bei typischen Parametern, sendet die URL aber trotzdem.
- **Neue Scans:** Das Tool startet keine Scans und lädt nichts hoch, sondern fragt nur vorhandene Daten ab. Unbekannte Dateien bleiben daher „Kein Befund“.

## Bewertung

| Einstufung | Regel |
|---|---|
| Bösartig, hoch | mindestens zwei unabhängige Quellen melden bösartig, ohne Widerspruch |
| Bösartig, mittel | eine Quelle bösartig plus weiterer Hinweis, oder zwei Quellen mit Widerspruch |
| Bösartig, niedrig | nur eine Quelle meldet bösartig |
| Verdächtig | deutliche Hinweise oder mehrere schwache Hinweise |
| Kein Befund | Quellen haben geantwortet, ohne relevante Treffer. Das bedeutet **nicht**, dass der Wert sicher ist |
| Nicht geprüft | keine Quelle hat geantwortet |
| Intern | wurde bewusst nicht abgefragt |

Die Dienste von abuse.ch zählen zusammen als eine Stimme. VirusTotal stuft Dateien ab 15 Engines als bösartig ein, URLs, Domains und IPs ab 5. AbuseIPDB gilt ab Score 70 als bösartig und ab 40 als verdächtig. Die Schwellen stehen in `internal/sources/adapters.go` und sollten an eure Praxis angepasst werden. Vor dem Blockieren immer manuell prüfen, besonders bei CDN-Adressen.

## Bekannte Grenzen

- Die Anbindungen sind mit Antworten nach der Dokumentation getestet, noch nicht gegen die echten Dienste. Beim ersten Einsatz jede Quelle einmal mit einem bekannten Wert prüfen.
- Die Tageszähler liegen im Speicher und beginnen nach einem Neustart bei 0.
- Mit 4 Abfragen pro Minute dauern 100 Werte bei VirusTotal rund 25 Minuten. Die Oberfläche muss dabei offen bleiben, verlassene Prüfungen enden nach 3 Minuten.
- In Firmennetzen bei Bedarf `HTTPS_PROXY` und `NO_PROXY` in der Dienstumgebung setzen.
- Kann die Feodo-Liste nach Ablauf ihres einstündigen Caches nicht aktualisiert werden, wird die Quelle als Fehler angezeigt. Veraltete Listen werden nicht als aktuelle Prüfung verwendet.
- Spamhaus DROP enthält nur Netzbereiche, die komplett von Kriminellen kontrolliert werden. Ein Treffer ist ein starkes Signal, kein Treffer heißt aber nicht unauffällig. Nach einem erfolgreichen Download werden die Listen 12 Stunden zwischengespeichert. Nach einem Abruffehler wartet der laufende Dienst mindestens eine Stunde bis zum nächsten Versuch. Ausgehend muss `www.spamhaus.org` erreichbar sein.

## Entwicklung

```bash
make test       # Tests mit Race Detector; benötigt einen C-Compiler
make vet
make release    # statische Linux-Binaries für amd64 und arm64
```

GitHub Actions führt Tests und Linux-Builds aus. Die Weboberfläche ist in das
Binary eingebettet. Es gibt keine externen Go-Abhängigkeiten außer der
Standardbibliothek. Für Releases eine aktuell unterstützte Go-Version verwenden.
Die Mindestversion in `go.mod` ist keine Empfehlung für den produktiven Betrieb.
Weitere Dienste werden in `internal/sources` als `Source` ergänzt.

Version 1.3.0 ergänzt Spamhaus DROP für IPv4 und IPv6. Version 1.2.4 behebt die Befunde aus dem Sicherheitsaudit.
Version 1.2.3 korrigiert Kontingentverbrauch nach Abbruch, die Gewichtung gleicher
Quellengruppen, die Behandlung abschließender URL-Zeichen und den Feodo-Fehlerfall.
