# OSINT-Check

Prüft URLs, Hashes, IPs, Domains und lokale Dateien parallel bei mehreren Threat-Intelligence-Diensten. Dieselbe Anwendung läuft lokal unter Windows und als Team-Server.

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
        │
        ▼
Regelbewertung · Details je Quelle · Export (CSV, JSON, Bericht)
```

## Schnellstart unter Windows

1. Die ZIP-Datei entpacken.
2. `Demo starten.bat` öffnen, um die Oberfläche mit erfundenen Daten zu testen. Dabei verlässt keine Anfrage den Rechner.
3. Für echte Prüfungen `osint-check.exe` starten und unter **Quellen** die API-Keys eintragen.
4. Das Konsolenfenster offen lassen. Beim Schließen wird das Tool beendet.

Die Datei ist nicht signiert, deshalb kann Windows SmartScreen warnen. Die mitgelieferte `.exe` ist mit Go 1.24.7 gebaut. Sie ist für den Einsatz auf dem eigenen PC gedacht, für den Dauerbetrieb den Docker-Weg nutzen oder sie mit aktuellem Go neu bauen. Die Einstellungen liegen in `%AppData%\OSINT-Check\config.json`. Auch die API-Keys stehen dort im Klartext, geschützt nur durch die Rechte des Windows-Benutzerkontos.

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

Das Tool setzt keine Lizenz durch. Bezahlte Limits trägst du unter `limits` in der `config.json` ein, einzelne Dienste schaltest du mit `disabled_sources` ab. Mehrere Gratis-Konten zur Limit-Umgehung sind bei VirusTotal und AbuseIPDB verboten.

## Team-Server

Empfohlen ist Docker Compose mit Caddy als HTTPS-Proxy. Die Vorlage liegt in `deploy/`.

```bash
cd deploy
cp .env.example .env
chmod 600 .env                    # danach Hostname, Passwort und Keys eintragen
mkdir -p config
cp config.example.json config/config.json   # eigene Domains eintragen
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

- Updates: `docker compose build --pull && docker compose up -d`, mindestens monatlich.
- Passwort ändern: `.env` anpassen und `docker compose up -d`. Dabei werden alle abgemeldet.
- Logs enthalten Anmeldungen und Anzahl der geprüften Werte mit IP, aber nie die Werte selbst.

**Eigener Proxy statt Caddy:** Mit `--trust-proxy` starten und den Dienst nur für den Proxy erreichbar machen. Der Proxy muss den originalen `Host` weitergeben sowie `X-Forwarded-Proto` und `X-Forwarded-For` setzen, bei nginx etwa `proxy_set_header Host $host`.

**Ohne Docker und Proxy:**

```bash
OSINT_PASSWORD="$(openssl rand -base64 24)" OSINT_VIRUSTOTAL_KEY=... \
./osint-check --server --listen 0.0.0.0:8484 --tls-cert cert.pem --tls-key key.pem
```

**Im Serverbetrieb gilt:**

- Der Dienst startet nur mit einem Passwort ab 12 Zeichen und im Netz nur mit TLS oder `--trust-proxy`.
- Alle teilen sich ein Team-Passwort. Es gibt keine einzelnen Konten und kein Protokoll, wer was geprüft hat.
- API-Keys liegen nur auf dem Server und erscheinen nie in der Oberfläche.
- Limits und Zwischenspeicher gelten für das ganze Team.

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
- Windows-Proxys aus den Systemeinstellungen werden nicht übernommen. In Firmennetzen `HTTPS_PROXY` setzen.

## Entwicklung

```bash
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o osint-check.exe .
```

Es gibt keine externen Abhängigkeiten außer der Go-Standardbibliothek. Für Releases immer eine aktuell unterstützte Go-Version verwenden, das Docker-Image baut mit Go 1.27. Weitere Dienste werden in `internal/sources` als `Source` ergänzt.
