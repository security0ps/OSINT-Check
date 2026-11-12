# OSINT-Check

Prüft URLs, Hashes, IPs, Domains und lokale Dateien parallel bei mehreren Threat-Intelligence-Diensten. Die Weboberfläche läuft mit Docker Compose hinter Caddy.
<img width="1512" height="853" alt="image" src="https://github.com/user-attachments/assets/88fd7273-49cc-43c3-974a-72c01bfa19a5" />

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

## Installation mit Docker Compose

Voraussetzung ist Docker mit Compose. Die Konfiguration liegt in `deploy/`.

**Erstinstallation**

```bash
cd deploy
cp -i .env.example .env
chmod 600 .env                    # danach SITE_ADDRESS eintragen
mkdir -p config
cp -i config.example.json config/config.json   # eigene Domains eintragen
chmod 644 config/config.json      # enthält keine Geheimnisse, der Dienst läuft ohne Root
docker compose up -d --build
docker compose exec app cat /data/setup-code
```

Öffne die konfigurierte HTTPS-Adresse. Gib bei der ersten Einrichtung den Code aus dem letzten Befehl ein und lege ein Team-Passwort mit mindestens 12 Zeichen fest. Der Code gilt einmal und wird bei einem Neustart vor der Einrichtung erneuert. Wenn bereits ein Passwort über die Umgebung oder Konfiguration gesetzt ist, entfällt der Code und du kannst dich direkt anmelden.

API-Keys kannst du auf zwei Wegen setzen: in der `.env` (`OSINT_VIRUSTOTAL_KEY` usw.) oder nach der Anmeldung unter **Quellen** in der Weboberfläche. Das können alle Personen mit Team-Passwort. **Ein Key aus der Weboberfläche überschreibt den Key desselben Dienstes aus der `.env`**, auch nach Neustarts. Wer einen Key später in der `.env` tauscht, muss deshalb den Web-Key zurücksetzen (siehe Betrieb). Die drei abuse.ch-Quellen teilen sich einen Key.

Das Volume `app_data` enthält den gesalzenen Passwort-Hash und die API-Keys. Keys werden für Abfragen im Klartext benötigt. Schütze das Volume und seine Backups wie deine `.env`. Beim Austausch des Containers wird das Volume weiterverwendet. `docker compose down -v` löscht die Volumes einschließlich der Zugangsdaten.

**Vor dem Start:**

1. DNS-Eintrag des Hostnamens auf den Server zeigen lassen.
2. In der Firewall nur 80 und 443 öffnen. Port 8484 bleibt intern.
3. Bei einem rein internen Hostnamen in `deploy/Caddyfile` die Zeile `tls internal` aktivieren oder ein Firmenzertifikat nutzen.
4. Das Tool möglichst nicht offen ins Internet stellen, sondern nur über Firmennetz oder VPN. Die Vorlage für eine IP-Sperre steht im `Caddyfile`.
5. Unter `internal_domains` alle eigenen Domains eintragen, auch `*.firma.de` und Umlaut-Domains funktionieren.

**Betrieb:**

- Passwort zurücksetzen (im Browser festgelegt): `docker compose exec app rm /data/password.json`, dann `docker compose restart app` und den neuen Code mit `docker compose exec app cat /data/setup-code` abrufen. Danach im Browser ein neues Passwort festlegen. Alle werden abgemeldet.
- Passwort über `.env` setzen: `OSINT_PASSWORD` eintragen und `docker compose up -d`. Es hat Vorrang vor dem im Browser festgelegten Passwort. Alle werden abgemeldet.
- Web-Keys zurücksetzen, damit wieder die Keys aus der `.env` gelten: `docker compose exec app rm /data/keys.json`, dann `docker compose restart app`. Das entfernt alle in der Weboberfläche gespeicherten Keys.
- Logs enthalten Anmeldungen und Anzahl der geprüften Werte mit IP, aber nie die Werte selbst.

**HTTPS-Inspektion (SSL-Scanning) auf Ubuntu.** Wenn der Firmenproxy ausgehende API-Verbindungen prüft, muss seine CA im Zertifikatsspeicher des Docker-Hosts enthalten sein. Ist `/etc/ssl/certs/ca-certificates.crt` auf dem Host als Bundle-Datei vorhanden, ergänze in `deploy/docker-compose.yml` unter `services.app.volumes` diese Zeile:

```yaml
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Führe anschließend im Ordner `deploy/` den Befehl `docker compose up -d --force-recreate app` aus.

**Eigener Proxy statt Caddy:** Mit `--trust-proxy` starten und den Dienst nur für den Proxy erreichbar machen. Der Proxy muss den originalen `Host` weitergeben sowie `X-Forwarded-Proto` und `X-Forwarded-For` setzen, bei nginx etwa `proxy_set_header Host $host`.

**Im Serverbetrieb gilt:**

- Vor der Einrichtung sind Quellen und Prüfungen gesperrt. Ein gesetztes `OSINT_PASSWORD` hat Vorrang vor dem gespeicherten Passwort.
- Alle teilen sich ein Team-Passwort. Es gibt keine einzelnen Konten und kein Protokoll, wer was geprüft hat.
- Anmeldebremse: 5 Fehlversuche pro Minute je IP und 30 insgesamt, auch bei gleichzeitigen Anfragen. Browser, die sich schon einmal erfolgreich angemeldet haben, bekommen ein Geräte-Cookie und zählen nur gegen ihr eigenes Limit, Angriffe von außen sperren das Team also nicht aus. Nach einem Neustart des Dienstes gelten alle Browser wieder als neu.
- API-Keys liegen nur auf dem Server und erscheinen nie in der Oberfläche.
- Limits und Zwischenspeicher gelten für das ganze Team.

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
