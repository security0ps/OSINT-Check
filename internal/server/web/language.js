'use strict';
const language = (() => {
  const supported = ['de', 'en'];
  const preferred = (navigator.languages || [navigator.language])
    .map(tag => tag.toLowerCase().split('-')[0]).find(tag => supported.includes(tag));
  let current = preferred || 'de';
  const storageKey = 'osint-check.language';
  try {
    const saved = localStorage.getItem(storageKey);
    if (supported.includes(saved)) current = saved;
  } catch { /* Storage may be unavailable in private browsing. */ }

  const t = (de, en) => current === 'en' ? en : de;
  const english = {
    "hoch": "high",
    "mittel": "medium",
    "niedrig": "low",
    "Interner Wert, wurde nicht an externe Dienste gesendet": "Internal indicator. It was never sent to external services",
    "Blockieren prüfen und Vorfall nachgehen": "Consider blocking and investigate the incident",
    "Blockieren prüfen und zweite Quelle kontrollieren": "Consider blocking and verify with a second source",
    "Nur eine Quelle meldet das, vor dem Blockieren manuell prüfen": "Only one source reported this. Review manually before blocking",
    "Beobachten und manuell prüfen": "Monitor and review manually",
    "Prüfung läuft": "Check in progress",
    "Keine Quelle hat geantwortet, Ergebnis ist nicht aussagekräftig": "No sources responded. The result is inconclusive",
    "Keine Treffer. Das beweist nicht, dass der Wert sicher ist": "No hits. This does not establish that the indicator is safe",
    "Nur ein schwacher Hinweis, im Zweifel manuell prüfen": "Only one weak signal. Review manually if in doubt",
    "Port entfernt": "Port removed",
    "Domain aus E-Mail-Adresse, die Adresse selbst wird nicht übertragen": "Domain extracted from email address. The email address itself is never sent",
    "Zugangsdaten aus der URL entfernt": "Credentials removed from the URL",
    "URL enthält evtl. sensible Parameter und wird trotzdem an die Dienste übertragen": "This URL may contain sensitive parameters and will still be sent to the services",
    "Tageslimit erreicht": "Daily quota reached",
    "Zu viele laufende Prüfungen, bitte gleich noch einmal versuchen": "Too many checks are running. Try again shortly",
    "Zugriff nur über localhost erlaubt": "Access is restricted to localhost",
    "Anfrage von fremder Seite abgelehnt": "Cross-site request rejected",
    "JSON erwartet": "Expected JSON",
    "Eingabe ist zu groß": "Input is too large",
    "Ungültige Anfrage": "Invalid request",
    "Anmeldung erforderlich": "Sign-in required",
    "Zu viele Fehlversuche, bitte eine Minute warten": "Too many failed attempts. Wait one minute",
    "Passwort ist falsch": "Incorrect password",
    "Interner Fehler": "Internal error",
    "Prüfung nicht gefunden, vermutlich wurde der Dienst neu gestartet": "Check not found. The service may have restarted",
    "Prüfung nicht gefunden": "Check not found",
    "Einstellungen werden im Serverbetrieb über die Konfiguration gesetzt": "In server mode, settings are managed in the configuration file",
    "Unbekannter Key-Name": "Unknown key name",
    "Einstellungen konnten nicht gespeichert werden": "Could not save settings",
    "Abfragelimit des Dienstes erreicht": "Service rate limit reached",
    "Zeitüberschreitung beim Dienst": "Service timed out",
    "Antwort konnte nicht gelesen werden": "Could not read the response",
    "API-Key ungültig oder ohne Berechtigung": "Invalid API key or insufficient permissions",
    "Antwort des Dienstes hat ein unerwartetes Format": "Unexpected service response format",
    "Bitte mindestens einen Wert eingeben.": "Enter at least one indicator.",
    "Der Dienst hat nicht wie erwartet geantwortet": "The service returned an unexpected response",
    "Gespeichert": "Saved",
    "Gratis-Zugang nur für nicht-kommerzielle Nutzung": "Free access for non-commercial use only",
    "Public API nicht für kommerzielle Produkte und Geschäftsprozesse": "Public API excludes commercial products and business processes",
    "Bei VirusTotal nicht bekannt": "Unknown to VirusTotal",
    "Bekannt, aber noch keine Engine-Analyse vorhanden": "Known, but no engine analysis is available yet",
    "Tor-Exit-Node: wird von vielen Personen genutzt": "Tor exit node shared by many people",
    "CDN-Adresse: Eine Blockade kann viele legitime Websites treffen": "CDN address: blocking it may affect many legitimate sites",
    "Kommerzielle Nutzung braucht laut AGB eine schriftliche Erlaubnis": "The terms require written permission for commercial use",
    "Keine vorhandenen Scans gefunden": "No existing scans found",
    "Gratis für nicht gewinnorientierte Nutzung, Firmen brauchen ggf. ein Abo": "Free for non-profit use. Businesses may need a subscription",
    "Nicht bei URLhaus gelistet": "Not listed by URLhaus",
    "Als Malware-Payload gelistet": "Listed as a malware payload",
    "Nicht in MalwareBazaar": "Not in MalwareBazaar",
    "Malware-Sample bekannt": "Known malware sample",
    "Nicht bei ThreatFox gelistet (Treffer bis 6 Monate zurück)": "Not listed by ThreatFox (matches up to six months old)",
    "Bei OTX nicht bekannt": "Unknown to OTX",
    "Von OTX als bekannt unbedenklich geführt": "Listed by OTX as known benign",
    "In keinem Threat-Pulse erwähnt": "No mentions in threat pulses",
    "Öffentlicher Dienst ohne API-Key": "Public service, no API key required",
    "Nicht in der Datenbank bekannter Dateien": "Not in the database of known files",
    "Datei ist in Referenzdaten bekannter Software erfasst": "File found in reference data for known software",
    "In CIRCL als bekannt bösartig markiert": "Flagged as known malicious by CIRCL",
    "CC0, frei nutzbar und ohne API-Key": "CC0, free to use without an API key",
    "Nicht auf der Botnet-C2-Blockliste": "Not on the botnet C2 blocklist",
    "unbekannte Familie": "unknown family",
    "aktiv": "active",
    "unbekannt": "unknown",
    "Verdächtig": "Suspicious",
    "Community-Reputation": "Community reputation",
    "Bedrohung": "Threat",
    "Dateiname": "Filename",
    "Dateityp": "File type",
    "AS-Betreiber": "AS operator",
    "Land": "Country",
    "Letzte Analyse": "Last analysis",
    "Melder": "Reporters",
    "Nutzungsart": "Usage type",
    "Letzte Meldung": "Last report",
    "Letzter Scan": "Last scan",
    "Hoster": "Hosting provider",
    "Malware-Familie": "Malware family",
    "Erfasst": "Recorded",
    "Erstmals gesehen": "First seen",
    "Bedrohungsart": "Threat type",
    "Treffer": "Matches",
    "Grund": "Reason",
    "Malware-Familien": "Malware families",
    "Beispiel-Pulse": "Example pulse",
    "Quellen": "Sources",
    "Zuletzt aktiv": "Last active",
    "Kostenlos, auch für Firmen; Download höchstens stündlich": "Free, including for companies; download at most once per hour",
    "Netz auf der Spamhaus-DROP-Liste (von Kriminellen kontrolliert)": "Network on the Spamhaus DROP list (controlled by criminals)",
    "Nicht auf der Spamhaus-DROP-Liste": "Not on the Spamhaus DROP list",
    "Netzbereich": "Network range",
    "SBL-Eintrag": "SBL record",
    "Antwort hat ein unerwartetes Format": "Unexpected response format",
    "Antwort enthält einen ungültigen Netzbereich": "Response contains an invalid network range",
    "Liste ist leer": "List is empty"
  };
  const codes = {
    "internal": "Internal indicator. It was never sent to external services",
    "investigate": "Consider blocking and investigate the incident",
    "verify_source": "Consider blocking and verify with a second source",
    "single_source": "Only one source reported this. Review manually before blocking",
    "review": "Monitor and review manually",
    "pending": "Check in progress",
    "unanswered": "No sources responded. The result is inconclusive",
    "no_hits": "No hits. This does not establish that the indicator is safe",
    "weak_signal": "Only one weak signal. Review manually if in doubt",
    "localhost_only": "Access is restricted to localhost",
    "cross_site": "Cross-site request rejected",
    "json_required": "Expected JSON",
    "input_too_large": "Input is too large",
    "invalid_request": "Invalid request",
    "login_required": "Sign-in required",
    "login_throttled": "Too many failed attempts. Wait one minute",
    "wrong_password": "Incorrect password",
    "internal_error": "Internal error",
    "busy": "Too many checks are running. Try again shortly",
    "job_expired": "Check not found. The service may have restarted",
    "job_missing": "Check not found",
    "settings_managed": "In server mode, settings are managed in the configuration file",
    "unknown_key": "Unknown key name",
    "save_failed": "Could not save settings"
  };
  const patterns = [
    [/^Widerspruch: (\d+) Quelle\(n\) stufen den Wert als unauffällig ein$/, 'Conflicting evidence: $1 source(s) rate the indicator as clean'],
    [/^Unvollständig: (\d+) von (\d+) Quellen haben geantwortet$/, 'Incomplete: $1 of $2 sources responded'],
    [/^(\d+) von (\d+) Engines melden bösartig$/, '$1 of $2 engines flagged this as malicious'],
    [/^Abuse-Score (\d+)\/100 aus (\d+) Meldungen$/, 'Abuse score $1/100 from $2 reports'],
    [/^(\d+) Scans gefunden, von den letzten (\d+) sind (\d+) als bösartig markiert$/, '$1 scans found, $3 of the latest $2 flagged as malicious'],
    [/^(\d+) Scans gefunden, keiner der letzten (\d+) als bösartig markiert$/, '$1 scans found, none of the latest $2 flagged as malicious'],
    [/^(\d+) gelistete Malware-URLs auf diesem Host, (\d+) aktiv$/, '$1 listed malware URLs on this host, $2 active'],
    [/^Gelistet als (.+) \(Konfidenz (\d+) %\)$/, 'Listed as $1 (confidence $2%)'],
    [/^In (\d+) Threat-Pulses erwähnt$/, 'Mentioned in $1 threat pulses'],
    [/^Als bekannte Datei geführt \(Vertrauen (\d+)\/100\)$/, 'Listed as a known file (trust $1/100)'],
    [/^(URLhaus|MalwareBazaar|ThreatFox) meldet: (.*)$/, '$1 reports: $2'],
    [/^Malware-Sample bekannt: (.*)$/, 'Known malware sample: $1'],
    [/^Dienst nicht erreichbar: (.*)$/, 'Service unreachable: $1'],
    [/^Dienst meldet Störung \(HTTP (\d+)\)$/, 'Service error (HTTP $1)'],
    [/^unerwartete Antwort \(HTTP (\d+)\)$/, 'Unexpected response (HTTP $1)'],
    [/^Nicht lesbar: ([\s\S]*)$/, 'Could not read: $1'],
  ];

  function message(value, code) {
    if (!value || current === 'de') return value;
    if (Object.hasOwn(codes, code)) return codes[code];
    if (Object.hasOwn(english, value)) return english[value];
    const prefixes = [
      ['Achtung: ', 'Warning: '],
      ['Als Malware-URL gelistet, Status: ', 'Listed as a malware URL, status: '],
      ['Feodo-Liste konnte nicht aktualisiert werden: ', 'Could not update the Feodo list: '],
      ['Spamhaus-DROP-Liste konnte nicht geladen werden: ', 'Could not load the Spamhaus DROP list: '],
    ];
    for (const [de, en] of prefixes) {
      if (value.startsWith(de)) return en + message(value.slice(de.length));
    }
    if (value === 'Botnet-C2-Server: unbekannte Familie') return 'Botnet C2 server: unknown family';
    if (value.startsWith('Botnet-C2-Server: ')) return value.replace('Botnet-C2-Server: ', 'Botnet C2 server: ');
    for (const [pattern, replacement] of patterns) {
      if (pattern.test(value)) return value.replace(pattern, replacement);
    }
    return value;
  }

  function bind(onChange) {
    const select = document.getElementById('language');
    const labels = [...document.querySelectorAll('[data-en]')].map(node => [node, node.textContent]);
    const aria = [...document.querySelectorAll('[data-en-label]')].map(node => [node, node.getAttribute('aria-label')]);
    function apply() {
      document.documentElement.lang = current;
      select.value = current;
      for (const [node, de] of labels) node.textContent = t(de, node.dataset.en);
      for (const [node, de] of aria) node.setAttribute('aria-label', t(de, node.dataset.enLabel));
      onChange();
    }
    select.addEventListener('change', () => {
      current = select.value;
      try { localStorage.setItem(storageKey, current); } catch { /* Session-only preference. */ }
      apply();
    });
    apply();
  }

  return { t, message, bind, get current() { return current; } };
})();
