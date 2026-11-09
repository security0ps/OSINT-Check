package engine

import (
	"fmt"
	"strings"

	"osint-check/internal/sources"
)

// Level ist die Gesamteinstufung eines Indikators.
type Level string

const (
	LevelMalicious  Level = "malicious"
	LevelSuspicious Level = "suspicious"
	LevelNoFinding  Level = "no_finding"
	LevelUnchecked  Level = "unchecked"
	LevelInternal   Level = "internal"
	LevelPending    Level = "pending"
)

// Assessment fasst die Quellen zusammen. Es ist eine nachvollziehbare
// Regelbewertung, keine Aussage darüber, dass etwas sicher ist.
type Assessment struct {
	Level      Level    `json:"level"`
	Confidence string   `json:"confidence,omitempty"` // hoch, mittel, niedrig
	Action     string   `json:"action"`
	Reasons    []string `json:"reasons"`
	Answered   int      `json:"answered"` // Quellen mit Antwort
	Total      int      `json:"total"`    // abfragbare Quellen
	Hits       int      `json:"hits"`
}

// Assess bewertet einen Indikator. Quellen derselben Gruppe (etwa die Dienste
// von abuse.ch) teilen sich Daten und zählen daher als eine Stimme.
func Assess(it Item, final bool) Assessment {
	a := Assessment{Reasons: []string{}}
	if it.Indicator.Internal {
		a.Level = LevelInternal
		a.Action = "Interner Wert, wurde nicht an externe Dienste gesendet"
		return a
	}
	mal, susp, weak, clean := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	running := false
	var warnings []string
	for _, r := range it.Results {
		a.Total++
		switch r.Status {
		case sources.StatusPending, sources.StatusWaiting:
			running = true
			continue
		case sources.StatusOK:
			a.Answered++
		default:
			continue
		}
		switch r.Verdict {
		case sources.Malicious:
			mal[r.Group] = true
			a.Hits++
			a.Reasons = append(a.Reasons, r.Name+": "+r.Summary)
		case sources.Suspicious:
			susp[r.Group] = true
			a.Hits++
			a.Reasons = append(a.Reasons, r.Name+": "+r.Summary)
		case sources.Weak:
			weak[r.Group] = true
			a.Hits++
			a.Reasons = append(a.Reasons, r.Name+": "+r.Summary)
		case sources.Clean:
			clean[r.Group] = true
		}
		warnings = append(warnings, r.Warnings...)
	}

	// Pro unabhängiger Gruppe zählt nur die stärkste belastende Einstufung.
	// Unauffällige Gegenbefunde bleiben für den Widerspruchshinweis erhalten.
	for group := range mal {
		delete(susp, group)
		delete(weak, group)
	}
	for group := range susp {
		delete(weak, group)
	}

	switch {
	case len(mal) >= 2:
		a.Level, a.Confidence = LevelMalicious, "hoch"
		a.Action = "Blockieren prüfen und Vorfall nachgehen"
	case len(mal) == 1 && len(susp)+len(weak) > 0:
		a.Level, a.Confidence = LevelMalicious, "mittel"
		a.Action = "Blockieren prüfen und zweite Quelle kontrollieren"
	case len(mal) == 1:
		a.Level, a.Confidence = LevelMalicious, "niedrig"
		a.Action = "Nur eine Quelle meldet das, vor dem Blockieren manuell prüfen"
	case len(susp) >= 2:
		a.Level, a.Confidence = LevelSuspicious, "mittel"
		a.Action = "Beobachten und manuell prüfen"
	case len(susp) == 1 || len(weak) >= 2:
		a.Level, a.Confidence = LevelSuspicious, "niedrig"
		a.Action = "Beobachten und manuell prüfen"
	case running:
		a.Level = LevelPending
		a.Action = "Prüfung läuft"
	case a.Answered == 0:
		a.Level = LevelUnchecked
		a.Action = "Keine Quelle hat geantwortet, Ergebnis ist nicht aussagekräftig"
	default:
		a.Level = LevelNoFinding
		a.Action = "Keine Treffer. Das beweist nicht, dass der Wert sicher ist"
		if len(weak) == 1 {
			a.Action = "Nur ein schwacher Hinweis, im Zweifel manuell prüfen"
		}
	}
	if (a.Level == LevelMalicious || a.Level == LevelSuspicious) && len(clean) > 0 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("Widerspruch: %d Quelle(n) stufen den Wert als unauffällig ein", len(clean)))
		if a.Confidence == "hoch" {
			a.Confidence = "mittel"
		}
	}
	if a.Level != LevelPending && a.Answered < a.Total && final {
		a.Reasons = append(a.Reasons, fmt.Sprintf("Unvollständig: %d von %d Quellen haben geantwortet", a.Answered, a.Total))
	}
	seen := map[string]bool{}
	for _, w := range warnings {
		if !seen[w] {
			seen[w] = true
			a.Reasons = append(a.Reasons, "Achtung: "+strings.TrimSpace(w))
		}
	}
	return a
}
