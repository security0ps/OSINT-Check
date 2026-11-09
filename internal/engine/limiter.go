package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"osint-check/internal/sources"
)

// ErrDailyLimit bedeutet, dass das Tageskontingent verbraucht ist.
var ErrDailyLimit = errors.New("Tageslimit erreicht")

// Limiter hält das Minuten- und Tageslimit einer Quelle ein. Die Slots werden
// gleichmäßig verteilt, damit auch kurze Spitzen nicht gegen Limits laufen.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	perDay   int
	next     time.Time
	day      string
	used     int
	now      func() time.Time
}

// NewLimiter erstellt einen Limiter. Der Tageszähler läuft in UTC.
func NewLimiter(l sources.Limit) *Limiter {
	lim := &Limiter{perDay: l.PerDay, now: time.Now}
	if l.PerMinute > 0 {
		lim.interval = time.Minute / time.Duration(l.PerMinute)
	}
	return lim
}

// acquire vergibt nur sofort nutzbare Slots. Wartende Aufträge reservieren
// weder Tageskontingent noch zukünftige Zeitfenster.
func (l *Limiter) acquire(ctx context.Context) (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := l.now()
	if d := now.UTC().Format("2006-01-02"); d != l.day {
		l.day, l.used = d, 0
	}
	if l.perDay > 0 && l.used >= l.perDay {
		return 0, ErrDailyLimit
	}
	if wait := l.next.Sub(now); wait > 0 {
		return wait, nil
	}
	l.used++
	l.next = now.Add(l.interval)
	return 0, nil
}

// Wait wartet abbrechbar auf einen Slot. Nach jedem Warten werden Zeit,
// Tageslimit und Kontext unter derselben Sperre erneut geprüft.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		wait, err := l.acquire(ctx)
		if err != nil || wait <= 0 {
			return err
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}

// UsedToday liefert die heute zum Start freigegebenen Anfragen.
func (l *Limiter) UsedToday() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.now().UTC().Format("2006-01-02") != l.day {
		return 0
	}
	return l.used
}
