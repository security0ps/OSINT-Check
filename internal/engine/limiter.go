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

func (l *Limiter) reserve() (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if d := now.UTC().Format("2006-01-02"); d != l.day {
		l.day, l.used = d, 0
	}
	if l.perDay > 0 && l.used >= l.perDay {
		return 0, ErrDailyLimit
	}
	l.used++
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	return wait, nil
}

// Wait reserviert einen Slot und wartet bis zu dessen Zeitpunkt.
func (l *Limiter) Wait(ctx context.Context) error {
	wait, err := l.reserve()
	if err != nil {
		return err
	}
	if wait <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UsedToday liefert die heute gestarteten Anfragen.
func (l *Limiter) UsedToday() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.now().UTC().Format("2006-01-02") != l.day {
		return 0
	}
	return l.used
}
