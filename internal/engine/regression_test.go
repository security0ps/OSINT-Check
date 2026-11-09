package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"osint-check/internal/sources"
)

func TestRegressionCancelledRequestsDoNotConsumeQuota(t *testing.T) {
	l := NewLimiter(sources.Limit{PerMinute: 4, PerDay: 500})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		_ = l.Wait(ctx)
	}
	if got := l.UsedToday(); got != 0 {
		t.Fatalf("100 cancelled waits, no network requests, UsedToday=%d", got)
	}
}

func TestCancelledWaitDoesNotDelayLaterRequest(t *testing.T) {
	l := NewLimiter(sources.Limit{PerMinute: 4, PerDay: 10})
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := l.next
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if l.UsedToday() != 1 || !l.next.Equal(next) {
		t.Fatal("cancelled wait reserved capacity")
	}
	// Advance the clock to the first available slot without waiting 15 seconds.
	l.now = func() time.Time { return next }
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.UsedToday() != 2 {
		t.Fatal(l.UsedToday())
	}
}

func TestConcurrentWaitsRespectDailyLimit(t *testing.T) {
	l := NewLimiter(sources.Limit{PerDay: 5})
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- l.Wait(context.Background()) }()
	}
	wg.Wait()
	close(errs)
	allowed := 0
	for err := range errs {
		if err == nil {
			allowed++
		} else if !errors.Is(err, ErrDailyLimit) {
			t.Fatal(err)
		}
	}
	if allowed != 5 || l.UsedToday() != 5 {
		t.Fatalf("allowed=%d used=%d", allowed, l.UsedToday())
	}
}

func TestRegressionSameGroupDoesNotRaiseConfidence(t *testing.T) {
	a := Assess(Item{Results: []Result{
		{Group: "abuse.ch", Status: sources.StatusOK, Finding: sources.Finding{Verdict: sources.Malicious}},
		{Group: "abuse.ch", Status: sources.StatusOK, Finding: sources.Finding{Verdict: sources.Suspicious}},
	}}, true)
	if a.Confidence != "niedrig" {
		t.Fatalf("one independent group: got confidence %q", a.Confidence)
	}
}
