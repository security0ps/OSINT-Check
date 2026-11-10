package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"osint-check/internal/ioc"
	"osint-check/internal/sources"
)

func res(group string, v sources.Verdict) Result {
	return Result{Source: group, Name: group, Group: group, Status: sources.StatusOK, Finding: sources.Finding{Verdict: v, Summary: "x"}}
}

func level(results ...Result) Assessment {
	return Assess(Item{Results: results}, true)
}

func TestAssessLevels(t *testing.T) {
	cases := []struct {
		name string
		rs   []Result
		lvl  Level
		conf string
	}{
		{"zwei unabhängige", []Result{res("a", sources.Malicious), res("b", sources.Malicious)}, LevelMalicious, "hoch"},
		{"eine Quelle", []Result{res("a", sources.Malicious), res("b", sources.NotFound)}, LevelMalicious, "niedrig"},
		{"gleiche Gruppe zählt einmal", []Result{res("abuse.ch", sources.Malicious), res("abuse.ch", sources.Malicious)}, LevelMalicious, "niedrig"},
		{"mal + verdächtig", []Result{res("a", sources.Malicious), res("b", sources.Suspicious)}, LevelMalicious, "mittel"},
		{"Widerspruch senkt", []Result{res("a", sources.Malicious), res("b", sources.Malicious), res("c", sources.Clean)}, LevelMalicious, "mittel"},
		{"zweimal verdächtig", []Result{res("a", sources.Suspicious), res("b", sources.Suspicious)}, LevelSuspicious, "mittel"},
		{"zweimal schwach", []Result{res("a", sources.Weak), res("b", sources.Weak)}, LevelSuspicious, "niedrig"},
		{"einmal schwach", []Result{res("a", sources.Weak), res("b", sources.Clean)}, LevelNoFinding, ""},
		{"nichts", []Result{res("a", sources.NotFound), res("b", sources.Clean)}, LevelNoFinding, ""},
	}
	for _, c := range cases {
		a := level(c.rs...)
		if a.Level != c.lvl || a.Confidence != c.conf {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, a.Level, a.Confidence, c.lvl, c.conf)
		}
	}
}

func TestAssessNoAnswerIsNotNoFinding(t *testing.T) {
	a := level(Result{Status: sources.StatusError}, Result{Status: sources.StatusNoKey})
	if a.Level != LevelUnchecked {
		t.Fatalf("%s", a.Level)
	}
}

func TestAssessMaliciousVisibleWhileRunning(t *testing.T) {
	a := Assess(Item{Results: []Result{res("a", sources.Malicious), {Status: sources.StatusWaiting}}}, false)
	if a.Level != LevelMalicious {
		t.Fatalf("%s", a.Level)
	}
	b := Assess(Item{Results: []Result{res("a", sources.NotFound), {Status: sources.StatusWaiting}}}, false)
	if b.Level != LevelPending {
		t.Fatalf("%s", b.Level)
	}
}

func TestAssessInternal(t *testing.T) {
	a := Assess(Item{Indicator: ioc.Indicator{Internal: true}}, true)
	if a.Level != LevelInternal {
		t.Fatal(a.Level)
	}
}

func TestLimiterSpacing(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := NewLimiter(sources.Limit{PerMinute: 4})
	l.now = func() time.Time { return now }
	w1, _ := l.acquire(context.Background())
	w2, _ := l.acquire(context.Background())
	w3, _ := l.acquire(context.Background())
	if w1 != 0 || w2 != 15*time.Second || w3 != 15*time.Second {
		t.Fatal(w1, w2, w3)
	}
	if l.UsedToday() != 1 {
		t.Fatal("waiting calls consumed quota")
	}
	now = now.Add(15 * time.Second)
	if wait, err := l.acquire(context.Background()); wait != 0 || err != nil {
		t.Fatal(wait, err)
	}
	if l.UsedToday() != 2 {
		t.Fatal(l.UsedToday())
	}
}

func TestLimiterDaily(t *testing.T) {
	now := time.Date(2026, 1, 1, 23, 59, 0, 0, time.UTC)
	l := NewLimiter(sources.Limit{PerDay: 2})
	l.now = func() time.Time { return now }
	l.acquire(context.Background())
	l.acquire(context.Background())
	if _, err := l.acquire(context.Background()); !errors.Is(err, ErrDailyLimit) {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // nächster UTC-Tag
	if _, err := l.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.UsedToday() != 1 {
		t.Fatal(l.UsedToday())
	}
}

func testEngine(calls *atomic.Int32, check func() (sources.Finding, error), limit sources.Limit) *Engine {
	src := &sources.Source{ID: "s", Name: "S", Group: "s", KeyName: "s", Types: []ioc.Type{ioc.IPv4, ioc.Domain},
		Check: func(ctx context.Context, _ *sources.Client, key string, in ioc.Indicator) (sources.Finding, error) {
			calls.Add(1)
			return check()
		}}
	return New(sources.NewClient(nil), []*SourceConfig{{Source: src, Key: "k", Limiter: NewLimiter(limit)}}, ioc.Options{})
}

func wait(t *testing.T, j *Job) JobView {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v := j.View()
		if v.Finished {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Timeout")
	return JobView{}
}

func TestInternalNeverQueried(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{Verdict: sources.Clean}, nil }, sources.Limit{})
	j, _ := e.Submit("192.168.0.1 10.1.1.1 fileserver.local", false)
	v := wait(t, j)
	if calls.Load() != 0 {
		t.Fatalf("interne Werte wurden %d-mal abgefragt", calls.Load())
	}
	if len(v.Items) != 3 || v.Items[0].Assessment.Level != LevelInternal {
		t.Fatalf("%+v", v)
	}
}

func TestCacheAndFresh(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{Verdict: sources.Clean}, nil }, sources.Limit{})
	wait(t, must(e.Submit("8.8.8.8", false)))
	v := wait(t, must(e.Submit("8.8.8.8", false)))
	if calls.Load() != 1 || !v.Items[0].Results[0].Cached {
		t.Fatalf("calls=%d %+v", calls.Load(), v.Items[0].Results[0])
	}
	wait(t, must(e.Submit("8.8.8.8", true)))
	if calls.Load() != 2 {
		t.Fatalf("fresh ignoriert: %d", calls.Load())
	}
}

func must(j *Job, err error) *Job {
	if err != nil {
		panic(err)
	}
	return j
}

func TestErrorsNotCached(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{}, errors.New("kaputt") }, sources.Limit{})
	v := wait(t, must(e.Submit("8.8.8.8", false)))
	wait(t, must(e.Submit("8.8.8.8", false)))
	if calls.Load() != 2 || v.Items[0].Results[0].Status != sources.StatusError {
		t.Fatal(calls.Load(), v.Items[0].Results[0])
	}
}

func TestDailyLimitReported(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{Verdict: sources.Clean}, nil }, sources.Limit{PerDay: 1})
	v := wait(t, must(e.Submit("8.8.8.8 1.1.1.1", false)))
	statuses := map[sources.Status]int{}
	for _, it := range v.Items {
		statuses[it.Results[0].Status]++
	}
	if statuses[sources.StatusOK] != 1 || statuses[sources.StatusLimit] != 1 {
		t.Fatalf("%+v", statuses)
	}
}

func TestMissingKeyMarked(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{}, nil }, sources.Limit{})
	e.SetKey("s", "")
	v := wait(t, must(e.Submit("8.8.8.8", false)))
	if calls.Load() != 0 || v.Items[0].Results[0].Status != sources.StatusNoKey || v.Items[0].Assessment.Level != LevelUnchecked {
		t.Fatalf("%+v", v.Items[0])
	}
}

func TestCancelStopsWaiting(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{Verdict: sources.Clean}, nil }, sources.Limit{PerMinute: 1})
	j := must(e.Submit("8.8.8.8 1.1.1.1 9.9.9.9", false))
	time.Sleep(30 * time.Millisecond)
	j.Cancel()
	v := wait(t, j)
	if calls.Load() != 1 || !v.Cancelled {
		t.Fatalf("calls=%d %+v", calls.Load(), v.Cancelled)
	}
}

func TestFinishedJobsAreBounded(t *testing.T) {
	var calls atomic.Int32
	e := testEngine(&calls, func() (sources.Finding, error) { return sources.Finding{}, nil }, sources.Limit{})
	for i := 0; i < maxStoredJobs+50; i++ {
		wait(t, must(e.Submit("10.0.0.1", false)))
	}
	if n := len(e.jobs); n > maxStoredJobs {
		t.Fatalf("%d Aufträge im Speicher", n)
	}
}
