package engine

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"osint-check/internal/ioc"
)

// Eine große, teure Eingabe darf Abfragen anderer Aufträge nicht blockieren.
func TestLargeInputDoesNotBlockJobPoll(t *testing.T) {
	var tok strings.Builder
	for r := rune(0x4E00); r < 0x4E00+1365; r++ {
		tok.WriteRune(r)
	}
	body := strings.Repeat(tok.String()+" ", 256) // ~1 MiB
	e := New(nil, nil, ioc.Options{})
	seed, err := e.Submit("x", false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { e.Submit(body, false); close(done) }()
	time.Sleep(2 * time.Millisecond)
	start := time.Now()
	if e.Job(seed.ID) == nil {
		t.Fatal("Auftrag fehlt")
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("Job-Abfrage %v blockiert", d)
	}
	<-done
}

// Gespeicherte Aufträge dürfen nicht die ganze Eingabe im Speicher halten.
func TestStoredJobsDoNotRetainInput(t *testing.T) {
	e := New(nil, nil, ioc.Options{})
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	const n = 16
	inputs := []string{
		"x%d",
		"8.8.8.%d",
		"0000000000000000000000000000000000000000000000000000000000000%03d",
	}
	for i := 0; i < n; i++ {
		v := fmt.Sprintf(inputs[i%len(inputs)], i)
		in := string([]byte(v + strings.Repeat(" ", 1<<20-128)))
		if _, err := e.Submit(in, false); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(e)
	if delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc); delta > 2<<20 {
		t.Fatalf("%d Aufträge halten %.1f MiB fest", n, float64(delta)/(1<<20))
	}
}
