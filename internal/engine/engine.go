// Package engine koordiniert Abfragen, Limits, Zwischenspeicher und Bewertung.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"osint-check/internal/ioc"
	"osint-check/internal/sources"
)

const (
	MaxIndicators = 100
	maxActiveJobs = 20
	maxStoredJobs = 500
	cacheTTL      = time.Hour
	cacheMax      = 5000
	jobMaxAge     = 2 * time.Hour
	// Ohne Abruf durch die Oberfläche wird ein Auftrag abgebrochen, damit ein
	// geschlossener Tab keine Tageslimits verbraucht.
	abandonAfter = 3 * time.Minute
)

// ErrBusy meldet zu viele laufende Aufträge.
var ErrBusy = errors.New("Zu viele laufende Prüfungen, bitte gleich noch einmal versuchen")

// Result ist der Stand einer Quelle für einen Indikator.
type Result struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Group  string `json:"-"`
	sources.Finding
	Status    sources.Status `json:"status"`
	Error     string         `json:"error,omitempty"`
	Cached    bool           `json:"cached,omitempty"`
	CheckedAt *time.Time     `json:"checked_at,omitempty"`
}

// Item ist ein Indikator samt Ergebnissen.
type Item struct {
	Indicator  ioc.Indicator `json:"indicator"`
	Results    []Result      `json:"results"`
	Assessment Assessment    `json:"assessment"`
}

// Job ist ein Prüfauftrag.
type Job struct {
	mu        sync.Mutex
	ID        string
	Created   time.Time
	Finished  bool
	Cancelled bool
	Items     []*Item
	Unknown   []string
	Truncated int
	cancel    context.CancelFunc
	lastSeen  time.Time
}

// JobView ist die JSON-Sicht auf einen Auftrag.
type JobView struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Finished  bool      `json:"finished"`
	Cancelled bool      `json:"cancelled"`
	Done      int       `json:"done"`
	Total     int       `json:"total"`
	Items     []Item    `json:"items"`
	Unknown   []string  `json:"unknown"`
	Truncated int       `json:"truncated"`
}

// SourceConfig verbindet eine Quelle mit Key und Limit.
type SourceConfig struct {
	Source  *sources.Source
	Key     string
	Limiter *Limiter
}

// Engine führt Aufträge aus.
type Engine struct {
	mu      sync.Mutex
	client  *sources.Client
	sources []*SourceConfig
	cache   map[string]cacheEntry
	jobs    map[string]*Job
	parse   ioc.Options
	// admitting zählt Aufträge, die einen Platz reserviert haben und gerade
	// außerhalb der Sperre zerlegt werden.
	admitting int
}

type cacheEntry struct {
	finding sources.Finding
	at      time.Time
}

// New erstellt die Engine.
func New(client *sources.Client, cfgs []*SourceConfig, parse ioc.Options) *Engine {
	parse.MaxItems = MaxIndicators
	return &Engine{client: client, sources: cfgs, cache: map[string]cacheEntry{}, jobs: map[string]*Job{}, parse: parse}
}

// Sources liefert eine Kopie der aktiven Quellen.
func (e *Engine) Sources() []SourceConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]SourceConfig, len(e.sources))
	for i, s := range e.sources {
		out[i] = *s
	}
	return out
}

// SetKey ändert einen API-Key zur Laufzeit.
func (e *Engine) SetKey(keyName, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.sources {
		if s.Source.KeyName == keyName {
			s.Key = value
		}
	}
}

// SetInternalDomains ändert die Liste eigener Domains.
func (e *Engine) SetInternalDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.parse.InternalDomains = domains
}

// InternalDomains liefert die Liste eigener Domains.
func (e *Engine) InternalDomains() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.parse.InternalDomains...)
}

// Submit startet einen Auftrag. Ist nichts zu prüfen, ist der Auftrag sofort fertig.
func (e *Engine) Submit(input string, fresh bool) (*Job, error) {
	e.mu.Lock()
	active := 0
	for id, j := range e.jobs {
		j.mu.Lock()
		if j.Finished && time.Since(j.Created) > jobMaxAge {
			delete(e.jobs, id)
		} else if !j.Finished {
			active++
		}
		j.mu.Unlock()
	}
	if active+e.admitting >= maxActiveJobs {
		e.mu.Unlock()
		return nil, ErrBusy
	}
	e.admitting++
	opts := e.parse
	opts.InternalDomains = append([]string(nil), e.parse.InternalDomains...)
	e.mu.Unlock()
	// Zerlegen ohne die Engine-Sperre: Eingaben eines Mitglieds dürfen Abfragen
	// anderer Mitglieder nicht blockieren.
	parsed := ioc.Parse(input, opts)
	cfgs := e.Sources()

	ctx, cancel := context.WithTimeout(context.Background(), jobMaxAge)
	job := &Job{ID: newID(), Created: time.Now(), Unknown: parsed.Unknown, Truncated: parsed.Truncated, cancel: cancel, lastSeen: time.Now()}
	type task struct {
		item, result int
		cfg          SourceConfig
	}
	var tasks []task
	for _, in := range parsed.Indicators {
		item := &Item{Indicator: in, Results: []Result{}}
		if !in.Internal {
			for _, cfg := range cfgs {
				if !cfg.Source.Supports(in.Type) {
					continue
				}
				r := Result{Source: cfg.Source.ID, Name: cfg.Source.Name, Group: cfg.Source.Group, Status: sources.StatusPending}
				if cfg.Source.KeyName != "" && cfg.Key == "" {
					r.Status = sources.StatusNoKey
				} else {
					tasks = append(tasks, task{len(job.Items), len(item.Results), cfg})
				}
				item.Results = append(item.Results, r)
			}
		}
		item.Assessment = Assess(*item, false)
		job.Items = append(job.Items, item)
	}

	e.mu.Lock()
	e.admitting--
	e.evictFinished()
	e.jobs[job.ID] = job
	e.mu.Unlock()

	var wg sync.WaitGroup
	// Jede Quelle arbeitet ihre Warteschlange unabhängig ab, ein langsames
	// Limit bremst daher keine andere Quelle.
	bySource := map[string][]task{}
	for _, t := range tasks {
		bySource[t.cfg.Source.ID] = append(bySource[t.cfg.Source.ID], t)
	}
	for _, list := range bySource {
		wg.Add(1)
		go func(list []task) {
			defer wg.Done()
			sem := make(chan struct{}, 4)
			var inner sync.WaitGroup
			for _, t := range list {
				sem <- struct{}{}
				inner.Add(1)
				go func(t task) {
					defer func() { <-sem; inner.Done() }()
					e.runCheck(ctx, job, t.item, t.result, t.cfg, fresh)
				}(t)
			}
			inner.Wait()
		}(list)
	}
	go func() {
		wg.Wait()
		cancel()
		job.mu.Lock()
		job.Finished = true
		for _, it := range job.Items {
			it.Assessment = Assess(*it, true)
		}
		job.mu.Unlock()
	}()
	go e.watch(ctx, job)
	return job, nil
}

// evictFinished begrenzt den Speicher, auch wenn viele Prüfungen sofort enden.
func (e *Engine) evictFinished() {
	for len(e.jobs) >= maxStoredJobs {
		var oldest *Job
		for _, j := range e.jobs {
			j.mu.Lock()
			if j.Finished && (oldest == nil || j.Created.Before(oldest.Created)) {
				oldest = j
			}
			j.mu.Unlock()
		}
		if oldest == nil {
			return
		}
		delete(e.jobs, oldest.ID)
	}
}

func (e *Engine) watch(ctx context.Context, job *Job) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			job.mu.Lock()
			idle := time.Since(job.lastSeen) > abandonAfter
			job.mu.Unlock()
			if idle {
				job.Cancel()
				return
			}
		}
	}
}

func (e *Engine) runCheck(ctx context.Context, job *Job, item, idx int, cfg SourceConfig, fresh bool) {
	in := job.Items[item].Indicator
	key := cfg.Source.ID + "|" + string(in.Type) + "|" + in.Value
	if !fresh {
		if c, ok := e.fromCache(key); ok {
			job.finish(item, idx, Result{Finding: c.finding, Status: sources.StatusOK, Cached: true, CheckedAt: &c.at})
			return
		}
	}
	job.set(item, idx, func(r *Result) { r.Status = sources.StatusWaiting })
	if err := cfg.Limiter.Wait(ctx); err != nil {
		if errors.Is(err, ErrDailyLimit) {
			job.finish(item, idx, Result{Status: sources.StatusLimit, Error: "Tageslimit erreicht"})
		} else {
			job.finish(item, idx, Result{Status: sources.StatusSkipped, Error: "Abgebrochen"})
		}
		return
	}
	job.set(item, idx, func(r *Result) { r.Status = sources.StatusPending })
	finding, err := cfg.Source.Check(ctx, e.client, cfg.Key, in)
	now := time.Now().UTC()
	switch {
	case err == nil:
		e.toCache(key, finding, now)
		job.finish(item, idx, Result{Finding: finding, Status: sources.StatusOK, CheckedAt: &now})
	case errors.Is(err, sources.ErrRateLimited):
		job.finish(item, idx, Result{Status: sources.StatusLimit, Error: err.Error()})
	case ctx.Err() != nil:
		job.finish(item, idx, Result{Status: sources.StatusSkipped, Error: "Abgebrochen"})
	default:
		job.finish(item, idx, Result{Status: sources.StatusError, Error: err.Error()})
	}
}

func (j *Job) set(item, idx int, f func(*Result)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f(&j.Items[item].Results[idx])
}

func (j *Job) finish(item, idx int, r Result) {
	j.mu.Lock()
	defer j.mu.Unlock()
	it := j.Items[item]
	cur := it.Results[idx]
	r.Source, r.Name, r.Group = cur.Source, cur.Name, cur.Group
	it.Results[idx] = r
	it.Assessment = Assess(*it, false)
}

// Cancel bricht den Auftrag ab.
func (j *Job) Cancel() {
	j.mu.Lock()
	j.Cancelled = true
	j.mu.Unlock()
	j.cancel()
}

// View erstellt eine Momentaufnahme und merkt sich den Abruf.
func (j *Job) View() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lastSeen = time.Now()
	v := JobView{ID: j.ID, Created: j.Created, Finished: j.Finished, Cancelled: j.Cancelled, Unknown: j.Unknown, Truncated: j.Truncated, Items: make([]Item, 0, len(j.Items))}
	for _, it := range j.Items {
		copyItem := Item{Indicator: it.Indicator, Assessment: it.Assessment, Results: append([]Result{}, it.Results...)}
		for _, r := range it.Results {
			v.Total++
			if r.Status != sources.StatusPending && r.Status != sources.StatusWaiting {
				v.Done++
			}
		}
		v.Items = append(v.Items, copyItem)
	}
	return v
}

// Job sucht einen Auftrag.
func (e *Engine) Job(id string) *Job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jobs[id]
}

func (e *Engine) fromCache(key string) (cacheEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.cache[key]
	if !ok || time.Since(c.at) > cacheTTL {
		return cacheEntry{}, false
	}
	return c, true
}

func (e *Engine) toCache(key string, f sources.Finding, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.cache) >= cacheMax {
		e.cache = map[string]cacheEntry{}
	}
	e.cache[key] = cacheEntry{finding: f, at: at}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
