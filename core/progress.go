package core

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Progress drives the RottenCore loading screen (rolling black apple, 0/100 bar, live line) for installs,
// updates and uploads alike. The rule: the counter only moves when real work moves. A job is a list of
// weighted steps; a step either has a byte total (download, upload, copy, hash) and advances with the
// bytes actually transferred, or has none and jumps only when it completes. Nothing is interpolated or
// timed, the counter never goes backwards, and it reaches 100 only when the last step is done.

// ProgressEvent is one update for the UI (also the NDJSON line of `rottencore ... --progress json`).
type ProgressEvent struct {
	Op      string `json:"op"`              // install | update | upload | download
	Step    int    `json:"step"`            // 0-based index of the current step
	Steps   int    `json:"steps"`           // number of steps
	Action  string `json:"action"`          // downloading | verifying | snapshotting | copying | uploading | ...
	Item    string `json:"item"`            // the file or thing being changed, added or downloaded
	Line    string `json:"line"`            // the live line under the bar
	Done    int64  `json:"done"`            // bytes (or units) done in this step
	Total   int64  `json:"total"`           // -1 when unknown
	Percent int    `json:"percent"`         // 0..100, integer, monotonic
	State   string `json:"state"`           // running | done | failed
	Error   string `json:"error,omitempty"` // when failed
	AtMs    int64  `json:"atMs"`
}

// ProgressStep is one weighted step.
type ProgressStep struct {
	Action string
	Item   string
	Weight int // relative; downloads usually dominate
}

// Progress tracks one job. Safe for concurrent use.
type Progress struct {
	mu      sync.Mutex
	op      string
	steps   []ProgressStep
	sumW    int
	cur     int
	doneW   int
	done    int64
	total   int64
	percent int
	state   string
	emit    func(ProgressEvent)
	now     func() time.Time
	lastPct int
	lastAt  time.Time
	gotByte bool // first byte report of a step is always shown
}

// NewProgress starts a job. emit receives every visible change (throttled to a changed percent, a changed
// line, or 10 per second for byte steps).
func NewProgress(op string, steps []ProgressStep, emit func(ProgressEvent)) *Progress {
	p := &Progress{op: op, steps: steps, emit: emit, now: time.Now, state: "running", total: -1, lastPct: -1}
	for _, s := range steps {
		p.sumW += max(s.Weight, 1)
	}
	if p.sumW == 0 {
		p.sumW = 1
	}
	p.send(true)
	return p
}

func (p *Progress) weight(i int) int { return max(p.steps[i].Weight, 1) }

// Bytes reports real progress inside the current step. total < 0 means unknown: the bar then holds still
// until the step finishes (never fake progress); the live line still shows the bytes moved.
func (p *Progress) Bytes(done, total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != "running" || p.cur >= len(p.steps) {
		return
	}
	p.done, p.total = done, total
	p.recompute()
	p.send(!p.gotByte)
	p.gotByte = true
}

// StepDone finishes the current step and moves to the next one.
func (p *Progress) StepDone() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != "running" || p.cur >= len(p.steps) {
		return
	}
	p.doneW += p.weight(p.cur)
	p.cur++
	p.done, p.total, p.gotByte = 0, -1, false
	if p.cur == len(p.steps) {
		p.state = "done"
	}
	p.recompute()
	p.send(true)
}

// Fail stops the job; the bar keeps the real percent reached.
func (p *Progress) Fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != "running" {
		return
	}
	p.state = "failed"
	ev := p.event()
	ev.Error = err.Error()
	ev.Line = "Stopped: " + err.Error()
	if p.emit != nil {
		p.emit(ev)
	}
}

// Percent is the current counter.
func (p *Progress) Percent() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.percent
}

// Writer wraps w so every byte written advances the current step (uploads, copies).
func (p *Progress) Writer(w io.Writer, total int64) io.Writer {
	return &progressWriter{w: w, total: total, fn: p.Bytes}
}

func (p *Progress) recompute() {
	var frac float64
	if p.cur < len(p.steps) && p.total > 0 {
		frac = float64(min(p.done, p.total)) / float64(p.total)
	}
	cw := 0
	if p.cur < len(p.steps) {
		cw = p.weight(p.cur)
	}
	pct := int((float64(p.doneW) + frac*float64(cw)) * 100 / float64(p.sumW))
	if p.state != "done" && pct >= 100 {
		pct = 99 // 100 only when every step is finished
	}
	if p.state == "done" {
		pct = 100
	}
	if pct > p.percent {
		p.percent = pct
	}
}

func (p *Progress) event() ProgressEvent {
	ev := ProgressEvent{Op: p.op, Step: p.cur, Steps: len(p.steps), Done: p.done, Total: p.total, Percent: p.percent, State: p.state, AtMs: p.now().UnixMilli()}
	if p.cur < len(p.steps) {
		s := p.steps[p.cur]
		ev.Action, ev.Item = s.Action, s.Item
	}
	ev.Line = liveLine(ev)
	return ev
}

func (p *Progress) send(force bool) {
	if p.emit == nil {
		return
	}
	now := p.now()
	if !force && p.percent == p.lastPct && now.Sub(p.lastAt) < 100*time.Millisecond {
		return
	}
	p.lastPct, p.lastAt = p.percent, now
	p.emit(p.event())
}

func liveLine(ev ProgressEvent) string {
	if ev.State == "done" {
		return "Done"
	}
	verb := map[string]string{"downloading": "Downloading", "verifying": "Checking signature of", "hashing": "Checking", "snapshotting": "Taking a snapshot of",
		"copying": "Adding", "replacing": "Changing", "removing": "Removing", "uploading": "Uploading", "installing": "Installing", "rolling-back": "Rolling back"}[ev.Action]
	if verb == "" {
		verb = ev.Action
	}
	l := verb + " " + ev.Item
	switch {
	case ev.Total > 0:
		l += fmt.Sprintf(" — %s of %s", humanBytes(ev.Done), humanBytes(ev.Total))
	case ev.Done > 0:
		l += " — " + humanBytes(ev.Done)
	}
	return l
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// NDJSONProgress writes each event as one JSON line (the RottenCore app reads this from the CLI).
func NDJSONProgress(w io.Writer) func(ProgressEvent) {
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	return func(ev ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(ev)
	}
}
