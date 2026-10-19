package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressOnlyMovesWithRealWork(t *testing.T) {
	var evs []ProgressEvent
	p := NewProgress("install", []ProgressStep{{"downloading", "redx.dmg", 8}, {"verifying", "redx.dmg", 1}, {"copying", "RedX.app", 1}}, func(e ProgressEvent) { evs = append(evs, e) })
	if p.Percent() != 0 {
		t.Fatal("starts above 0")
	}
	time.Sleep(20 * time.Millisecond) // time alone must not move the bar
	if p.Percent() != 0 {
		t.Fatal("moved without work")
	}
	p.Bytes(500, 1000)
	if p.Percent() != 40 {
		t.Fatalf("half the download of an 80%% step = %d", p.Percent())
	}
	p.Bytes(100, 1000) // a restart reports fewer bytes: the counter never goes back
	if p.Percent() != 40 {
		t.Fatalf("went backwards: %d", p.Percent())
	}
	p.Bytes(1000, 1000)
	if p.Percent() != 80 {
		t.Fatalf("download done = %d", p.Percent())
	}
	p.StepDone()
	p.Bytes(5<<20, -1) // unknown total: bar holds, line still shows bytes
	if p.Percent() != 80 {
		t.Fatalf("unknown total moved the bar: %d", p.Percent())
	}
	if l := evs[len(evs)-1].Line; !strings.Contains(l, "Checking signature of redx.dmg") || !strings.Contains(l, "5.0 MB") {
		t.Fatalf("line = %q", l)
	}
	p.StepDone()
	if p.Percent() != 90 {
		t.Fatalf("after verify = %d", p.Percent())
	}
	p.Bytes(1<<40, 1) // over-report is capped below 100
	if p.Percent() != 99 {
		t.Fatalf("100 before the last step finished: %d", p.Percent())
	}
	p.StepDone()
	if last := evs[len(evs)-1]; last.Percent != 100 || last.State != "done" {
		t.Fatalf("last = %+v", last)
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Percent < evs[i-1].Percent || evs[i].Percent > 100 {
			t.Fatalf("non-monotonic %d -> %d", evs[i-1].Percent, evs[i].Percent)
		}
	}
}

func TestProgressFailKeepsRealPercent(t *testing.T) {
	var last ProgressEvent
	p := NewProgress("upload", []ProgressStep{{"uploading", "app.rarxai", 1}}, func(e ProgressEvent) { last = e })
	p.Bytes(30, 100)
	p.Fail(errors.New("store refused the upload"))
	if last.State != "failed" || last.Percent != 30 || !strings.Contains(last.Line, "store refused") {
		t.Fatalf("%+v", last)
	}
}

// A real HTTP download drives the bar: every event's percent is backed by bytes received.
func TestProgressRealDownload(t *testing.T) {
	payload := bytes.Repeat([]byte("rotten"), 200_000) // 1.2 MB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1200000")
		for i := 0; i < len(payload); i += 64 << 10 {
			end := min(i+64<<10, len(payload))
			w.Write(payload[i:end])
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	var buf bytes.Buffer
	emit := NDJSONProgress(&buf)
	p := NewProgress("download", []ProgressStep{{"downloading", "big.dmg", 1}}, emit)
	n := &Net{AllowLoopbackHTTP: true}
	sum, size, err := n.Download(context.Background(), srv.URL+"/big.dmg", filepath.Join(t.TempDir(), "big.dmg"), p.Bytes)
	if err != nil || size != int64(len(payload)) || len(sum) != 64 {
		t.Fatal(err)
	}
	p.StepDone()
	var evs []ProgressEvent
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e ProgressEvent
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, e)
	}
	if len(evs) < 3 || evs[0].Percent != 0 || evs[len(evs)-1].Percent != 100 {
		t.Fatalf("events %d first %d last %d", len(evs), evs[0].Percent, evs[len(evs)-1].Percent)
	}
	for _, e := range evs[1 : len(evs)-1] {
		if e.Total != int64(len(payload)) || int64(e.Percent) != min(e.Done*100/e.Total, 99) {
			t.Fatalf("percent %d not backed by bytes %d/%d", e.Percent, e.Done, e.Total)
		}
	}
}
