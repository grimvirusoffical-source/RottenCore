package main

import (
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type pipeTTY struct {
	r   *io.PipeReader
	out *strings.Builder
}

func (p pipeTTY) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p pipeTTY) Write(b []byte) (int, error) { return p.out.Write(b) }
func (p pipeTTY) Close() error                { return nil }

// QA L4: Ctrl-C at the hidden prompt aborts at once and turns echo back on.
func TestAccountsKeyPromptAbortsOnInterrupt(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	var echoOn, echoOff int32
	oldOpen, oldEcho, oldSig, oldInt := ttyOpen, ttyEcho, promptSignals, promptInterrupted
	defer func() { ttyOpen, ttyEcho, promptSignals, promptInterrupted = oldOpen, oldEcho, oldSig, oldInt }()
	ttyOpen = func() (io.ReadWriteCloser, error) { return pipeTTY{pr, &strings.Builder{}}, nil }
	ttyEcho = func(_ io.ReadWriteCloser, on bool) error {
		if on {
			atomic.AddInt32(&echoOn, 1)
		} else {
			atomic.AddInt32(&echoOff, 1)
		}
		return nil
	}
	sigc := make(chan chan<- os.Signal, 1)
	promptSignals = func(c chan<- os.Signal) { sigc <- c }
	aborted := make(chan struct{})
	promptInterrupted = func() {
		if atomic.LoadInt32(&echoOn) == 0 {
			t.Error("echo not restored before exit")
		}
		close(aborted)
		pw.CloseWithError(io.ErrClosedPipe) // the real path exits; here unblock the reader
	}
	errc := make(chan error, 1)
	go func() { _, err := readAccountsKey(); errc <- err }()
	c := <-sigc
	c <- os.Interrupt
	select {
	case <-aborted:
	case <-time.After(3 * time.Second):
		t.Fatal("Ctrl-C at the hidden prompt did not abort")
	}
	if err := <-errc; err == nil {
		t.Fatal("aborted read returned a key")
	}
	if atomic.LoadInt32(&echoOff) != 1 {
		t.Fatal("echo was not turned off for the prompt")
	}
}
