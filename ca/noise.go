// Package ca is the Red-XAI certificate generator for the ra-core CA path: magnitude tiers, white-noise
// entropy mixing, key generation, issuing, update-signer certificates for Red-XAI Hosts, and revocation
// list updates. It uses the TEST root until Josh's root ceremony; production roots are pinned in
// core.PinnedCARoots only after that.
package ca

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"runtime"
	"time"
)

// White noise (docs/CERTGEN.md §2). Key material is
//
//	seed = HKDF-SHA-512(ikm = 64 bytes of OS CSPRNG || SHA-512(noise samples), salt = "ra-core keygen v1", info)
//
// The OS CSPRNG is ALWAYS required (keygen fails if it fails); noise is an extra input that can only
// add entropy. A weak, missing or tampered noise source leaves the key exactly as strong as the OS CSPRNG
// alone. Raw samples are never logged or stored: only their SHA-512 enters the mix, and only health
// results are reported.

// NoiseSource produces raw noise samples.
type NoiseSource interface {
	Name() string
	Sample(ctx context.Context, n int) ([]byte, error)
}

// JitterNoise is "generated" noise: CPU timing jitter (nanosecond deltas of a busy loop). Always
// available, low quality by design; it never stands alone.
type JitterNoise struct{}

func (JitterNoise) Name() string { return "generated:cpu-jitter" }

func (JitterNoise) Sample(ctx context.Context, n int) ([]byte, error) {
	out := make([]byte, n)
	x := uint64(1)
	for i := range out {
		if i%4096 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t0 := time.Now().UnixNano()
		for j := 0; j < 64+int(x&63); j++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
		if i%97 == 0 {
			runtime.Gosched()
		}
		out[i] = byte(time.Now().UnixNano()-t0) ^ byte(x>>56)
	}
	return out, nil
}

// MicrophoneNoise records raw PCM from the default microphone with an external recorder (optional; for
// the root ceremony on a Mac). Default command: ffmpeg from AVFoundation. If the recorder is missing or
// the user denies microphone access, Sample fails and the source is simply skipped.
type MicrophoneNoise struct {
	Command []string // nil = DefaultMicCommand(); must write raw samples to stdout
	Seconds int      // default 2
}

// DefaultMicCommand records mono 16-bit PCM from the default input device.
func DefaultMicCommand(seconds int) []string {
	if runtime.GOOS == "darwin" {
		return []string{"ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "avfoundation", "-i", ":0", "-t", fmt.Sprint(seconds), "-ac", "1", "-f", "s16le", "-"}
	}
	return []string{"arecord", "-q", "-f", "S16_LE", "-c", "1", "-d", fmt.Sprint(seconds), "-t", "raw"}
}

func (m MicrophoneNoise) Name() string { return "microphone" }

func (m MicrophoneNoise) Sample(ctx context.Context, n int) ([]byte, error) {
	secs := m.Seconds
	if secs <= 0 {
		secs = 2
	}
	cmd := m.Command
	if cmd == nil {
		cmd = DefaultMicCommand(secs)
	}
	if _, err := exec.LookPath(cmd[0]); err != nil {
		return nil, fmt.Errorf("microphone recorder %s not found", cmd[0])
	}
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	var buf bytes.Buffer
	c.Stdout = &buf
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("microphone recording failed: %v", err)
	}
	b := buf.Bytes()
	if len(b) < n {
		return nil, fmt.Errorf("microphone gave %d bytes, wanted %d", len(b), n)
	}
	return b, nil
}

// ReaderNoise wraps any reader (a hardware RNG device, an ADC stream, a test vector).
type ReaderNoise struct {
	Label string
	R     io.Reader
}

func (r ReaderNoise) Name() string { return r.Label }
func (r ReaderNoise) Sample(_ context.Context, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r.R, b)
	return b, err
}

// Health is what gets logged about one source (never the samples).
type Health struct {
	Source        string  `json:"source"`
	Bytes         int     `json:"bytes"`
	OK            bool    `json:"ok"`
	Used          bool    `json:"used"`
	RepetitionMax int     `json:"repetitionMax"` // longest run of one byte value
	ProportionMax int     `json:"proportionMax"` // most frequent value in a 512-sample window
	MinEntropy    float64 `json:"minEntropyBitsPerByte"`
	Problem       string  `json:"problem,omitempty"`
}

// SP 800-90B style continuous health tests for 8-bit samples, assuming at least ~1 bit/byte claimed
// entropy (H=1): repetition count cutoff C = 1 + ceil(20/H) = 21; adaptive proportion window 512,
// cutoff 410 (alpha 2^-20 at H=1).
const (
	repCutoff  = 21
	propWindow = 512
	propCutoff = 410
)

// CheckHealth runs the tests and a most-common-value min-entropy estimate.
func CheckHealth(name string, b []byte) Health {
	h := Health{Source: name, Bytes: len(b)}
	if len(b) < propWindow {
		h.Problem = "too few samples"
		return h
	}
	run, maxRun := 1, 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 1
		}
	}
	h.RepetitionMax = maxRun
	for w := 0; w+propWindow <= len(b); w += propWindow {
		var cnt [256]int
		for _, x := range b[w : w+propWindow] {
			cnt[x]++
		}
		for _, c := range cnt {
			if c > h.ProportionMax {
				h.ProportionMax = c
			}
		}
	}
	var all [256]int
	top := 0
	for _, x := range b {
		all[x]++
		if all[x] > top {
			top = all[x]
		}
	}
	p := float64(top) / float64(len(b))
	h.MinEntropy = -math.Log2(p)
	switch {
	case maxRun >= repCutoff:
		h.Problem = fmt.Sprintf("repetition count test failed (run of %d)", maxRun)
	case h.ProportionMax >= propCutoff:
		h.Problem = fmt.Sprintf("adaptive proportion test failed (%d of %d)", h.ProportionMax, propWindow)
	default:
		h.OK = true
	}
	return h
}

// Mixer combines the OS CSPRNG with noise sources.
type Mixer struct {
	Sources []NoiseSource
	Samples int       // bytes per source, default 4096
	OS      io.Reader // nil = crypto/rand.Reader (tests may replace it to prove it is always used)
	// Log receives health reports (never samples).
	Log func(Health)
}

// ErrNoOSRandom means the OS CSPRNG failed: keygen must stop, noise can never stand in.
var ErrNoOSRandom = errors.New("the OS random number generator failed; refusing to generate keys")

// Material returns n bytes of key material for info (purpose, tier, serial) and the health reports.
func (m *Mixer) Material(ctx context.Context, info string, n int) ([]byte, []Health, error) {
	osr := m.OS
	if osr == nil {
		osr = rand.Reader
	}
	ikm := make([]byte, 64, 128)
	if _, err := io.ReadFull(osr, ikm); err != nil {
		return nil, nil, ErrNoOSRandom
	}
	samples := m.Samples
	if samples <= 0 {
		samples = 4096
	}
	nh := sha512.New()
	var reports []Health
	for _, s := range m.Sources {
		b, err := s.Sample(ctx, samples)
		var h Health
		if err != nil {
			h = Health{Source: s.Name(), Problem: err.Error()}
		} else {
			h = CheckHealth(s.Name(), b)
			if h.OK {
				nh.Write([]byte(s.Name()))
				nh.Write(b)
				h.Used = true
			}
			for i := range b { // do not keep samples around
				b[i] = 0
			}
		}
		reports = append(reports, h)
		if m.Log != nil {
			m.Log(h)
		}
	}
	ikm = append(ikm, nh.Sum(nil)...)
	out := hkdfSHA512(ikm, []byte("ra-core keygen v1"), []byte(info), n)
	for i := range ikm {
		ikm[i] = 0
	}
	return out, reports, nil
}

// hkdfSHA512 is RFC 5869 HKDF with SHA-512 (extract then expand).
func hkdfSHA512(ikm, salt, info []byte, n int) []byte {
	ex := hmac.New(sha512.New, salt)
	ex.Write(ikm)
	prk := ex.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha512.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}
