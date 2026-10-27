package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// Daemon limits. The process exits with ErrDaemonReset so the OS supervisor
// starts a fresh one. Support files, the keyring, and installed apps are left
// in place.
const (
	DaemonTick      = 60 * time.Second
	DaemonRSSLimit  = 64 << 20
	DaemonMaxUptime = 12 * time.Hour
	DaemonStall     = 3 * time.Minute
)

// ErrDaemonReset means the daemon should be replaced by a new process.
var ErrDaemonReset = errors.New("rottencore daemon reset")

// DaemonConfig tunes one daemon run. Zero values use the documented limits.
type DaemonConfig struct {
	Tick      time.Duration
	Stall     time.Duration
	MaxUptime time.Duration
	RSSLimit  uint64
	Downloads string
	RSS       func() uint64
	Now       func() time.Time
	Started   time.Time
	OnReset   func(reason string)
}

func (cfg DaemonConfig) tick() time.Duration {
	if cfg.Tick > 0 {
		return cfg.Tick
	}
	return DaemonTick
}

func (cfg DaemonConfig) stall() time.Duration {
	if cfg.Stall > 0 {
		return cfg.Stall
	}
	return DaemonStall
}

func (cfg DaemonConfig) maxUptime() time.Duration {
	if cfg.MaxUptime > 0 {
		return cfg.MaxUptime
	}
	return DaemonMaxUptime
}

func (cfg DaemonConfig) rssLimit() uint64 {
	if cfg.RSSLimit > 0 {
		return cfg.RSSLimit
	}
	return DaemonRSSLimit
}

func (cfg DaemonConfig) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now()
	}
	return time.Now()
}

// daemonResetReason reports why a fresh process is needed. Empty means keep running.
func daemonResetReason(rss, limit uint64, uptime, maxUptime, sinceTick, stall time.Duration) string {
	if limit > 0 && rss > limit {
		return "memory"
	}
	if maxUptime > 0 && uptime > maxUptime {
		return "uptime"
	}
	if stall > 0 && sinceTick > stall {
		return "watchdog"
	}
	return ""
}

// RunDaemon watches downloads, records update checks, and resets itself when the
// limits in DaemonConfig are crossed. It does not install or decrypt anything:
// opening a carrier still asks for the Red-SecretsXAI password.
func (c *Core) RunDaemon(ctx context.Context, cfg DaemonConfig) error {
	if cfg.Started.IsZero() {
		cfg.Started = cfg.now()
	}
	last := cfg.now()
	ticker := time.NewTicker(cfg.tick())
	defer ticker.Stop()
	for {
		if err := c.daemonPass(ctx, cfg); err != nil && ctx.Err() == nil {
			return err
		}
		since := cfg.now().Sub(last)
		rss := uint64(0)
		if cfg.RSS != nil {
			rss = cfg.RSS()
		}
		if why := daemonResetReason(rss, cfg.rssLimit(), cfg.now().Sub(cfg.Started), cfg.maxUptime(), since, cfg.stall()); why != "" {
			if cfg.OnReset != nil {
				cfg.OnReset(why)
			}
			return fmtReset(why)
		}
		last = cfg.now()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func fmtReset(why string) error {
	return errors.Join(ErrDaemonReset, errors.New(why))
}

func (c *Core) daemonPass(ctx context.Context, cfg DaemonConfig) error {
	if cfg.Downloads != "" {
		if err := c.noteCarriers(cfg.Downloads); err != nil {
			return err
		}
	}
	ups, err := c.CheckUpdates(ctx)
	if err != nil {
		return nil
	}
	b, err := json.MarshalIndent(struct {
		Schema  int          `json:"schema"`
		Checked string       `json:"checked"`
		Updates []UpdateInfo `json:"updates"`
	}{Schema: 1, Checked: cfg.now().UTC().Format(time.RFC3339), Updates: ups}, "", "  ")
	if err != nil || c.State == nil {
		return nil
	}
	return writePrivate(filepath.Join(c.State.Dir, "updates.json"), append(b, '\n'))
}

func (c *Core) noteCarriers(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, sign.FileExt) || strings.HasSuffix(name, ".rotten_core_signed") {
			found = append(found, filepath.Join(dir, name))
		}
	}
	if len(found) == 0 || c.State == nil {
		return nil
	}
	prev := c.pendingPaths()
	seen := map[string]bool{}
	for _, p := range prev {
		seen[p] = true
	}
	for _, p := range found {
		if !seen[p] {
			prev = append(prev, p)
		}
	}
	b, err := json.MarshalIndent(struct {
		Schema int      `json:"schema"`
		Paths  []string `json:"paths"`
	}{Schema: 1, Paths: prev}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(c.State.Dir, "pending-imports.json"), append(b, '\n'))
}

func (c *Core) pendingPaths() []string {
	b, err := os.ReadFile(filepath.Join(c.State.Dir, "pending-imports.json"))
	if err != nil {
		return nil
	}
	var f struct {
		Paths []string `json:"paths"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Paths
}
