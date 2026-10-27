package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Store installs go through the Rotten Apple launcher (ra-launcher), not through RottenCore's own
// engine. The launcher owns the .rarxai format and every store rule: the signed manifest and developer
// certificate chain, the store review receipt for the exact build, the signed status ticket (revocation),
// age gating on the store-confirmed rating, entitlements for paid apps and the splash rules. RottenCore
// only detects that a file or app id belongs to the store, checks the store's attestation of the file's
// sha256 up front, and hands over. It never re-implements those checks.

// LauncherCandidates are where ra-launcher is looked for, in order.
func LauncherCandidates() []string {
	c := []string{}
	if p := os.Getenv("ROTTENCORE_RA_LAUNCHER"); p != "" {
		c = append(c, p)
	}
	if p, err := exec.LookPath("ra-launcher"); err == nil {
		c = append(c, p)
	}
	c = append(c,
		"/Applications/Rotten Apple.app/Contents/MacOS/ra-launcher",
		"/Applications/Poison Apple.app/Contents/MacOS/pa-launcher",
		"/Applications/Poison Apple.app/Contents/MacOS/Poison Apple",
		"/usr/local/bin/ra-launcher",
		"/usr/local/bin/pa-launcher",
		"/opt/homebrew/bin/ra-launcher",
	)
	return c
}

// LauncherStatus reports the Rotten Apple or Poison Apple launcher. installed means a
// candidate binary exists; running means that binary, or a process named ra-launcher,
// pa-launcher, "Rotten Apple" or "Poison Apple", is executing.
func LauncherStatus() (path string, installed, running bool) {
	path, err := FindLauncher()
	installed = err == nil && path != ""
	running = launcherRunning(path)
	return path, installed, running
}

// FindLauncher returns the first ra-launcher that exists.
func FindLauncher() (string, error) {
	for _, p := range LauncherCandidates() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("the Rotten Apple launcher (ra-launcher) is not installed; store apps are installed and checked by it")
}

// StoreInstallLink is the deep link the launcher's own install sheet answers.
func StoreInstallLink(store, appID string) (string, error) {
	if !ValidOrigin(store, false) {
		return "", fmt.Errorf("store URL %q is not an https origin", store)
	}
	if !appIDRe.MatchString(appID) {
		return "", fmt.Errorf("invalid app id %q", appID)
	}
	return "rottenapple://install?app=" + url.QueryEscape(appID) + "&store=" + url.QueryEscape(strings.TrimRight(store, "/")), nil
}

// InstallRARXAI hands a store package file to ra-launcher (which verifies it fully) and records it.
func (c *Core) InstallRARXAI(ctx context.Context, in *Inspection) (*Entry, error) {
	l, err := FindLauncher()
	if err != nil {
		return nil, err
	}
	args := []string{}
	if in.Store != nil && in.Store.URL != "" {
		args = append(args, "--store", in.Store.URL)
	}
	args = append(args, "install", in.Path)
	out, err := c.Engine.R.Run(ctx, l, args...)
	if err != nil {
		return nil, fmt.Errorf("the Rotten Apple launcher refused it: %w", err)
	}
	e := Entry{AppID: in.AppID, Name: in.Name, Version: in.Version, Source: SourceStore, Trusted: in.Verdict.Trusted, TrustedBy: in.Verdict.TrustedBy,
		AcceptedRisk: !in.Verdict.Trusted, Kind: KindRARXAI, ArtifactName: filepath.Base(in.Path), SHA256: in.Verdict.SHA256, Paths: []string{},
		Store: in.Store, AgeRating: in.AgeRating, Managed: "ra-launcher", InstalledAt: c.now().UTC(), UpdatedAt: c.now().UTC()}
	_ = out
	if e.AppID == "" {
		return nil, errors.New("installed by the Rotten Apple launcher; RottenCore could not tell which app it was (no store listing)")
	}
	return &e, c.State.Put(e)
}

// UpdateViaLauncher asks ra-launcher to update a store app (it needs the store session in
// RA_STORE_TOKEN, which comes from Red-XAI Accounts once that exists).
func (c *Core) UpdateViaLauncher(ctx context.Context, e *Entry) error {
	l, err := FindLauncher()
	if err != nil {
		return err
	}
	if e.Store == nil || e.Store.URL == "" {
		return errors.New("no store URL is recorded for this app")
	}
	_, err = c.Engine.R.Run(ctx, l, "--store", e.Store.URL, "update", e.AppID)
	return err
}

var launcherComms = []string{"ra-launcher", "pa-launcher", "Rotten Apple", "Poison Apple"}

func launcherName(name string) bool {
	base := filepath.Base(name)
	for _, n := range launcherComms {
		if name == n || base == n {
			return true
		}
	}
	return false
}

func launcherRunning(bin string) bool {
	// An explicit launcher path (tests, ROTTENCORE_RA_LAUNCHER) has to be that process.
	// Otherwise any Rotten Apple or Poison Apple process counts.
	strict := os.Getenv("ROTTENCORE_RA_LAUNCHER") != ""
	if st, err := os.Stat("/proc/1"); err == nil && st.IsDir() {
		return scanProc(bin, strict)
	}
	return scanPS(bin, strict)
}

func scanProc(bin string, strict bool) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		comm := ""
		if b, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		raw, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			continue
		}
		hitPath := false
		hitName := launcherName(comm)
		for _, a := range bytes.Split(raw, []byte{0}) {
			if bin != "" && string(a) == bin {
				hitPath = true
			}
			if launcherName(string(a)) || launcherName(filepath.Base(string(a))) {
				hitName = true
			}
		}
		if strict {
			if hitPath {
				return true
			}
			continue
		}
		if hitPath || hitName {
			return true
		}
	}
	return false
}

func scanPS(bin string, strict bool) bool {
	// -ww: macOS ps otherwise clips the command at the window width, which hides a long temp path.
	out, err := exec.Command("ps", "-axww", "-o", "command=").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "ps ") {
			continue
		}
		hitPath := bin != "" && strings.Contains(line, bin)
		hitName := false
		for _, n := range launcherComms {
			if strings.Contains(line, n) {
				hitName = true
			}
		}
		if strict {
			if hitPath {
				return true
			}
			continue
		}
		if hitPath || hitName {
			return true
		}
	}
	return false
}
