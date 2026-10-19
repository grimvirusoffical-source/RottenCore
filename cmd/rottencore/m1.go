package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// Milestone 1 commands: fetch (real progress for the loading screen), verify-signature (Red-XAI cert chain +
// revocation), verify-update-manifest (redx.update-manifest/v1). Production trust only: pinned CA roots,
// pinned store key and pinned host keys, all from code.

var progressMode string // "" (text bar on stderr) | json (NDJSON on stderr, for the app's loading screen)

func progressEmitter() func(core.ProgressEvent) {
	if progressMode == "json" {
		return core.NDJSONProgress(os.Stderr)
	}
	return func(e core.ProgressEvent) {
		fmt.Fprintf(os.Stderr, "\r[%3d/100] %-70.70s", e.Percent, e.Line)
		if e.State != "running" {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func runM1(ctx context.Context, cmd string, rest []string, kid string, lastSeq int64) bool {
	switch cmd {
	case "fetch":
		need(rest, 2)
		p := core.NewProgress("download", []core.ProgressStep{{Action: "downloading", Item: filepath.Base(rest[1]), Weight: 1}}, progressEmitter())
		n := &core.Net{GitHubToken: os.Getenv("ROTTENCORE_GITHUB_TOKEN")}
		sum, size, err := n.Download(ctx, rest[0], rest[1], p.Bytes)
		if err != nil {
			p.Fail(err)
			check(err)
		}
		p.StepDone()
		out(map[string]interface{}{"sha256": sum, "bytes": size, "path": rest[1]}, func() { fmt.Printf("%s  %s (%d bytes)\n", sum, rest[1], size) })
	case "verify-signature":
		need(rest, 1)
		file := rest[0]
		sigPath := file + core.SignatureSidecar
		if len(rest) > 1 {
			sigPath = rest[1]
		}
		sum, size, err := core.FileSHA256(file)
		check(err)
		var sig *core.FileSignature
		if b, err := os.ReadFile(sigPath); err == nil {
			sig, err = core.ParseFileSignature(b)
			check(err)
		}
		cfg, err := core.LoadConfig(core.SupportDir())
		check(err)
		cache := &core.RevocationCache{Path: filepath.Join(core.SupportDir(), "status-ticket.json"), Pins: core.PinnedStoreKeys}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		rev, rerr := cache.Refresh(rctx, &core.Net{}, cfg.StoreURL)
		cancel()
		r := core.VerifyFileSignature(sig, sum, size, core.ChainPolicy{Roots: core.PinnedCARoots, Production: true}, rev)
		if rerr != nil {
			r.Reasons = append(r.Reasons, "revocation list not refreshed: "+rerr.Error())
		}
		out(r, func() {
			fmt.Printf("%s: %s (revocation list: %s)\n", file, r.Status, r.Revocation)
			for _, s := range r.Reasons {
				fmt.Println("  -", s)
			}
		})
		if r.Refuse() {
			os.Exit(4)
		}
		if !r.Trusted() {
			os.Exit(3)
		}
	case "verify-update-manifest":
		// verify-update-manifest <manifest.json> <manifest.sig | "ed25519:..."> <keys.json> [--kid K] [--last-seq N]
		need(rest, 3)
		body, err := os.ReadFile(rest[0])
		check(err)
		sig := rest[1]
		if !strings.HasPrefix(sig, "ed25519:") {
			b, err := os.ReadFile(sig)
			check(err)
			sig = strings.TrimSpace(string(b))
		}
		kb, err := os.ReadFile(rest[2])
		check(err)
		var keys []core.UpdateKey
		check(json.Unmarshal(kb, &keys))
		trusted := core.TrustedUpdateKeys(keys, core.PinnedUpdateKeyFingerprints, time.Now())
		if len(trusted) == 0 {
			fail(errors.New("no pinned Red-XAI Host update key is in that key list (none is provisioned yet)"), 3)
		}
		m, err := core.VerifyUpdateManifest(body, sig, kid, trusted, lastSeq)
		check(err)
		a, aerr := m.PickArtifact(runtime.GOOS, runtime.GOARCH, "", "")
		out(map[string]interface{}{"manifest": m, "artifact": a}, func() {
			fmt.Printf("%s %s (%s, sequence %d): signature OK\n  %s\n", m.App, m.Version, m.Channel, m.Sequence, m.Outcome.Summary)
			if aerr == nil {
				fmt.Printf("  for this machine: %s — %s\n", a.Label, a.Filename)
			}
		})
	default:
		return false
	}
	return true
}
