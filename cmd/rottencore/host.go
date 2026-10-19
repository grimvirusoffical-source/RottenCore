package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// --host and the host key let the CLI drive a Red-XAI Host's update API so the updater UI's rollout cards
// can do live rollbacks (and apply/promote/source). The host key comes from the environment and is never
// printed. Mirrors core.HostClient.
var hostBase string

// hostClient builds a HostClient from --host (or RA_HOST_URL) and the key in RA_HOST_KEY.
func hostClient() (*core.HostClient, error) {
	base := hostBase
	if base == "" {
		base = os.Getenv("RA_HOST_URL")
	}
	if base == "" {
		return nil, errors.New("no host configured: pass --host https://redx.example or set RA_HOST_URL")
	}
	return &core.HostClient{Base: base, Token: os.Getenv("RA_HOST_KEY")}, nil
}

// runHost handles `rottencore host ...`. It returns false for any other command.
func runHost(ctx context.Context, cmd string, rest []string) bool {
	if cmd != "host" {
		return false
	}
	need(rest, 1)
	h, err := hostClient()
	check(err)
	switch rest[0] {
	case "status":
		if len(rest) >= 2 {
			app, err := h.App(ctx, rest[1])
			check(err)
			out(app, func() { printHostApp(app) })
			return true
		}
		apps, err := h.Apps(ctx)
		check(err)
		out(apps, func() {
			for i := range apps {
				printHostApp(&apps[i])
			}
		})
	case "rollout":
		need(rest, 2)
		r, err := h.Rollout(ctx, rest[1])
		check(err)
		out(r, func() {
			fmt.Printf("rollout %s: %s %s, %s, %s (%s)\n", r.RolloutID, r.App, r.Version, r.State, r.Strategy, r.HealthSummary())
			if r.AwaitingHealthData() {
				fmt.Println("awaiting health data — nothing auto-promotes yet")
			}
		})
	case "rollback": // live rollback of a rollout (what the updater rollout card calls)
		need(rest, 2)
		reason := "rolled back from Rotten Core"
		if len(rest) >= 3 {
			reason = strings.Join(rest[2:], " ")
		}
		check(h.RollbackRollout(ctx, rest[1], reason))
		out(map[string]string{"rolledBack": rest[1]}, func() { fmt.Printf("rollout %s rolled back\n", rest[1]) })
	case "app-rollback": // restore one app to a snapshot (that app only)
		need(rest, 3)
		check(h.RestoreSnapshot(ctx, rest[1], rest[2]))
		out(map[string]string{"app": rest[1], "snapshot": rest[2]}, func() { fmt.Printf("%s restored to %s\n", rest[1], rest[2]) })
	case "promote":
		need(rest, 2)
		check(h.Promote(ctx, rest[1]))
		out(map[string]string{"promoted": rest[1]}, func() { fmt.Printf("rollout %s promoted\n", rest[1]) })
	case "apply":
		need(rest, 3)
		source := "host"
		if len(rest) >= 4 {
			source = rest[3]
		}
		ro, snap, err := h.Apply(ctx, rest[1], core.ApplyRequest{Version: rest[2], Source: source})
		check(err)
		out(map[string]string{"rollout": ro, "snapshot": snap}, func() { fmt.Printf("rollout %s started (snapshot %s)\n", ro, snap) })
	case "source":
		need(rest, 3)
		app, err := h.App(ctx, rest[1])
		check(err)
		check(h.SetSource(ctx, rest[1], rest[2], app.Hosted))
		out(map[string]string{"app": rest[1], "source": rest[2]}, func() { fmt.Printf("%s update source set to %s\n", rest[1], rest[2]) })
	case "snapshots":
		need(rest, 2)
		snaps, err := h.Snapshots(ctx, rest[1])
		check(err)
		out(snaps, func() {
			for _, s := range snaps {
				fmt.Printf("%s  %s %s  %s\n", s.ID, s.App, s.Version, s.SHA256)
			}
		})
	default:
		fail(errors.New("usage: rottencore host status [app] | rollout <id> | rollback <id> [reason] | app-rollback <app> <snapshot> | promote <id> | apply <app> <version> [source] | source <app> <host|github|both> | snapshots <app>"), 2)
	}
	return true
}

func printHostApp(a *core.HostApp) {
	installed := "—"
	if a.Installed != nil {
		installed = a.Installed.Version
	}
	fmt.Printf("%s (installed %s, hosted=%v, source=%s)\n", a.App, installed, a.Hosted, a.SourcePref)
	for _, v := range a.OfferableVersions() {
		fmt.Printf("  offer %s [%s] via %s\n", v.Version, v.Channel, strings.Join(v.Sources, ","))
	}
}
