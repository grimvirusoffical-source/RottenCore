package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

func runLogin(ctx context.Context, c *core.Core, noBrowser bool) {
	who, err := c.LoginQuick(ctx, func(p core.LoginPrompt) {
		fmt.Fprintf(os.Stderr, "Quick Login\nCode: %s\nOpen: %s\n", p.UserCode, p.VerificationURI)
		if !noBrowser {
			openBrowser(p.VerificationURI)
		}
	})
	check(err)
	out(who, func() { printWho(who) })
}

func openBrowser(uri string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", uri)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", uri)
	default:
		cmd = exec.Command("xdg-open", uri)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "open the Quick Login URL in a browser")
	}
}

func runDevCert(ctx context.Context, c *core.Core, secretsStdin bool) {
	token, err := c.AccessToken()
	check(err)
	pw, err := readSignPassword(secretsStdin)
	if err != nil {
		fail(err, 1)
	}
	defer core.Wipe(pw)
	rec, err := c.EnsureDeveloperCert(ctx, token, pw, nil)
	check(err)
	out(rec, func() {
		fmt.Printf("developer cert %s\nemail: %s\npubkey: %s\n", rec.CertID, rec.Email, rec.PubKey)
		fmt.Println("Accounts has no developer-certificate registration endpoint; this public key is stored on this computer only.")
	})
}

func runOpen(ctx context.Context, c *core.Core, path string, secretsStdin bool) {
	pw, err := readSignPassword(secretsStdin)
	if err != nil {
		fail(err, 1)
	}
	defer core.Wipe(pw)
	e, err := c.OpenSigned(ctx, path, pw, o.accept, nil)
	check(err)
	out(e, func() { fmt.Printf("installed %s %s\n", e.Name, e.Version) })
}

func runDaemon(ctx context.Context, c *core.Core, rest []string) {
	home, _ := os.UserHomeDir()
	exe, _ := os.Executable()
	if len(rest) > 0 {
		switch rest[0] {
		case "install":
			path, err := core.InstallAutostart(home, exe)
			check(err)
			out(map[string]string{"autostart": path}, func() { fmt.Println("launch at login:", path) })
			return
		case "uninstall":
			check(core.RemoveAutostart(home))
			out(map[string]bool{"removed": true}, func() { fmt.Println("launch at login removed") })
			return
		default:
			fail(errors.New("usage: rottencore daemon [install|uninstall]"), 2)
		}
	}
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(96 << 20)
	err := c.RunDaemon(ctx, core.DaemonConfig{Downloads: filepath.Join(home, "Downloads")})
	if errors.Is(err, core.ErrDaemonReset) {
		if os.Getenv("ROTTENCORE_DAEMON_SUPERVISED") == "1" {
			os.Exit(0)
		}
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if startErr := cmd.Start(); startErr == nil {
			os.Exit(0)
		}
		os.Exit(0)
	}
	check(err)
}
