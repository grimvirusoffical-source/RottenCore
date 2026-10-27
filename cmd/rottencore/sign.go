package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

func validateSign(lifetime, withLauncher, withoutLauncher bool, platform string, paths []string) error {
	if !lifetime {
		return errors.New("sign needs --lifetime")
	}
	if withLauncher == withoutLauncher {
		return errors.New("sign needs exactly one of --with-launcher or --without-launcher")
	}
	if strings.TrimSpace(platform) == "" {
		return errors.New("sign needs --platform macos|ios|android|windows|linux")
	}
	if len(paths) != 1 || strings.TrimSpace(paths[0]) == "" {
		return errors.New("sign needs the file to sign")
	}
	return nil
}

func runSign(ctx context.Context, c *core.Core, paths []string, lifetime, withLauncher, withoutLauncher, viaAgent, secretsStdin bool, platform string) {
	if err := validateSign(lifetime, withLauncher, withoutLauncher, platform, paths); err != nil {
		fail(err, 2)
	}
	token := os.Getenv("ROTTENCORE_ACCESS_TOKEN")
	who, err := c.WhoAmI(ctx, token)
	check(err)
	useAgent := viaAgent || who.Role != core.RoleOwner
	if useAgent {
		if !c.AgentRunning() {
			fail(core.ErrAgentDown, 1)
		}
		res, err := c.AgentSign(ctx, token, paths[0], platform, withLauncher)
		check(err)
		out(res, func() { printSign(res) })
		return
	}
	pw, err := readSignPassword(secretsStdin)
	if err != nil {
		fail(err, 1)
	}
	defer core.Wipe(pw)
	res, err := c.SignLifetime(ctx, token, pw, paths[0], platform, withLauncher, nil)
	check(err)
	out(res, func() { printSign(res) })
}

func printSign(r *core.SignResult) {
	fmt.Printf("signed %s %s\n", r.AppID, r.Version)
	fmt.Printf("sig id: %s\n", r.SigID)
	fmt.Printf("sha256: %s\n", r.Hash)
	fmt.Printf("platforms: %s\n", strings.Join(r.Platforms, ", "))
	if r.LauncherRequired {
		fmt.Println("launcher required: yes")
	} else {
		fmt.Println("launcher required: no")
	}
	if r.PrevSigID != "" {
		fmt.Println("previous sig id:", r.PrevSigID)
	}
	fmt.Println("wrote:", r.Output)
	fmt.Println(r.OfficialOSSigning)
}

func printWho(w *core.Who) {
	fmt.Printf("%s (%s)\n", w.Role, w.Email)
	fmt.Printf("verified: %v  2FA: %v  idVerified: %v\n", w.Verified, w.MFA, w.IDVerified)
	fmt.Printf("platforms: %s\n", strings.Join(w.Platforms, ", "))
	fmt.Printf("launcher installed: %v  running: %v\n", w.LauncherInstalled, w.LauncherRunning)
	if w.AgentRunning {
		fmt.Println("signing agent: running")
	} else {
		fmt.Println("signing agent: stopped")
	}
	fmt.Println(w.OfficialOSSigning)
}

func runAgent(ctx context.Context, c *core.Core, rest []string) {
	if len(rest) > 0 && rest[0] == "shutdown" {
		check(c.ShutdownAgent(ctx))
		out(map[string]bool{"stopped": true}, func() { fmt.Println("signing agent stopped") })
		return
	}
	if len(rest) > 0 {
		fail(errors.New("usage: rottencore agent [shutdown]"), 2)
	}
	token, pw, err := core.ReadAgentHandshake(os.Stdin)
	if err != nil {
		fail(err, 1)
	}
	defer core.Wipe(pw)
	check(c.RunAgent(ctx, token, pw, nil))
}

func readSignPassword(fromStdin bool) ([]byte, error) {
	if fromStdin {
		b, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		if err != nil && len(b) == 0 {
			return nil, errors.New("could not read the Red-SecretsXAI password")
		}
		b = bytes.TrimRight(b, "\r\n")
		if len(b) == 0 {
			return nil, errors.New("the Red-SecretsXAI password was empty")
		}
		return b, nil
	}
	return readTTYPassword()
}

func readTTYPassword() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no terminal; pass the Red-SecretsXAI password on stdin with --secrets-stdin")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, "Red-SecretsXAI password: "); err != nil {
		return nil, err
	}
	off := exec.Command("stty", "-echo")
	off.Stdin = tty
	if err := off.Run(); err != nil {
		return nil, errors.New("could not turn off terminal echo")
	}
	defer func() {
		on := exec.Command("stty", "echo")
		on.Stdin = tty
		_ = on.Run()
		fmt.Fprintln(tty)
	}()
	line, err := bufio.NewReader(tty).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, errors.New("could not read the Red-SecretsXAI password")
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("the Red-SecretsXAI password was empty")
	}
	return line, nil
}
