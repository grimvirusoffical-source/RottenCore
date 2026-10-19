package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner runs the macOS tools RottenCore needs (ditto, hdiutil, installer, pkgutil, codesign, spctl,
// mdls, xattr, xar, sw_vers). Tests replace it with a fake; nothing goes through a shell except
// RunAdmin's osascript prompt, whose arguments are quoted (shellQuote, appleScriptString).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunAdmin runs one command as root: directly when already root, otherwise through the chosen prompt.
	RunAdmin(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner is the real Runner. Admin is "sudo" (command line) or "osascript" (the standard macOS
// administrator password dialog, used by the app).
type ExecRunner struct {
	Admin string
}

// Run runs a command and returns stdout+stderr.
func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var buf bytes.Buffer
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	if err != nil {
		return buf.Bytes(), fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(lastLine(buf.String())))
	}
	return buf.Bytes(), nil
}

// RunAdmin runs a command as root.
func (r *ExecRunner) RunAdmin(ctx context.Context, name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return r.Run(ctx, name, args...)
	}
	switch r.Admin {
	case "osascript":
		parts := []string{shellQuote(name)}
		for _, a := range args {
			parts = append(parts, shellQuote(a))
		}
		script := "do shell script " + appleScriptString(strings.Join(parts, " ")) + " with administrator privileges"
		return r.Run(ctx, "/usr/bin/osascript", "-e", script)
	case "", "sudo":
		c := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"--", name}, args...)...)
		c.Stdin, c.Stderr = os.Stdin, os.Stderr
		out, err := c.Output()
		if err != nil {
			return out, fmt.Errorf("sudo %s: %v", name, err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown admin prompt %q", r.Admin)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// shellQuote quotes one argument for /bin/sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// appleScriptString makes an AppleScript string literal.
func appleScriptString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
