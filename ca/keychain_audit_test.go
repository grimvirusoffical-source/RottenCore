package ca

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestKeychainDarwinSourceKeepsSecretsOffArgv is a static audit: the darwin Keychain Put path must not
// pass the private-key blob as an argv element of `security` (QA blocker: visible in `ps`).
func TestKeychainDarwinSourceKeepsSecretsOffArgv(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	src := filepath.Join(filepath.Dir(file), "keychain_darwin.go")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	// Forbidden: exec.Command("security", …, "-w", <something that includes the blob variable>)
	// Allowed: security -i with the blob only on stdin.
	if !strings.Contains(text, `exec.Command("security", "-i")`) {
		t.Fatal(`Put must invoke exec.Command("security", "-i") so the secret rides on stdin, not argv`)
	}
	// Any Command("security", ...) whose arg list includes "-w" next to a non-literal is a regression.
	re := regexp.MustCompile(`exec\.Command\(\s*"security"\s*,([^)]*)\)`)
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		args := m[1]
		if strings.Contains(args, `"-i"`) || strings.Contains(args, `"find-generic-password"`) {
			continue // -i has no secret in argv; find -w prints to stdout
		}
		if strings.Contains(args, `"-w"`) {
			t.Fatalf("security argv still includes -w (secret risk): exec.Command(\"security\", %s)", args)
		}
	}
}

// TestMacSignScriptKeepsKeyMaterialOffArgv audits the Mac ceremony script: it must drive signing
// through rottencore-ca --keychain (labels only) and must never invoke `security … -w <secret>`.
func TestMacSignScriptKeepsKeyMaterialOffArgv(t *testing.T) {
	candidates := []string{
		os.Getenv("MAC_SIGN_SH"),
		"/workspace/rollout/mac-sign.sh",
		filepath.Join("..", "..", "rollout", "mac-sign.sh"),
	}
	var path string
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("mac-sign.sh not found (set MAC_SIGN_SH); ceremony script audit skipped")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	// The script must never call the security(1) CLI itself with a password flag.
	if regexp.MustCompile(`(?m)^\s*security\b`).MatchString(text) {
		t.Fatalf("%s invokes security(1) directly; private-key material must stay behind rottencore-ca --keychain", path)
	}
	if strings.Contains(text, "add-generic-password") {
		t.Fatalf("%s must not call add-generic-password; use rottencore-ca --keychain", path)
	}
	// Positive: signing goes through --keychain labels.
	if !strings.Contains(text, "--keychain") {
		t.Fatalf("%s should use --keychain so keys stay in the Keychain", path)
	}
}
