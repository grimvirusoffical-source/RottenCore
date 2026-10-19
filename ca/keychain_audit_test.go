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
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "scripts", "rollout")
	if env := os.Getenv("MAC_SIGN_SH"); env != "" {
		dir = filepath.Dir(env)
	}
	if _, err := os.Stat(dir); err != nil {
		alt := "/workspace/rollout"
		if _, err2 := os.Stat(alt); err2 != nil {
			t.Skip("scripts/rollout not found; ceremony script audit skipped")
		}
		dir = alt
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.sh"))
	if err != nil || len(entries) == 0 {
		t.Skip("no *.sh in", dir)
	}
	var combined strings.Builder
	for _, path := range entries {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		combined.WriteString(text)
		combined.WriteByte('\n')
		if strings.Contains(text, "add-generic-password") {
			t.Fatalf("%s must not call add-generic-password; use rottencore-ca --keychain", path)
		}
		for _, line := range strings.Split(text, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") || !strings.Contains(trim, "security") {
				continue
			}
			// Existence probes without -w are OK. find … -w in phase-pair is intentional:
			// the secret is captured into a shell/python variable, never passed as another process's argv.
			// Still forbid add-generic-password and `security … -w` used to *set* a password.
			if strings.Contains(trim, "add-generic-password") {
				t.Fatalf("%s: %s", path, trim)
			}
		}
		// Bearer token must not appear on curl argv
		for _, line := range strings.Split(text, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") {
				continue
			}
			// Allow `printf 'Authorization: …' | curl -H @-` (header on stdin). Forbid Bearer on curl argv.
			if strings.Contains(trim, "curl") && strings.Contains(trim, "Authorization: Bearer") && !strings.Contains(trim, "-H @-") && !strings.Contains(trim, "printf") {
				t.Fatalf("%s puts Authorization on curl argv (use -H @-): %s", path, trim)
			}
			if strings.Contains(trim, "curl") && strings.Contains(trim, "$GITHUB_TOKEN") && strings.Contains(trim, "-H") && !strings.Contains(trim, "-H @-") && !strings.Contains(trim, "printf") {
				t.Fatalf("%s expands GITHUB_TOKEN into curl -H argv: %s", path, trim)
			}
		}
	}
	text := combined.String()
	if !strings.Contains(text, "--keychain") {
		t.Fatalf("%s scripts should use --keychain so keys stay in the Keychain", dir)
	}
}
