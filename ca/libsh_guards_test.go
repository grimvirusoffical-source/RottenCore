package ca

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runLib(t *testing.T, env []string, script string) (string, error) {
	t.Helper()
	lib := filepath.Join(rolloutScriptsDir(t), "lib.sh")
	cmd := exec.Command("bash", "-c", `set -euo pipefail; die(){ echo "DIE: $*" >&2; exit 9; }; source "$LIB"; `+script)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "LIB=" + lib, "HOME=" + t.TempDir()}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// QA L1: the shell env guard is case-insensitive like Go's (?i) accountsKeyEnvRe.
func TestLibEnvGuardCaseInsensitive(t *testing.T) {
	for _, n := range []string{"REDX_ACCOUNTS_KEY", "redx_accounts_key", "Redx_Full_Token", "rxa_secret_x", "red_xai_key", "My_Account_Token", "ACCOUNTS_API_KEY"} {
		out, err := runLib(t, []string{n + "=ra_sk_live_SECRETVALUE"}, "refuse_accounts_key_env")
		if err == nil || !strings.Contains(out, n) {
			t.Errorf("%s not refused: %v %s", n, err, out)
		}
		if strings.Contains(out, "SECRETVALUE") {
			t.Errorf("%s: value printed", n)
		}
	}
	if out, err := runLib(t, []string{"KEYCHAIN_SERVICE=x", "RA_DEVHUB_URL=https://x", "ROTTEN_DEV_ID=x"}, "refuse_accounts_key_env"); err != nil {
		t.Errorf("benign env refused: %s", out)
	}
}

// QA L2: RA_DEVHUB_URL must be https (plain http only to loopback).
func TestLibDevhubURLHTTPSOnly(t *testing.T) {
	for _, u := range []string{"https://api.rottenapplestore.org", "https://api.rottenapplestore.org/", "https://hub.example:8443", "http://127.0.0.1:8080", "http://localhost:9000", "http://[::1]:1"} {
		if out, err := runLib(t, nil, `require_https_devhub "`+u+`"`); err != nil {
			t.Errorf("%s refused: %s", u, out)
		}
	}
	for _, u := range []string{"http://api.rottenapplestore.org", "http://10.0.0.5", "ftp://x", "api.rottenapplestore.org", "https://user:pw@x", "https://x/path", "https://x?q=1", "http://127.0.0.1.evil.example", "http://localhost.evil.example", ""} {
		out, err := runLib(t, nil, `require_https_devhub "`+u+`"`)
		if err == nil || !strings.Contains(out, "https") {
			t.Errorf("%q accepted: %s", u, out)
		}
	}
	lib, _ := exec.Command("grep", "-c", `require_https_devhub "$DEVHUB_URL"`, filepath.Join(rolloutScriptsDir(t), "lib.sh")).Output()
	if strings.TrimSpace(string(lib)) != "1" {
		t.Error("setup_rollout_env must call require_https_devhub on RA_DEVHUB_URL")
	}
}

// The backup MANIFEST pin is the same everywhere it is written (lib.sh, QA-README).
func TestManifestPinConsistent(t *testing.T) {
	dir := rolloutScriptsDir(t)
	out, err := exec.Command("bash", "-c", `grep -o 'ROTTEN_MANIFEST_SHA256:-[0-9a-f]\{64\}' "$0/lib.sh" | cut -d- -f2`, dir).Output()
	pin := strings.TrimSpace(string(out))
	if err != nil || len(pin) != 64 {
		t.Fatalf("no pin in lib.sh: %v %q", err, pin)
	}
	readme, err := exec.Command("cat", filepath.Join(dir, "QA-README.md")).Output()
	if err != nil || !strings.Contains(string(readme), pin) {
		t.Fatalf("QA-README.md does not state the lib.sh MANIFEST pin %s", pin)
	}
	if strings.Contains(string(readme), "81c30f1041bc5501") || strings.Contains(string(readme), "ca16acf820c69848") {
		t.Fatal("QA-README.md still names the old MANIFEST pin")
	}
}
