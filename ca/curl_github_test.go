package ca

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// QA D3 (scripts): curl_github never follows a redirect itself. A fake curl on PATH plays GitHub: the
// authenticated call answers 302 to $FAKE_LOC; only an https GitHub asset host is then fetched, without
// the token (the token only ever reaches curl on stdin of the first call).
func TestCurlGithubHandlesRedirectsExplicitly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	lib := filepath.Join(rolloutScriptsDir(t), "lib.sh")
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	fake := `#!/bin/bash
in=$(cat 2>/dev/null)
echo "ARGS $*" >> "$CALLS"
echo "STDIN ${in}" >> "$CALLS"
dest=""; prev=""
for a in "$@"; do [[ "$prev" == "-o" ]] && dest="$a"; prev="$a"; done
case "$*" in
  *api.github.com*) echo body > "$dest"; printf '%s %s' "$FAKE_CODE" "$FAKE_LOC" ;;
  *) echo asset > "$dest" ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(code, loc string) (string, string, error) {
		os.Remove(log)
		dest := filepath.Join(t.TempDir(), "asset.partial")
		cmd := exec.Command("bash", "-c", `set -euo pipefail; die(){ echo "$*" >&2; exit 9; }; source "$LIB"; GH_RELEASE_TOKEN=tok_SECRET; curl_github "https://api.github.com/repos/o/r/releases/assets/1" "$DEST"`)
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "CALLS=" + log, "FAKE_CODE=" + code, "FAKE_LOC=" + loc, "LIB=" + lib, "DEST=" + dest, "HOME=" + t.TempDir()}
		out, err := cmd.CombinedOutput()
		calls, _ := os.ReadFile(log)
		if _, serr := os.Stat(dest); err != nil && serr == nil {
			t.Errorf("failed download left %s behind", dest)
		}
		return string(out), string(calls), err
	}
	// 302 to the GitHub asset host: second call has no token, no -L, https only.
	out, calls, err := run("302", "https://objects.githubusercontent.com/x/y?sig=Q")
	if err != nil {
		t.Fatalf("asset redirect refused: %v %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(calls), "\n")
	if len(lines) != 4 || !strings.Contains(lines[1], "Authorization: Bearer tok_SECRET") || strings.Contains(lines[3], "tok_SECRET") || strings.Contains(lines[2], "tok_SECRET") {
		t.Fatalf("token must reach only the first call, on stdin:\n%s", calls)
	}
	if strings.Contains(calls, " -L") || !strings.Contains(lines[2], "--max-redirs 0") || !strings.Contains(lines[0], "--max-redirs 0") {
		t.Fatalf("curl must not follow redirects:\n%s", calls)
	}
	// 200 directly: one call.
	if _, calls, err := run("200", ""); err != nil || strings.Count(calls, "ARGS") != 1 {
		t.Fatalf("200: %v\n%s", err, calls)
	}
	// Anything else is a hard error naming only status and host; the target is never contacted.
	for _, c := range [][2]string{
		{"307", "https://evil.example/x?sig=Q"},
		{"302", "http://objects.githubusercontent.com/x"},
		{"302", "https://objects.githubusercontent.com.evil.example/x"},
		{"302", ""},
		{"404", ""},
		{"500", ""},
	} {
		out, calls, err := run(c[0], c[1])
		if err == nil || strings.Count(calls, "ARGS") != 1 {
			t.Errorf("%v: want a hard error with no second request, got %v\n%s", c, err, calls)
		}
		if strings.Contains(out, "sig=Q") || strings.Contains(out, "tok_SECRET") || !strings.Contains(out, c[0]) {
			t.Errorf("%v: message must name only status and host: %s", c, out)
		}
	}
}
