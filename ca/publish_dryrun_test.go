package ca

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Expected publish.sh --dry-run on the box (needs the box backups; skipped elsewhere): only the 21 signed
// macOS assets are replaced, the deferred ones are left exactly as published, checksum files are merged.
func TestPublishDryRunExpectations(t *testing.T) {
	backups := os.Getenv("ROTTEN_BACKUPS")
	if backups == "" {
		backups = "/workspace/release-backups"
	}
	if _, err := os.Stat(filepath.Join(backups, "MANIFEST.json")); err != nil {
		t.Skip("box backups not present")
	}
	src := rolloutScriptsDir(t)
	dir := t.TempDir()
	_, thisFile, _, _ := runtime.Caller(0)
	repoScripts := filepath.Join(filepath.Dir(thisFile), "..", "scripts", "rollout")
	for _, f := range []string{"publish.sh", "inventory.json", "inventory.full.json"} {
		from := filepath.Join(src, f)
		if _, err := os.Stat(from); err != nil && f == "inventory.full.json" {
			from = filepath.Join(repoScripts, f) // box-only file, not shipped in the Mac tgz
		}
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, f), b, 0o755)
	}
	var inv struct {
		Sign []struct{ Repo, Tag, Asset string } `json:"sign_on_mac"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "inventory.json"))
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "signed")
	for _, a := range inv.Sign {
		d := filepath.Join(signed, a.Repo, a.Tag)
		os.MkdirAll(d, 0o755)
		if err := os.Symlink(filepath.Join(backups, a.Repo, a.Tag, a.Asset), filepath.Join(d, a.Asset)); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, a.Asset+".rasig"), []byte("{}"), 0o644)
	}
	cmd := exec.Command("bash", filepath.Join(dir, "publish.sh"), "--dry-run")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GITHUB_TOKEN=dry-run-not-a-token", "ROTTEN_SIGNED_IN=" + signed, "ROTTEN_BACKUPS=" + backups}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	var plan map[string][]map[string]interface{}
	pb, _ := os.ReadFile(filepath.Join(dir, "work", "publish-plan.json"))
	if err := json.Unmarshal(pb, &plan); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"replacements": 21, "rasigs": 21, "sums": 0, "sums_unchanged": 4, "sums_blocked": 0, "missing_signed": 0,
		"skipped_deferred": 31, "untouched_latest": 6, "convert_to_draft": 9, "convert_to_draft_blocked": 0}
	for k, n := range want {
		if len(plan[k]) != n {
			t.Errorf("%s = %d, want %d", k, len(plan[k]), n)
		}
	}
	per := map[string]int{}
	for _, r := range plan["replacements"] {
		per[r["repo"].(string)]++
		n := r["name"].(string)
		if strings.Contains(strings.ToLower(n), "linux") || strings.HasSuffix(n, ".deb") || strings.Contains(n, "windows") || strings.Contains(n, "extension") {
			t.Errorf("non-Mac asset replaced: %s", n)
		}
	}
	for repo, n := range map[string]int{"RedX": 8, "quick-launch": 8, "RottenApple": 2, "gendragoon-cloud-ssd": 3} {
		if per[repo] != n {
			t.Errorf("%s replacements = %d, want %d", repo, per[repo], n)
		}
	}
}
