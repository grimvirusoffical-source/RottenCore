package builder_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/builder"
)

func writeInbox(t *testing.T, support, id string, body map[string]interface{}, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(support, "build-requests")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if body["id"] == nil {
		body["id"] = id
	}
	if body["schema"] == nil {
		body["schema"] = builder.RequestSchema
	}
	raw, _ := json.Marshal(body)
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func validBody(dir string) map[string]interface{} {
	return map[string]interface{}{
		"requestedBy": "quicklaunch",
		"createdMs":   1,
		"project": map[string]string{
			"name": "QuickLaunch", "id": "com.redx.quicklaunch", "version": "1.0.0", "dir": dir,
		},
		"targets": []map[string]string{{"platform": "linux", "prebuilt": filepath.Join(dir, "app")}},
	}
}

func TestOpenInboxRejectsTraversalIDs(t *testing.T) {
	support := t.TempDir()
	for _, id := range []string{
		"../../../../../evil/evil",
		"../evil",
		"foo/bar",
		"foo.bar",
		"short",                        // < 8
		"",                             // empty
		"a" + string(make([]byte, 64)), // too long once expanded — use a long string
		"has space1",
		"has.dots1",
	} {
		if len(id) > 64 {
			id = id[:65]
		}
		_, _, _, err := builder.OpenInboxRequest(support, id)
		if !errors.Is(err, builder.ErrBadBuildID) {
			t.Fatalf("id %q: want ErrBadBuildID, got %v", id, err)
		}
		_, err = builder.InboxPath(support, id)
		if !errors.Is(err, builder.ErrBadBuildID) {
			t.Fatalf("InboxPath(%q): want ErrBadBuildID, got %v", id, err)
		}
	}
}

func TestOpenInboxRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink perms differ on Windows")
	}
	support := t.TempDir()
	outside := t.TempDir()
	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, "app"), []byte("x"), 0o644)
	evil := filepath.Join(outside, "evil.json")
	body := validBody(proj)
	body["id"] = "evilreq01"
	raw, _ := json.Marshal(body)
	os.WriteFile(evil, raw, 0o600)
	inbox := filepath.Join(support, "build-requests")
	os.MkdirAll(inbox, 0o700)
	link := filepath.Join(inbox, "symlink01.json")
	if err := os.Symlink(evil, link); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := builder.OpenInboxRequest(support, "symlink01")
	if err == nil {
		t.Fatal("symlink escape accepted")
	}
	if !errors.Is(err, builder.ErrInboxEscape) && !errors.Is(err, builder.ErrInboxPerms) {
		t.Fatalf("want escape/perms error, got %v", err)
	}
}

func TestOpenInboxRejectsWrongMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix mode bits")
	}
	support, proj := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(proj, "app"), []byte("x"), 0o644)
	body := validBody(proj)
	writeInbox(t, support, "modefail1", body, 0o644) // group/world readable
	_, _, _, err := builder.OpenInboxRequest(support, "modefail1")
	if !errors.Is(err, builder.ErrInboxPerms) {
		t.Fatalf("want ErrInboxPerms, got %v", err)
	}
}

func TestOpenInboxRejectsIDMismatch(t *testing.T) {
	support, proj := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(proj, "app"), []byte("x"), 0o644)
	body := validBody(proj)
	body["id"] = "other-id-01" // file will be named mismatch1.json
	writeInbox(t, support, "mismatch1", body, 0o600)
	_, _, _, err := builder.OpenInboxRequest(support, "mismatch1")
	if !errors.Is(err, builder.ErrIDMismatch) {
		t.Fatalf("want ErrIDMismatch, got %v", err)
	}
}

func TestOpenInboxAcceptsStrictGoodRequest(t *testing.T) {
	support, proj := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(proj, "app"), []byte("x"), 0o644)
	body := validBody(proj)
	writeInbox(t, support, "good-req1", body, 0o600)
	req, targets, path, err := builder.OpenInboxRequest(support, "good-req1")
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != "good-req1" || len(targets) != 1 {
		t.Fatalf("got id=%s targets=%d", req.ID, len(targets))
	}
	prev := builder.MakePreview(req, targets, path)
	if prev.App != "QuickLaunch" || prev.Dir != proj || prev.Message == "" {
		t.Fatalf("preview %+v", prev)
	}
	if err := builder.ConsumeRequest(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request was not deleted")
	}
}

func TestConfirmRequiredSentinel(t *testing.T) {
	if builder.ErrConfirmRequired == nil || builder.ErrConfirmRequired.Error() == "" {
		t.Fatal("ErrConfirmRequired must be a clear user-facing error")
	}
}

// N4: scrubBuildEnv must drop the API keys so npm scripts never see them.
func TestScrubBuildEnvDropsAPIKeys(t *testing.T) {
	in := []string{"PATH=/bin", "RA_API_KEY=ra_sk_secret", "ROTTENCORE_BUILD_API_KEY=ra_sk_build", "RA_HOST_KEY=h", "HOME=/tmp"}
	out := builder.ScrubBuildEnvForTest(in)
	joined := strings.Join(out, "\n")
	for _, bad := range []string{"RA_API_KEY=", "ROTTENCORE_BUILD_API_KEY=", "RA_HOST_KEY="} {
		if strings.Contains(joined, bad) {
			t.Fatalf("scrubbed env still has %s: %v", bad, out)
		}
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "HOME=/tmp") {
		t.Fatalf("lost unrelated env: %v", out)
	}
}
