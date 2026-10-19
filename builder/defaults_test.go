package builder_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/builder"
)

// TestFillDefaultsAcceptsQuickLaunchPlatformOnly is the cross-repo fixture: QuickLaunch writes targets
// with only "platform" set; after FillDefaults, ReadRequest/Validate must accept them.
func TestFillDefaultsAcceptsQuickLaunchPlatformOnly(t *testing.T) {
	dir := t.TempDir()
	// Minimal Node project so DefaultCommand picks npm scripts.
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"ql-fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := map[string]interface{}{
		"schema":      builder.RequestSchema,
		"id":          "quicklaunch-1-0-0",
		"requestedBy": "quicklaunch",
		"createdMs":   1,
		"project": map[string]string{
			"name": "QuickLaunch", "id": "com.redx.quicklaunch", "version": "1.0.0", "dir": dir,
		},
		"targets": []map[string]string{
			{"platform": "macos-arm64"},
			{"platform": "linux"},
		},
	}
	raw, _ := json.Marshal(fixture)
	path := filepath.Join(dir, "request.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	req, targets, err := builder.ReadRequest(path)
	if err != nil {
		t.Fatalf("ReadRequest rejected QuickLaunch platform-only targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets: %d", len(targets))
	}
	for _, tgt := range req.Targets {
		if len(tgt.Command) == 0 && tgt.Prebuilt == "" {
			t.Fatalf("target %s still has no command after FillDefaults", tgt.Platform)
		}
	}
}

// Write the same fixture for QuickLaunch's mirrored test to load.
func TestWriteCrossRepoFixture(t *testing.T) {
	dir := filepath.Join("testdata")
	_ = os.MkdirAll(dir, 0o755)
	fixture := map[string]interface{}{
		"schema": "rottencore.build-request/v1", "id": "quicklaunch-1-0-0", "requestedBy": "quicklaunch",
		"createdMs": 1,
		"project":   map[string]string{"name": "QuickLaunch", "id": "com.redx.quicklaunch", "version": "1.0.0", "dir": "."},
		"targets":   []map[string]string{{"platform": "macos-arm64"}, {"platform": "linux"}},
	}
	raw, _ := json.MarshalIndent(fixture, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "ql-platform-only-request.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
