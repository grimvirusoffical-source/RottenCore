package builder_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// N5: the default Go build must set GOOS/GOARCH (and CGO_ENABLED=0) per target so a Mac never labels a
// Mach-O as Linux or an arm64 binary as Intel.
func TestDefaultGoCommandSetsGOOSGOARCH(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		builder.PlatformMacArm64: {"darwin", "arm64"},
		builder.PlatformMacIntel: {"darwin", "amd64"},
		builder.PlatformWindows:  {"windows", "amd64"},
		builder.PlatformLinux:    {"linux", "amd64"},
	}
	for plat, ga := range want {
		cmd, _ := builder.DefaultCommand(plat, dir)
		if len(cmd) < 2 || cmd[0] != "go" || cmd[1] != "build" {
			t.Fatalf("%s: expected go build argv (no env wrapper), got %v", plat, cmd)
		}
		for _, a := range cmd {
			if strings.HasPrefix(a, "GOOS=") || a == "env" {
				t.Fatalf("%s: GOOS/GOARCH must not be in the command argv (Windows has no env(1)): %v", plat, cmd)
			}
		}
		env := builder.GoBuildEnv(plat)
		joined := strings.Join(env, " ")
		if !strings.Contains(joined, "GOOS="+ga[0]) || !strings.Contains(joined, "GOARCH="+ga[1]) || !strings.Contains(joined, "CGO_ENABLED=0") {
			t.Fatalf("%s: GoBuildEnv want GOOS=%s GOARCH=%s CGO_ENABLED=0, got %v", plat, ga[0], ga[1], env)
		}
	}
}

func TestFillDefaultsSetsGoEnv(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n"), 0o644)
	req := &builder.Request{Project: builder.Project{Dir: dir}, Targets: []builder.Target{{Platform: builder.PlatformLinux}}}
	req.FillDefaults()
	if len(req.Targets[0].Env) == 0 || !strings.Contains(strings.Join(req.Targets[0].Env, " "), "GOOS=linux") {
		t.Fatalf("FillDefaults must set Target.Env for Go builds, got %v", req.Targets[0].Env)
	}
	if req.Targets[0].Command[0] == "env" {
		t.Fatal("command must not start with env")
	}
}
