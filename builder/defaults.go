package builder

import (
	"os"
	"path/filepath"
)

// DefaultCommand returns the agreed per-platform build command when QuickLaunch (or another client)
// sends a target with neither command nor prebuilt. Both repos use this convention
// (docs/BUILDER.md §Defaults; quick-launch/internal/rottencore.DefaultCommand).
//
// Detection is by project files in dir:
//   - package.json  → npm/electron-builder style
//   - go.mod        → go build
//   - otherwise     → a clearly-named stub that fails loudly
func DefaultCommand(platform, dir string) (command []string, artifact string) {
	hasPkg := fileExists(filepath.Join(dir, "package.json"))
	hasGo := fileExists(filepath.Join(dir, "go.mod"))
	out := filepath.Join("dist", platform)
	switch platform {
	case PlatformMacArm64:
		if hasPkg {
			return []string{"npm", "run", "build:mac-arm64", "--if-present"}, filepath.Join(out, "app.dmg")
		}
		if hasGo {
			return []string{"go", "build", "-o", filepath.Join(out, "app"), "."}, filepath.Join(out, "app")
		}
	case PlatformMacIntel:
		if hasPkg {
			return []string{"npm", "run", "build:mac-x64", "--if-present"}, filepath.Join(out, "app.dmg")
		}
		if hasGo {
			return []string{"go", "build", "-o", filepath.Join(out, "app"), "."}, filepath.Join(out, "app")
		}
	case PlatformWindows:
		if hasPkg {
			return []string{"npm", "run", "build:win", "--if-present"}, filepath.Join(out, "app.exe")
		}
		if hasGo {
			return []string{"go", "build", "-o", filepath.Join(out, "app.exe"), "."}, filepath.Join(out, "app.exe")
		}
	case PlatformLinux:
		if hasPkg {
			return []string{"npm", "run", "build:linux", "--if-present"}, filepath.Join(out, "app.AppImage")
		}
		if hasGo {
			return []string{"go", "build", "-o", filepath.Join(out, "app"), "."}, filepath.Join(out, "app")
		}
	case PlatformExtensions:
		if hasPkg {
			return []string{"npm", "run", "build:extension", "--if-present"}, filepath.Join(out, "extension.zip")
		}
	case PlatformAndroid:
		if hasPkg {
			return []string{"npm", "run", "build:android", "--if-present"}, filepath.Join(out, "app.apk")
		}
	case PlatformIOS:
		if hasPkg {
			return []string{"npm", "run", "build:ios", "--if-present"}, filepath.Join(out, "app.ipa")
		}
	}
	// Last resort: a command that fails with a clear name so the loading screen shows what happened.
	return []string{"sh", "-c", "echo 'rottencore: no default build command for this project type; set command or prebuilt in the request' >&2; exit 1"}, ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// FillDefaults sets Command/Artifact on any target that has neither a command nor a prebuilt path,
// using DefaultCommand against Project.Dir. Safe to call before Validate.
func (r *Request) FillDefaults() {
	if r == nil {
		return
	}
	dir := r.Project.Dir
	if dir == "" {
		dir = "."
	}
	for i := range r.Targets {
		t := &r.Targets[i]
		if len(t.Command) > 0 || t.Prebuilt != "" {
			continue
		}
		cmd, art := DefaultCommand(t.Platform, dir)
		t.Command = cmd
		if t.Artifact == "" {
			t.Artifact = art
		}
	}
}
