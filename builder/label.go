package builder

import (
	"fmt"
	"regexp"
	"strings"
)

// Label is the human asset label Josh asked for, e.g. "QuickLaunch Beta 1.0.0 (Mac, M1 chip)".
func Label(p Project, platform string) string {
	name := p.Name
	if ch := channelWord(p.Channel); ch != "" {
		name += " " + ch
	}
	return fmt.Sprintf("%s %s (%s)", name, p.Version, platformWords(platform))
}

// Filename is the distinct download name, e.g. "quicklaunch-1.0.0-beta-macos-arm64.dmg". Every platform gets
// a different name so two files never collide.
func Filename(p Project, platform string) string {
	parts := []string{slug(p.Name), p.Version}
	if ch := strings.ToLower(strings.TrimSpace(p.Channel)); ch != "" && ch != "stable" && ch != "release" {
		parts = append(parts, slug(ch))
	}
	parts = append(parts, platform)
	return strings.Join(parts, "-") + extFor(platform)
}

func channelWord(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "", "stable", "release":
		return ""
	case "beta":
		return "Beta"
	case "rc":
		return "RC"
	case "nightly":
		return "Nightly"
	default:
		return strings.Title(strings.ToLower(c))
	}
}

func platformWords(platform string) string {
	switch platform {
	case PlatformMacArm64:
		return "Mac, M1 chip"
	case PlatformMacIntel:
		return "Mac, Intel chip"
	case PlatformWindows:
		return "Windows"
	case PlatformLinux:
		return "Linux"
	case PlatformExtensions:
		return "Browser extensions"
	case PlatformAndroid:
		return "Android"
	case PlatformIOS:
		return "iOS"
	default:
		return platform
	}
}

func extFor(platform string) string {
	switch platform {
	case PlatformMacArm64, PlatformMacIntel:
		return ".dmg"
	case PlatformWindows:
		return ".exe"
	case PlatformLinux:
		return ".AppImage"
	case PlatformExtensions:
		return ".zip"
	case PlatformAndroid:
		return ".apk"
	case PlatformIOS:
		return ".ipa"
	default:
		return ".bin"
	}
}

// Kind is the artifact kind recorded in the .rasig (file signature doc).
func Kind(platform string) string {
	return strings.TrimPrefix(extFor(platform), ".")
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlug.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}
