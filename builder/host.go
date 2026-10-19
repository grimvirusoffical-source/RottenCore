package builder

import (
	"fmt"
	"runtime"
	"sort"
)

// HostOS is the build-and-sign device's OS as a runtime.GOOS value: "darwin" (Mac), "windows" or "linux".
func HostOS() string { return runtime.GOOS }

// Signing device policy (Josh's rule): a Mac builds and signs only Mac and iOS assets; a Windows machine
// builds and signs only Windows and Android assets. Linux and browser-extension assets need no Apple or
// Windows code-signing toolchain, so any host may build and sign them.
//
// signingHosts maps a platform to the host GOOS values allowed to build and sign it.
var signingHosts = map[string][]string{
	PlatformMacArm64:   {"darwin"},
	PlatformMacIntel:   {"darwin"},
	PlatformIOS:        {"darwin"},
	PlatformWindows:    {"windows"},
	PlatformAndroid:    {"windows"},
	PlatformLinux:      {"darwin", "windows", "linux"},
	PlatformExtensions: {"darwin", "windows", "linux"},
}

// CanSignOn reports whether a host GOOS may build and sign a platform's assets.
func CanSignOn(platform, host string) bool {
	for _, h := range signingHosts[platform] {
		if h == host {
			return true
		}
	}
	return false
}

// DeviceFor names the device a platform must be built and signed on, for an error or a checklist line,
// e.g. "a Mac" or "a Windows device". Host-neutral platforms return "any device".
func DeviceFor(platform string) string {
	hosts := signingHosts[platform]
	if len(hosts) != 1 {
		return "any device"
	}
	switch hosts[0] {
	case "darwin":
		return "a Mac"
	case "windows":
		return "a Windows device"
	default:
		return "a " + hosts[0] + " device"
	}
}

// ErrWrongHost is returned when the current device may not build or sign a platform's assets.
type ErrWrongHost struct {
	Platform string
	Host     string
}

func (e *ErrWrongHost) Error() string {
	return fmt.Sprintf("%s assets must be built and signed on %s, not on this %s host", e.Platform, DeviceFor(e.Platform), hostWord(e.Host))
}

func hostWord(goos string) string {
	switch goos {
	case "darwin":
		return "Mac"
	case "windows":
		return "Windows"
	default:
		return goos
	}
}

// SplitForHost sorts the targets into build order and separates the ones this host may build and sign
// (ordered) from the ones it may not (with the device each needs).
func SplitForHost(targets []Target, host string) (buildable []Target, deferred []Target) {
	ordered := append([]Target(nil), targets...)
	sort.SliceStable(ordered, func(i, j int) bool { return platformOrder[ordered[i].Platform] < platformOrder[ordered[j].Platform] })
	for _, t := range ordered {
		if CanSignOn(t.Platform, host) {
			buildable = append(buildable, t)
		} else {
			deferred = append(deferred, t)
		}
	}
	return buildable, deferred
}
