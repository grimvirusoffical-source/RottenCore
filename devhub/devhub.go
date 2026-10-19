// Package devhub is Rotten Core's client for a developer's Rotten Apple dev account: the device
// registration, the build API key, the team/individual build context, and the per-app SDK selection.
//
// Grok Bot is building the server side in ra-core on branch dev-hub. Those endpoints are not live yet, so
// everything here sits behind interfaces with a local, file-backed default (LocalDeviceService,
// LocalContextProvider). docs/DEV_HUB.md documents the migration to the dev-hub HTTP API: swap the local
// implementations for HTTPDeviceService / HTTPContextProvider against docs/DEV_HUB_API.md once it exists.
// Nothing here registers a real device or runs anything on Josh's Mac; approval is explicit.
package devhub

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Platform is the device class the store records. A Mac may build/sign Mac and iOS apps; a Windows PC may
// build/sign Windows and Android apps. This mirrors (and is the source of) the builder's host split.
type Platform string

const (
	PlatformMac     Platform = "mac"
	PlatformWindows Platform = "windows"
)

// Target platform ids (same strings as package builder, kept here to avoid an import cycle).
const (
	TargetMacArm64   = "macos-arm64"
	TargetMacIntel   = "macos-intel"
	TargetIOS        = "ios"
	TargetWindows    = "windows"
	TargetAndroid    = "android"
	TargetLinux      = "linux"
	TargetExtensions = "extensions"
)

// DevicePlatform returns the platform class of the machine Rotten Core runs on.
func DevicePlatform() (Platform, error) {
	switch runtime.GOOS {
	case "darwin":
		return PlatformMac, nil
	case "windows":
		return PlatformWindows, nil
	default:
		return "", fmt.Errorf("a developer device must be a Mac or a Windows PC; this is %s", runtime.GOOS)
	}
}

// deviceTargets is what each device platform may build and sign. Linux and browser-extension assets need
// neither Apple nor Windows toolchains, so any registered device may produce them.
var deviceTargets = map[Platform][]string{
	PlatformMac:     {TargetMacArm64, TargetMacIntel, TargetIOS, TargetLinux, TargetExtensions},
	PlatformWindows: {TargetWindows, TargetAndroid, TargetLinux, TargetExtensions},
}

// TargetsFor lists the build targets a device platform is allowed to produce.
func TargetsFor(p Platform) []string { return deviceTargets[p] }

// Allows reports whether a device platform may build and sign a target.
func (p Platform) Allows(target string) bool {
	for _, t := range deviceTargets[p] {
		if t == target {
			return true
		}
	}
	return false
}

// Device is a registered (or pending) developer device.
type Device struct {
	ID          string   `json:"id"`
	Platform    Platform `json:"platform"`
	PublicKey   []byte   `json:"publicKey"` // the device key Rotten Core generated (never leaves the machine)
	PairingCode string   `json:"pairingCode"`
	Approved    bool     `json:"approved"`
	TeamID      string   `json:"teamId,omitempty"`     // the dev account/team that approved it
	Individual  bool     `json:"individual,omitempty"` // approved under an individual account, not a team
	CreatedMs   int64    `json:"createdMs"`
	ApprovedMs  int64    `json:"approvedMs,omitempty"`
}

// ErrNoDevice means no approved device is registered for this machine.
var ErrNoDevice = errors.New("this device is not registered: open Rotten Core > Dev account, start registration and approve the pairing code in your Rotten Apple dev dashboard")

// ErrNoBuildKey is shown verbatim by Rotten Core and the QuickLaunch hand-off when a build API key is
// missing.
var ErrNoBuildKey = errors.New("Create a build API key in your Rotten Apple dev account.")

// NewPairingCode makes a short, human-readable pairing code (e.g. "RC-7FQ2-K9MX").
func NewPairingCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("RC-")
	for i, x := range b {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return sb.String(), nil
}

// PairingLabel describes who approved the device, for the CLI/UI.
func (d *Device) PairingLabel() string {
	if d.Individual || d.TeamID == "" {
		return "an individual account"
	}
	return "team " + d.TeamID
}
