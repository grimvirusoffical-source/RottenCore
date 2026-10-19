// Package builder is Rotten Core's builder: it takes a build request (from QuickLaunch or the CLI), builds
// each target in Josh's order, labels and names every output, signs it with the developer's ra-core
// certificate (.rasig), writes SHA256SUMS and hands the set to the uploader, all behind the shared loading
// screen (core.Progress, real progress only).
//
// Nothing is encrypted. The packaging step goes through the seal hook (ENCRYPTION-HOOK builder.package),
// which is a no-op until an encrypter is plugged in.
package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// RequestSchema is the version string every build request carries.
const RequestSchema = "rottencore.build-request/v1"

// Request is the build request schema (docs/BUILDER.md). QuickLaunch writes one into Rotten Core's inbox
// (<support dir>/build-requests/<id>.json) and opens rottencore://build?id=<id>; the CLI takes a path.
type Request struct {
	Schema      string    `json:"schema"`
	ID          string    `json:"id"`          // [A-Za-z0-9_-]{8,64}; also the inbox file name
	RequestedBy string    `json:"requestedBy"` // "quicklaunch" | "cli" | ...
	CreatedMs   int64     `json:"createdMs"`
	Project     Project   `json:"project"`
	Targets     []Target  `json:"targets"`
	SDKs        []string  `json:"sdks,omitempty"`   // SDKs this build declares; validated against the store selection
	Upload      *UploadTo `json:"upload,omitempty"` // nil = build and sign only
	// BuildAPIKey is the Rotten Apple build API key QuickLaunch passes through (file mode 0600). Never log it.
	BuildAPIKey string `json:"buildApiKey,omitempty"`
}

// Project names the thing being built and the label the assets carry.
type Project struct {
	Name    string `json:"name"`    // "QuickLaunch"
	ID      string `json:"id"`      // "com.redx.quicklaunch" (reverse-DNS app id)
	Version string `json:"version"` // "1.0.0"
	Channel string `json:"channel"` // "", "beta", "rc", "nightly" -> shown in the label
	Dir     string `json:"dir"`     // project root the build commands run in
	// IconProduct selects the app-icon set under assets/icons/<product> (IconRottenCore by default,
	// IconPoisonApple for the Poison Apple launcher build).
	IconProduct string `json:"iconProduct,omitempty"`
}

// Target is one platform to build.
type Target struct {
	Platform string   `json:"platform"` // one of Platforms
	Command  []string `json:"command"`  // build command; empty -> Prebuilt must be set
	Prebuilt string   `json:"prebuilt"` // path to an already-built artifact (skip the command)
	Artifact string   `json:"artifact"` // path the command leaves the artifact at (relative to Project.Dir)
}

// UploadTo picks the store for a successful build (handled by package uploader).
type UploadTo struct {
	Store   string `json:"store"`             // "ra-core" | "github" | "both"
	BaseURL string `json:"baseUrl,omitempty"` // ra-core base, when not the default
}

// Platforms is Josh's build order: Mac arm64, Mac Intel, Windows, Linux, the browser extensions, then the
// Android and iOS targets QuickLaunch supports.
var Platforms = []string{
	PlatformMacArm64,
	PlatformMacIntel,
	PlatformWindows,
	PlatformLinux,
	PlatformExtensions,
	PlatformAndroid,
	PlatformIOS,
}

const (
	PlatformMacArm64   = "macos-arm64"
	PlatformMacIntel   = "macos-intel"
	PlatformWindows    = "windows"
	PlatformLinux      = "linux"
	PlatformExtensions = "extensions"
	PlatformAndroid    = "android"
	PlatformIOS        = "ios"
)

var platformOrder = func() map[string]int {
	m := map[string]int{}
	for i, p := range Platforms {
		m[p] = i
	}
	return m
}()

// Validate checks a request and returns the targets in build order.
func (r *Request) Validate() ([]Target, error) {
	if r.Schema != RequestSchema {
		return nil, fmt.Errorf("unknown build request schema %q (want %q)", r.Schema, RequestSchema)
	}
	if err := ValidateBuildID(r.ID); err != nil {
		return nil, err
	}
	if r.Project.Name == "" || r.Project.Version == "" || r.Project.ID == "" {
		return nil, errors.New("project needs a name, id and version")
	}
	if len(r.Targets) == 0 {
		return nil, errors.New("no build targets")
	}
	seen := map[string]bool{}
	for _, t := range r.Targets {
		if _, ok := platformOrder[t.Platform]; !ok {
			return nil, fmt.Errorf("unknown platform %q", t.Platform)
		}
		if seen[t.Platform] {
			return nil, fmt.Errorf("platform %q listed twice", t.Platform)
		}
		seen[t.Platform] = true
		if len(t.Command) == 0 && t.Prebuilt == "" {
			return nil, fmt.Errorf("target %q has neither a command nor a prebuilt artifact", t.Platform)
		}
	}
	out := append([]Target(nil), r.Targets...)
	sort.SliceStable(out, func(i, j int) bool { return platformOrder[out[i].Platform] < platformOrder[out[j].Platform] })
	return out, nil
}

// ReadRequest loads and validates a request file.
func ReadRequest(path string) (*Request, []Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, err
	}
	r.FillDefaults() // QuickLaunch may send platform-only targets; fill the agreed default commands
	targets, err := r.Validate()
	if err != nil {
		return nil, nil, err
	}
	return &r, targets, nil
}
