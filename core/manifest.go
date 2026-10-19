// Package core is RottenCore: the shared Red-XAI installer engine. It finds out where an app came from
// (the Rotten Apple Mac store or a GitHub release), checks the bytes, decides trust, installs .app, .dmg,
// .pkg and .zip payloads, keeps track of what it installed, checks for updates and uninstalls.
// docs/ROTTENCORE.md is the specification.
package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ManifestName is the file an app ships so RottenCore knows what it is. It sits inside the payload
// (App.app/Contents/Resources/rottencore.json, the root of a .dmg, a .pkg's Resources) or next to the
// downloaded file as <file>.rottencore.json.
const ManifestName = "rottencore.json"

// AttestationName is the store attestation file, found the same way as the manifest
// (<file>.rottencore-attestation.json next to the download, or rottencore.attestation.json inside).
const AttestationName = "rottencore.attestation.json"

// Sources.
const (
	SourceStore   = "store"
	SourceGitHub  = "github"
	SourceUnknown = "unknown"
)

// Kinds of payload.
const (
	KindApp    = "app"
	KindDMG    = "dmg"
	KindPKG    = "pkg"
	KindZIP    = "zip"
	KindRARXAI = "rarxai"
)

// Manifest is rottencore.json, schema 1.
type Manifest struct {
	Schema    int          `json:"schema"`
	AppID     string       `json:"appId"`
	Name      string       `json:"name"`
	Version   string       `json:"version"`
	Source    string       `json:"source"` // store | github: a claim only; trust needs proof (trust.go)
	GitHub    *GitHubRef   `json:"github,omitempty"`
	Store     *StoreRef    `json:"store,omitempty"`
	Artifact  *ArtifactRef `json:"artifact,omitempty"`
	Install   *InstallSpec `json:"install,omitempty"`
	MinMacOS  string       `json:"minMacOS,omitempty"`
	AgeRating string       `json:"ageRating,omitempty"` // everyone | 13+ | 18+ (shown; the store enforces)
}

// GitHubRef names the release a GitHub build came from.
type GitHubRef struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	Tag   string `json:"tag,omitempty"`
	// Asset is this file's name in the release; AssetPattern picks the asset of later releases for
	// updates, with {version} replaced by the release version (tag without a leading v).
	Asset        string `json:"asset,omitempty"`
	AssetPattern string `json:"assetPattern,omitempty"`
	Sums         string `json:"sums,omitempty"` // checksum asset name, default SHA256SUMS
}

// StoreRef names the store listing.
type StoreRef struct {
	URL       string `json:"url,omitempty"` // store origin; default from config
	ListingID int64  `json:"listingId,omitempty"`
}

// ArtifactRef describes the downloaded file. Only a sidecar manifest can carry its sha256 (a file cannot
// contain its own hash); it is a consistency check, never a reason to trust.
type ArtifactRef struct {
	Kind   string `json:"kind,omitempty"`
	Name   string `json:"name,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// InstallSpec says what to take out of a .dmg or .zip and where it goes.
type InstallSpec struct {
	Bundle      string   `json:"bundle,omitempty"`      // e.g. RedX.app (inside a dmg/zip)
	Pkg         string   `json:"pkg,omitempty"`         // e.g. RedX.pkg (inside a dmg)
	PkgIDs      []string `json:"pkgIds,omitempty"`      // receipt ids a .pkg installs (for uninstall)
	Destination string   `json:"destination,omitempty"` // default /Applications
}

var (
	appIDRe   = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9-]+)+$`)
	ghNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	versionRe = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.-]{1,40})?$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fileRe    = regexp.MustCompile(`^[^/\\\x00]{1,200}$`)
	macOSRe   = regexp.MustCompile(`^[0-9]{2}(\.[0-9]{1,2}){0,2}$`)
)

// ParseManifest decodes and validates rottencore.json. Unknown fields are refused so a typo cannot
// silently drop a setting.
func ParseManifest(b []byte) (*Manifest, error) {
	if len(b) > 64<<10 {
		return nil, errors.New("rottencore.json is larger than 64 KB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("rottencore.json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("rottencore.json: trailing data")
	}
	return &m, m.Validate()
}

// Validate checks every field.
func (m *Manifest) Validate() error {
	bad := func(f string, a ...interface{}) error { return fmt.Errorf("rottencore.json: "+f, a...) }
	if m.Schema != 1 {
		return bad("schema must be 1, got %d", m.Schema)
	}
	if !appIDRe.MatchString(m.AppID) || len(m.AppID) > 155 {
		return bad("appId must be reverse-DNS in lower case, like com.redxai.redx")
	}
	if strings.TrimSpace(m.Name) == "" || len(m.Name) > 80 {
		return bad("name must be 1 to 80 characters")
	}
	if !versionRe.MatchString(m.Version) {
		return bad("version %q is not a version like 1.2.3", m.Version)
	}
	switch m.Source {
	case SourceStore:
		if m.Store == nil {
			m.Store = &StoreRef{}
		}
	case SourceGitHub:
		if m.GitHub == nil || !ghNameRe.MatchString(m.GitHub.Owner) || !ghNameRe.MatchString(m.GitHub.Repo) {
			return bad("a github source needs github.owner and github.repo")
		}
		for _, f := range []string{m.GitHub.Asset, m.GitHub.AssetPattern, m.GitHub.Sums} {
			if f != "" && !fileRe.MatchString(f) {
				return bad("github asset names must be plain file names")
			}
		}
		if m.GitHub.Tag != "" && !ghNameRe.MatchString(m.GitHub.Tag) {
			return bad("github.tag is not a valid tag")
		}
	default:
		return bad("source must be %q or %q", SourceStore, SourceGitHub)
	}
	if m.Store != nil && m.Store.URL != "" && !ValidOrigin(m.Store.URL, false) {
		return bad("store.url must be an https origin")
	}
	if a := m.Artifact; a != nil {
		if a.Kind != "" && !validKind(a.Kind) {
			return bad("artifact.kind %q is not app, dmg, pkg, zip or rarxai", a.Kind)
		}
		if a.SHA256 != "" && !sha256Re.MatchString(a.SHA256) {
			return bad("artifact.sha256 must be 64 lower-case hex characters")
		}
		if a.Name != "" && !fileRe.MatchString(a.Name) {
			return bad("artifact.name must be a plain file name")
		}
	}
	if in := m.Install; in != nil {
		if in.Bundle != "" && (!fileRe.MatchString(in.Bundle) || !strings.HasSuffix(in.Bundle, ".app")) {
			return bad("install.bundle must be a plain .app name")
		}
		if in.Pkg != "" && (!fileRe.MatchString(in.Pkg) || !strings.HasSuffix(in.Pkg, ".pkg")) {
			return bad("install.pkg must be a plain .pkg name")
		}
		for _, id := range in.PkgIDs {
			if !ghNameRe.MatchString(id) {
				return bad("install.pkgIds has an invalid id %q", id)
			}
		}
		if in.Destination != "" && !allowedDestination(in.Destination) {
			return bad("install.destination must be /Applications or ~/Applications")
		}
	}
	if m.MinMacOS != "" && !macOSRe.MatchString(m.MinMacOS) {
		return bad("minMacOS must look like 12.0")
	}
	switch m.AgeRating {
	case "", "everyone", "13+", "18+":
	default:
		return bad("ageRating must be everyone, 13+ or 18+")
	}
	return nil
}

func validKind(k string) bool {
	switch k {
	case KindApp, KindDMG, KindPKG, KindZIP, KindRARXAI:
		return true
	}
	return false
}

func allowedDestination(d string) bool {
	return d == "/Applications" || d == "~/Applications"
}

// KindOf guesses the payload kind from a file name.
func KindOf(name string) string {
	l := strings.ToLower(strings.TrimRight(name, "/"))
	for _, k := range []string{KindApp, KindDMG, KindPKG, KindZIP, KindRARXAI} {
		if strings.HasSuffix(l, "."+k) {
			return k
		}
	}
	return ""
}
