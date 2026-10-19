package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Red-XAI Host update manifests: the client side of specs/redx-host-update-contract.md §1
// ("redx.update-manifest/v1"). The host serves the exact JSON bytes plus a detached Ed25519 signature
// (header X-RedX-Signature: ed25519:<base64>, or GET .../manifest.sig). RottenCore must:
//   1. verify the signature over the exact bytes under a key it trusts (UpdateKey, checked against
//      not_after),
//   2. parse strictly and validate every field,
//   3. refuse a sequence <= the last one it applied for that app (rollback protection),
//   4. after download, check the artifact's sha256 and size.

// UpdateManifestSchema is the only schema RottenCore accepts.
const UpdateManifestSchema = "redx.update-manifest/v1"

// UpdateKey is one entry of GET /v1/updates/keys.
type UpdateKey struct {
	KID      string `json:"kid"`
	Alg      string `json:"alg"`
	Pub      string `json:"pub"`
	NotAfter string `json:"not_after"`
}

// PinnedUpdateKeyFingerprints are the host manifest-signing keys RottenCore trusts (KeyFingerprint of the
// raw public key). EMPTY until RedX Dev provisions the production host key; keys fetched from
// /v1/updates/keys are only used when their fingerprint is pinned here (or, later, when they carry a
// ra-core certificate; see the plan's open questions).
var PinnedUpdateKeyFingerprints = []string{}

// UpdateManifest is redx.update-manifest/v1.
type UpdateManifest struct {
	Schema      string           `json:"schema"`
	App         string           `json:"app"`
	Version     string           `json:"version"`
	Channel     string           `json:"channel"`
	PublishedAt string           `json:"published_at"`
	Sequence    int64            `json:"sequence"`
	Source      UpdateSource     `json:"source"`
	Outcome     UpdateOutcome    `json:"outcome"`
	Requires    *UpdateRequires  `json:"requires,omitempty"`
	Artifacts   []UpdateArtifact `json:"artifacts"`
	LivePatch   []LivePatch      `json:"live_patch,omitempty"`
	Certificate json.RawMessage  `json:"certificate,omitempty"`
}

// UpdateSource says where the build came from.
type UpdateSource struct {
	Kind   string `json:"kind"` // host | github
	GitHub *struct {
		Repo      string `json:"repo"`
		Tag       string `json:"tag"`
		Commit    string `json:"commit"`
		ReleaseID int64  `json:"release_id"`
	} `json:"github,omitempty"`
	Host *struct {
		BuildID string `json:"build_id"`
		Commit  string `json:"commit"`
	} `json:"host,omitempty"`
}

// UpdateOutcome is what the update does (shown on the outcome card).
type UpdateOutcome struct {
	Tags        []string    `json:"tags"`
	Summary     string      `json:"summary"`
	Risk        *UpdateRisk `json:"risk"`
	ChangelogMD string      `json:"changelog_md"`
}

// UpdateRisk is null until analysed.
type UpdateRisk struct {
	Score   float64  `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

// UpdateRequires lists preconditions.
type UpdateRequires struct {
	MinFrom    string   `json:"min_from"`
	Restart    bool     `json:"restart"`
	Migrations []string `json:"migrations"`
}

// UpdateArtifact is one downloadable build.
type UpdateArtifact struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Kind      string   `json:"kind"`
	Filename  string   `json:"filename"`
	URL       string   `json:"url"`
	Mirrors   []string `json:"mirrors"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256"`
	DeltaFrom *string  `json:"delta_from"`
}

// LivePatch is a phase-2 non-structural change.
type LivePatch struct {
	Target string `json:"target"`
	Path   string `json:"path"`
	Op     string `json:"op"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

var (
	semverRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,40})?$`)
	artIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	outcomeRe  = regexp.MustCompile(`^[+-](security|perf|stability|capability|breaking|compat)$`)
	hex40Re    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	appSlugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,99}$`)
	updateOS   = map[string]bool{"macos": true, "windows": true, "linux": true}
	updateArch = map[string]bool{"arm64": true, "amd64": true, "universal": true, "armv7": true}
	updateKind = map[string]bool{"dmg": true, "pkg": true, "exe": true, "zip": true, "tar.gz": true, "deb": true, "delta": true}
)

// ErrUpdateManifest wraps every manifest refusal; Code matches the contract's error codes.
type ErrUpdateManifest struct {
	Code string // bad_signature | sequence_regression | bad_manifest | bad_artifact
	Msg  string
}

func (e *ErrUpdateManifest) Error() string { return e.Code + ": " + e.Msg }

func umErr(code, f string, a ...interface{}) error {
	return &ErrUpdateManifest{Code: code, Msg: fmt.Sprintf(f, a...)}
}

// TrustedUpdateKeys picks, from a /v1/updates/keys answer, the keys whose fingerprint is pinned and that
// have not passed not_after.
func TrustedUpdateKeys(keys []UpdateKey, pinnedFPs []string, now time.Time) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		if k.Alg != "ed25519" || k.KID == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(k.Pub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		if k.NotAfter != "" {
			na, err := time.Parse(time.RFC3339, k.NotAfter)
			if err != nil || now.After(na) {
				continue
			}
		}
		fp := KeyFingerprint(raw)
		for _, p := range pinnedFPs {
			if p == fp {
				out[k.KID] = ed25519.PublicKey(raw)
			}
		}
	}
	return out
}

// VerifyUpdateManifest checks the detached signature header value ("ed25519:<base64>") over body under the
// trusted keys (kid from X-RedX-Key-Id; "" tries every trusted key), parses and validates the manifest,
// and refuses a sequence <= lastSeq.
func VerifyUpdateManifest(body []byte, sigHeader, kid string, keys map[string]ed25519.PublicKey, lastSeq int64) (*UpdateManifest, error) {
	if len(body) == 0 || len(body) > 1<<20 {
		return nil, umErr("bad_manifest", "manifest is empty or larger than 1 MB")
	}
	b64, ok := strings.CutPrefix(strings.TrimSpace(sigHeader), "ed25519:")
	if !ok {
		return nil, umErr("bad_signature", "signature is not ed25519:<base64>")
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, umErr("bad_signature", "signature is malformed")
	}
	verified := false
	for id, k := range keys {
		if kid != "" && id != kid {
			continue
		}
		if ed25519.Verify(k, body, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, umErr("bad_signature", "manifest signature does not verify under a trusted host key")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var m UpdateManifest
	if err := dec.Decode(&m); err != nil {
		return nil, umErr("bad_manifest", "%v", err)
	}
	if dec.More() {
		return nil, umErr("bad_manifest", "trailing data")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.Sequence <= lastSeq {
		return nil, umErr("sequence_regression", "sequence %d is not newer than %d (rollback attempt or replay)", m.Sequence, lastSeq)
	}
	return &m, nil
}

// Validate checks every field against the contract.
func (m *UpdateManifest) Validate() error {
	bad := func(f string, a ...interface{}) error { return umErr("bad_manifest", f, a...) }
	if m.Schema != UpdateManifestSchema {
		return bad("schema %q is not %s", m.Schema, UpdateManifestSchema)
	}
	if !appSlugRe.MatchString(m.App) {
		return bad("app id %q is invalid", m.App)
	}
	if !semverRe.MatchString(m.Version) {
		return bad("version %q is not semver", m.Version)
	}
	switch m.Channel {
	case "stable", "beta", "security":
	default:
		return bad("channel %q is not stable, beta or security", m.Channel)
	}
	if _, err := time.Parse(time.RFC3339, m.PublishedAt); err != nil {
		return bad("published_at is not RFC 3339")
	}
	if m.Sequence <= 0 {
		return bad("sequence must be positive")
	}
	switch m.Source.Kind {
	case "host":
		if m.Source.Host == nil || m.Source.Host.BuildID == "" {
			return bad("a host manifest needs source.host.build_id")
		}
	case "github":
		g := m.Source.GitHub
		if g == nil || strings.Count(g.Repo, "/") != 1 || g.Tag == "" || !hex40Re.MatchString(g.Commit) {
			return bad("a github manifest needs source.github repo, tag and a 40-hex commit")
		}
	default:
		return bad("source.kind must be host or github")
	}
	for _, t := range m.Outcome.Tags {
		if !outcomeRe.MatchString(t) {
			return bad("outcome tag %q is not in the contract vocabulary", t)
		}
	}
	if r := m.Outcome.Risk; r != nil {
		if r.Score < 0 || r.Score > 1 {
			return bad("risk score must be 0..1")
		}
		switch r.Level {
		case "low", "medium", "high", "critical":
		default:
			return bad("risk level %q is invalid", r.Level)
		}
	}
	if len(m.Artifacts) == 0 {
		return bad("no artifacts")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, a := range m.Artifacts {
		if !artIDRe.MatchString(a.ID) || ids[a.ID] {
			return bad("artifact id %q is invalid or repeated", a.ID)
		}
		if !fileRe.MatchString(a.Filename) || names[a.Filename] {
			return bad("artifact filename %q is invalid or repeated (filenames must be distinct)", a.Filename)
		}
		ids[a.ID], names[a.Filename] = true, true
		if strings.TrimSpace(a.Label) == "" {
			return bad("artifact %s has no label", a.ID)
		}
		if !updateOS[a.OS] || !updateArch[a.Arch] || !updateKind[a.Kind] {
			return bad("artifact %s: os/arch/kind %s/%s/%s not in the contract", a.ID, a.OS, a.Arch, a.Kind)
		}
		if !sha256Re.MatchString(a.SHA256) || a.Size <= 0 {
			return bad("artifact %s needs a sha256 and a size", a.ID)
		}
		for _, u := range append([]string{a.URL}, a.Mirrors...) {
			if !ValidOrigin(originOf(u), false) {
				return bad("artifact %s: %q is not an https URL", a.ID, u)
			}
		}
		if a.Kind == "delta" && (a.DeltaFrom == nil || !semverRe.MatchString(*a.DeltaFrom)) {
			return bad("delta artifact %s needs delta_from", a.ID)
		}
	}
	return nil
}

func originOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return u[:i+3] + rest
}

// PickArtifact chooses the artifact for this machine: exact arch first (Apple silicon = arm64 first), then
// universal; full installers before deltas unless the delta's base is the installed version; preferred
// kind (the one used last time) first.
func (m *UpdateManifest) PickArtifact(goos, arch, installed, preferKind string) (*UpdateArtifact, error) {
	osName := map[string]string{"darwin": "macos", "windows": "windows", "linux": "linux"}[goos]
	type cand struct {
		a     *UpdateArtifact
		score int
	}
	var cs []cand
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if a.OS != osName {
			continue
		}
		s := 0
		switch a.Arch {
		case arch:
			s += 100
		case "universal":
			s += 50
		default:
			continue
		}
		if a.Kind == "delta" {
			if a.DeltaFrom == nil || *a.DeltaFrom != installed {
				continue
			}
			s += 20
		}
		if a.Kind == preferKind {
			s += 10
		}
		cs = append(cs, cand{a, s})
	}
	if len(cs) == 0 {
		return nil, umErr("bad_artifact", "no %s/%s build in %s %s", osName, arch, m.App, m.Version)
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].score > cs[j].score })
	return cs[0].a, nil
}

// CheckArtifact compares a downloaded file with the manifest entry.
func (a *UpdateArtifact) CheckArtifact(sum string, size int64) error {
	if sum != a.SHA256 || size != a.Size {
		return umErr("bad_artifact", "%s does not match the signed manifest (sha256 or size differ); nothing will be installed", a.Filename)
	}
	return nil
}

// Update source preference (contract §2 PUT .../source).
const (
	UpdateFromHost   = "host"
	UpdateFromGitHub = "github"
	UpdateFromBoth   = "both"
)

// UpdateSourceOptions lists what the source picker may offer: Host and Both only for Red-XAI hosted apps.
func UpdateSourceOptions(hosted bool) []string {
	if hosted {
		return []string{UpdateFromHost, UpdateFromGitHub, UpdateFromBoth}
	}
	return []string{UpdateFromGitHub}
}

// ValidUpdateSource checks a stored preference (contract: host/both on a non-hosted app is not_hosted).
func ValidUpdateSource(pref string, hosted bool) error {
	for _, o := range UpdateSourceOptions(hosted) {
		if o == pref {
			return nil
		}
	}
	if pref == UpdateFromHost || pref == UpdateFromBoth {
		return umErr("not_hosted", "this app is not hosted with Red-XAI, so it can only update from GitHub")
	}
	return umErr("bad_manifest", "source must be host, github or both")
}
