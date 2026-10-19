package builder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// BuildManifestSchema versions the signed build manifest.
const BuildManifestSchema = "rottencore.build-manifest/v1"

// buildManifestDomain separates a build manifest signature from any other signature.
const buildManifestDomain = "ROTTENCORE-BUILDMANIFEST-v1\x00"

// BuildManifest is signed once per build set. It records the account context, the registered device
// platform, and the SDKs the build declared (validated against the store's selection), plus each artifact's
// name/sha256. The signature lets the store verify the build ran under an approved device and only selected,
// unlocked SDKs. Owners and admins may build with any SDK (devhub.BuildContext.Exempt), which is recorded.
type BuildManifest struct {
	Schema         string             `json:"schema"`
	Project        Project            `json:"project"`
	Account        string             `json:"account"` // "team T-x" | "individual account"
	TeamID         string             `json:"teamId,omitempty"`
	CertTeamID     string             `json:"certTeamId,omitempty"` // the team's certificate teamId (rxa_ individual | rxt_ team)
	Individual     bool               `json:"individual,omitempty"`
	DevicePlatform string             `json:"devicePlatform"` // mac | windows
	SDKs           []string           `json:"sdks"`
	SDKExempt      bool               `json:"sdkExempt"`
	Artifacts      []ManifestArtifact `json:"artifacts"`
	SignedMs       int64              `json:"signedMs"`
}

// ManifestArtifact is one output in the manifest.
type ManifestArtifact struct {
	Platform string `json:"platform"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
}

// SignedBuildManifest is the manifest plus a detached signature and the signer's chain.
type SignedBuildManifest struct {
	Doc   string      `json:"doc"` // base64 of the canonical BuildManifest JSON
	Alg   string      `json:"alg"`
	Sig   string      `json:"sig"`
	Chain []core.Cert `json:"chain"`
}

// writeBuildManifest builds, signs and writes <OutDir>/build-manifest.json. ctx may be nil (no dev-hub
// context) in which case SDKs are empty and the account is "local".
func (b *Builder) writeBuildManifest(p Project, ctx *devhub.BuildContext, sdks []string, arts []Artifact) (string, error) {
	m := BuildManifest{Schema: BuildManifestSchema, Project: p, Account: "local", SignedMs: b.now().UnixMilli()}
	if ctx != nil {
		m.Account, m.TeamID, m.Individual = ctx.AccountLabel(), ctx.TeamID, ctx.Individual
		m.CertTeamID = ctx.CertTeamID
		m.SDKExempt = ctx.Exempt()
		if ctx.Device != nil {
			m.DevicePlatform = string(ctx.Device.Platform)
		}
	}
	if m.DevicePlatform == "" {
		if dp, err := devhub.DevicePlatform(); err == nil {
			m.DevicePlatform = string(dp)
		}
	}
	m.SDKs = append([]string(nil), sdks...)
	sort.Strings(m.SDKs)
	ma := make([]ManifestArtifact, 0, len(arts))
	for _, a := range arts {
		ma = append(ma, ManifestArtifact{Platform: a.Platform, Filename: a.Filename, SHA256: a.SHA256})
	}
	sort.Slice(ma, func(i, j int) bool { return ma[i].Filename < ma[j].Filename })
	m.Artifacts = ma

	doc, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	msg := append([]byte(buildManifestDomain), doc...)
	sig, err := b.Signer.Sign(msg)
	if err != nil {
		return "", err
	}
	signed := SignedBuildManifest{Doc: base64.StdEncoding.EncodeToString(doc), Alg: b.Signer.Alg(),
		Sig: base64.StdEncoding.EncodeToString(sig), Chain: b.Chain}
	out, _ := json.MarshalIndent(signed, "", "  ")
	path := filepath.Join(b.OutDir, "build-manifest.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// VerifyBuildManifest checks a signed build manifest against a chain policy and returns the manifest.
func VerifyBuildManifest(b []byte, pol core.ChainPolicy) (*BuildManifest, error) {
	var sm SignedBuildManifest
	if err := json.Unmarshal(b, &sm); err != nil {
		return nil, err
	}
	doc, err := base64.StdEncoding.DecodeString(sm.Doc)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(sm.Sig)
	if err != nil {
		return nil, err
	}
	leaf, err := core.VerifyCertChain(sm.Chain, pol)
	if err != nil {
		return nil, err
	}
	alg := sm.Alg
	if alg == "" {
		alg = core.AlgEd25519
	}
	leafAlg := leaf.Alg
	if leafAlg == "" {
		leafAlg = core.AlgEd25519
	}
	if leafAlg != alg {
		return nil, fmt.Errorf("manifest alg %q does not match the leaf key", sm.Alg)
	}
	if !core.VerifySig(alg, leaf.PublicKey, append([]byte(buildManifestDomain), doc...), sig) {
		return nil, fmt.Errorf("build manifest signature is not valid")
	}
	var m BuildManifest
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
