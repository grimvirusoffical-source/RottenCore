package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
	"github.com/grimvirusoffical-source/RottenCore/seal"
)

// Artifact is one built, labelled, named and signed output.
type Artifact struct {
	Platform string `json:"platform"`
	Label    string `json:"label"`    // "QuickLaunch Beta 1.0.0 (Mac, M1 chip)"
	Filename string `json:"filename"` // "quicklaunch-1.0.0-beta-macos-arm64.dmg"
	Path     string `json:"path"`     // where it landed in OutDir
	SigPath  string `json:"sigPath"`  // the .rasig sidecar
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	IconPath string `json:"iconPath,omitempty"` // app icon embedded for this platform (assets/icons/<product>)
}

// Result is a finished build set.
type Result struct {
	Request      string     `json:"request"`
	Project      Project    `json:"project"`
	OutDir       string     `json:"outDir"`
	Artifacts    []Artifact `json:"artifacts"`
	SumsPath     string     `json:"sumsPath"`               // SHA256SUMS
	ManifestPath string     `json:"manifestPath,omitempty"` // signed build-manifest.json (with a dev-hub context)
	SDKs         []string   `json:"sdks,omitempty"`
}

// Builder runs a request. Signer and Chain are the developer's ra-core identity (from the CA / cert bundle).
type Builder struct {
	Signer    core.Signer
	Chain     []core.Cert
	OutDir    string               // where artifacts, .rasig files and SHA256SUMS are written
	IconsRoot string               // root of the app-icon sets (assets/icons); "" disables icon embedding
	Host      string               // build-and-sign device GOOS; "" means HostOS(); targets this host may not sign are refused
	Context   *devhub.BuildContext // dev-hub build context (device platform, team/individual, build key, SDKs); nil = local build
	Emit      func(core.ProgressEvent)
	Now       func() time.Time
}

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Run builds every target in order, signs it and writes SHA256SUMS. It drives the shared loading screen
// with real progress only: one weighted step per target plus a final "signing" step.
func (b *Builder) Run(ctx context.Context, r *Request, targets []Target) (*Result, error) {
	if b.Signer == nil || len(b.Chain) == 0 {
		return nil, fmt.Errorf("builder needs a developer signing key and certificate chain")
	}
	host := b.Host
	if host == "" {
		host = HostOS()
	}
	for _, t := range targets {
		if !CanSignOn(t.Platform, host) {
			return nil, &ErrWrongHost{Platform: t.Platform, Host: host}
		}
	}
	var sdks []string
	if b.Context != nil {
		if err := b.Context.RequireBuildKey(); err != nil {
			return nil, err
		}
		for _, t := range targets {
			if b.Context.Device != nil && !b.Context.Device.Platform.Allows(t.Platform) {
				return nil, fmt.Errorf("your registered %s device may not build %s assets", b.Context.Device.Platform, t.Platform)
			}
		}
		var err error
		if sdks, err = b.Context.ValidateSDKs(r.SDKs); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(b.OutDir, 0o755); err != nil {
		return nil, err
	}
	steps := make([]core.ProgressStep, 0, len(targets)+1)
	for _, t := range targets {
		steps = append(steps, core.ProgressStep{Action: "building", Item: platformWords(t.Platform), Weight: 10})
	}
	steps = append(steps, core.ProgressStep{Action: "signing", Item: "SHA256SUMS", Weight: 2})
	pr := core.NewProgress("build", steps, b.Emit)

	res := &Result{Request: r.ID, Project: r.Project, OutDir: b.OutDir}
	for _, t := range targets {
		art, err := b.one(ctx, r.Project, t)
		if err != nil {
			pr.Fail(err)
			return nil, fmt.Errorf("%s: %w", t.Platform, err)
		}
		res.Artifacts = append(res.Artifacts, *art)
		pr.StepDone()
	}
	sums, err := b.writeSums(res.Artifacts)
	if err != nil {
		pr.Fail(err)
		return nil, err
	}
	res.SumsPath = sums
	res.SDKs = sdks
	if b.Context != nil {
		mp, err := b.writeBuildManifest(r.Project, b.Context, sdks, res.Artifacts)
		if err != nil {
			pr.Fail(err)
			return nil, err
		}
		res.ManifestPath = mp
	}
	pr.StepDone()
	return res, nil
}

func (b *Builder) one(ctx context.Context, p Project, t Target) (*Artifact, error) {
	src := t.Prebuilt
	requireBin := false
	if src == "" {
		out := t.Artifact
		if !filepath.IsAbs(out) {
			out = filepath.Join(p.Dir, out)
		}
		if err := b.build(ctx, p.Dir, t.Command, t.Env); err != nil {
			return nil, err
		}
		src = out
		requireBin = isGoBuildCommand(t.Command)
	}
	if err := VerifyArtifactPlatform(src, t.Platform, requireBin); err != nil {
		return nil, err
	}
	// M3: package a raw Go binary so the download name matches the bytes (.dmg/.zip/.tar.gz/.exe),
	// never a Mach-O named .dmg or an ELF named .AppImage.
	packSrc := src
	name := Filename(p, t.Platform)
	kind := Kind(t.Platform)
	if requireBin {
		base := slug(p.Name) + "-" + p.Version + "-" + t.Platform
		pr, err := PackageNative(src, t.Platform, b.OutDir, base)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", t.Platform, err)
		}
		packSrc = pr.Path
		name = FilenamePacked(p, t.Platform, pr.Ext)
		kind = strings.TrimPrefix(pr.Ext, ".")
		if err := VerifyContainer(packSrc, pr.Container, t.Platform); err != nil {
			return nil, err
		}
	}
	dst := filepath.Join(b.OutDir, name)
	// ENCRYPTION-HOOK: builder.package -- packaging the built artifact for distribution. The bytes are
	// copied through the seal Sealer so an encrypter can be plugged in here later; the default Sealer is a
	// no-op and the file is copied verbatim. DON'T ENCRYPT ANYTHING by default.
	var sum string
	var n int64
	var err error
	if filepath.Clean(packSrc) == filepath.Clean(dst) {
		sum, n, err = sealHash(packSrc, seal.BuildArtifact)
	} else {
		sum, n, err = sealCopy(packSrc, dst, seal.BuildArtifact)
	}
	if err != nil {
		return nil, err
	}
	var doc core.FileSigDoc
	doc.AppID, doc.Version = p.ID, labelVersion(p)
	doc.Artifact.Name, doc.Artifact.Kind, doc.Artifact.SHA256, doc.Artifact.Bytes = name, kind, sum, n
	doc.SignedMs = b.now().UnixMilli()
	sig, err := core.SignFileDocWith(b.Signer, b.Chain, doc)
	if err != nil {
		return nil, err
	}
	sigBytes, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return nil, err
	}
	sigPath := dst + ".rasig"
	if err := os.WriteFile(sigPath, append(sigBytes, '\n'), 0o644); err != nil {
		return nil, err
	}
	art := &Artifact{
		Platform: t.Platform, Label: Label(p, t.Platform), Filename: name,
		Path: dst, SigPath: sigPath, SHA256: sum, Bytes: n,
	}
	if b.IconsRoot != "" {
		icon, err := IconForPlatform(b.IconsRoot, IconProductFor(p), t.Platform)
		if err != nil {
			return nil, err
		}
		art.IconPath = icon
	}
	return art, nil
}

func (b *Builder) build(ctx context.Context, dir string, command, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	// N4: never let the build API key (or a general store key) leak into npm scripts / install hooks.
	// M2: GOOS/GOARCH/CGO_ENABLED come from extraEnv (Target.Env), not an `env` argv wrapper.
	cmd.Env = append(scrubBuildEnv(os.Environ()), extraEnv...)
	return cmd.Run()
}

// isGoBuildCommand reports whether the command is a go build (argv starts at "go" "build").
func isGoBuildCommand(command []string) bool {
	for i, a := range command {
		if a == "go" && i+1 < len(command) && command[i+1] == "build" {
			return true
		}
	}
	return false
}

// scrubBuildEnv drops Rotten Apple / Rotten Core API keys so they never reach child build processes.
func scrubBuildEnv(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		switch {
		case strings.HasPrefix(e, "RA_API_KEY="),
			strings.HasPrefix(e, "ROTTENCORE_BUILD_API_KEY="),
			strings.HasPrefix(e, "RA_HOST_KEY="):
			continue
		}
		out = append(out, e)
	}
	return out
}

func (b *Builder) writeSums(in []Artifact) (string, error) {
	arts := append([]Artifact(nil), in...)
	sort.Slice(arts, func(i, j int) bool { return arts[i].Filename < arts[j].Filename })
	f, err := os.Create(filepath.Join(b.OutDir, "SHA256SUMS"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, a := range arts {
		if _, err := fmt.Fprintf(f, "%s  %s\n", a.SHA256, a.Filename); err != nil {
			return "", err
		}
	}
	return f.Name(), nil
}

func labelVersion(p Project) string {
	if ch := channelWord(p.Channel); ch != "" {
		return p.Version + "-" + slug(ch)
	}
	return p.Version
}

// sealCopy copies src to dst through the active Sealer (no-op by default) and returns the hex SHA-256 and
// size of the bytes written.
func sealCopy(src, dst string, purpose seal.Purpose) (string, int64, error) {
	in, err := os.ReadFile(src)
	if err != nil {
		return "", 0, err
	}
	sealed, err := seal.Current().Seal(purpose, in, []byte("artifact:"+filepath.Base(dst)))
	if err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(dst, sealed, 0o644); err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(sealed)
	return hex.EncodeToString(h[:]), int64(len(sealed)), nil
}

func sealHash(path string, purpose seal.Purpose) (string, int64, error) {
	in, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sealed, err := seal.Current().Seal(purpose, in, []byte("artifact:"+filepath.Base(path)))
	if err != nil {
		return "", 0, err
	}
	if !bytes.Equal(sealed, in) {
		if err := os.WriteFile(path, sealed, 0o644); err != nil {
			return "", 0, err
		}
	}
	h := sha256.Sum256(sealed)
	return hex.EncodeToString(h[:]), int64(len(sealed)), nil
}

var _ = io.Copy

// ScrubBuildEnvForTest exposes scrubBuildEnv for tests.
func ScrubBuildEnvForTest(in []string) []string { return scrubBuildEnv(in) }
