package builder

import (
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
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
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
}

// Result is a finished build set.
type Result struct {
	Request   string     `json:"request"`
	Project   Project    `json:"project"`
	OutDir    string     `json:"outDir"`
	Artifacts []Artifact `json:"artifacts"`
	SumsPath  string     `json:"sumsPath"` // SHA256SUMS
}

// Builder runs a request. Signer and Chain are the developer's ra-core identity (from the CA / cert bundle).
type Builder struct {
	Signer core.Signer
	Chain  []core.Cert
	OutDir string // where artifacts, .rasig files and SHA256SUMS are written
	Host   string // build-and-sign device GOOS; "" means HostOS(); targets this host may not sign are refused
	Emit   func(core.ProgressEvent)
	Now    func() time.Time
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
	pr.StepDone()
	return res, nil
}

func (b *Builder) one(ctx context.Context, p Project, t Target) (*Artifact, error) {
	src := t.Prebuilt
	if src == "" {
		out := t.Artifact
		if !filepath.IsAbs(out) {
			out = filepath.Join(p.Dir, out)
		}
		if err := b.build(ctx, p.Dir, t.Command); err != nil {
			return nil, err
		}
		src = out
	}
	name := Filename(p, t.Platform)
	dst := filepath.Join(b.OutDir, name)
	// ENCRYPTION-HOOK: builder.package -- packaging the built artifact for distribution. The bytes are
	// copied through the seal Sealer so an encrypter can be plugged in here later; the default Sealer is a
	// no-op and the file is copied verbatim. DON'T ENCRYPT ANYTHING by default.
	sum, n, err := sealCopy(src, dst, seal.BuildArtifact)
	if err != nil {
		return nil, err
	}
	var doc core.FileSigDoc
	doc.AppID, doc.Version = p.ID, labelVersion(p)
	doc.Artifact.Name, doc.Artifact.Kind, doc.Artifact.SHA256, doc.Artifact.Bytes = name, Kind(t.Platform), sum, n
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
	return &Artifact{
		Platform: t.Platform, Label: Label(p, t.Platform), Filename: name,
		Path: dst, SigPath: sigPath, SHA256: sum, Bytes: n,
	}, nil
}

func (b *Builder) build(ctx context.Context, dir string, command []string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
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

var _ = io.Copy
