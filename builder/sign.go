package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// Embeddable reports whether a platform's container format can carry the signature inside the file. No
// Rotten Core format does today: a detached .rasig (or GitHub release asset) is always written, because an
// embedded signature cannot cover the bytes of the file that contains it (that needs a tree hash; future
// work). Kept as a seam so `rottencore sign` can embed once a format supports it.
func Embeddable(platform string) bool { return false }

// SignFile signs one already-built artifact: it enforces the signing-device policy (CanSignOn), hashes the
// file, writes a detached <file>.rasig next to it (embedding is not available yet) and regenerates the
// directory's SHA256SUMS. appID and version come from the project; platform may be given or inferred from
// the file name.
func SignFile(path, appID, version, platform string, host string, k core.Signer, chain []core.Cert, now time.Time) (*Artifact, error) {
	if k == nil || len(chain) == 0 {
		return nil, errors.New("signing needs a developer key and certificate chain")
	}
	if platform == "" {
		platform = PlatformFromName(filepath.Base(path))
	}
	if _, ok := platformOrder[platform]; !ok {
		return nil, fmt.Errorf("unknown or undetectable platform for %q; pass --platform", filepath.Base(path))
	}
	if !CanSignOn(platform, host) {
		return nil, &ErrWrongHost{Platform: platform, Host: host}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	var doc core.FileSigDoc
	doc.AppID, doc.Version = appID, version
	doc.Artifact.Name = filepath.Base(path)
	doc.Artifact.Kind, doc.Artifact.SHA256, doc.Artifact.Bytes = Kind(platform), hexSum, int64(len(raw))
	doc.SignedMs = now.UnixMilli()
	sig, err := core.SignFileDocWith(k, chain, doc)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return nil, err
	}
	sigPath := path + ".rasig"
	if err := os.WriteFile(sigPath, append(b, '\n'), 0o644); err != nil {
		return nil, err
	}
	if _, err := RegenerateSums(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &Artifact{Platform: platform, Filename: filepath.Base(path), Path: path, SigPath: sigPath, SHA256: hexSum, Bytes: int64(len(raw))}, nil
}

// PlatformFromName guesses a platform from an asset file name (the names Filename produces, or a plain
// extension). Returns "" when it cannot tell.
func PlatformFromName(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "extension") || strings.HasSuffix(n, ".crx") || strings.HasSuffix(n, ".xpi"):
		return PlatformExtensions
	case strings.HasSuffix(n, ".ipa") || strings.Contains(n, "-ios-") || strings.Contains(n, "_ios_"):
		return PlatformIOS
	case strings.HasSuffix(n, ".apk") || strings.HasSuffix(n, ".aab") || strings.Contains(n, "android"):
		return PlatformAndroid
	case strings.HasSuffix(n, ".exe") || strings.HasSuffix(n, ".msi") || strings.Contains(n, "windows") || strings.Contains(n, "win32") || strings.Contains(n, "win64"):
		return PlatformWindows
	case strings.Contains(n, "macos-arm64") || strings.Contains(n, "mac-arm64") || strings.Contains(n, "darwin-arm64") ||
		strings.Contains(n, "-arm64.dmg") || strings.Contains(n, "-arm64.pkg") || strings.Contains(n, "macos-universal") ||
		(strings.Contains(n, "mac") && strings.Contains(n, "arm64")):
		return PlatformMacArm64
	case strings.Contains(n, "macos-intel") || strings.Contains(n, "mac-intel") || strings.Contains(n, "darwin-amd64") ||
		strings.Contains(n, "darwin-x64") || strings.Contains(n, "macos-amd64") || strings.Contains(n, "-x64.dmg") ||
		strings.Contains(n, "-x64.pkg") || strings.Contains(n, "-amd64.dmg") || strings.Contains(n, "-amd64.pkg") ||
		strings.HasSuffix(n, ".dmg") || strings.HasSuffix(n, ".pkg") ||
		(strings.Contains(n, "mac") && (strings.Contains(n, "amd64") || strings.Contains(n, "x64") || strings.Contains(n, "intel"))) ||
		strings.Contains(n, "-mac-") || strings.Contains(n, "_mac_") || strings.HasPrefix(n, "mac-") ||
		strings.Contains(n, "install-macos"):
		return PlatformMacIntel // Intel/x64; also the fallback for undifferentiated "Mac" assets signed on a Mac
	case strings.Contains(n, "linux") || strings.HasSuffix(n, ".appimage") || strings.HasSuffix(n, ".deb") || strings.HasSuffix(n, ".rpm"):
		return PlatformLinux
	default:
		return ""
	}
}

// RegenerateSums rewrites <dir>/SHA256SUMS from every file in dir (except SHA256SUMS and .rasig files),
// hashing each file's current bytes. Returns the number of files listed.
func RegenerateSums(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	type line struct{ sum, name string }
	var lines []line
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "SHA256SUMS" || strings.HasSuffix(name, ".rasig") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, err
		}
		s := sha256.Sum256(raw)
		lines = append(lines, line{hex.EncodeToString(s[:]), name})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].name < lines[j].name })
	var sb strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&sb, "%s  %s\n", l.sum, l.name)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sb.String()), 0o644); err != nil {
		return 0, err
	}
	return len(lines), nil
}
