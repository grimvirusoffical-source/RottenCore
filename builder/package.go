package builder

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Container formats PackageNative may produce for a raw Go binary so the download name matches the bytes
// (QA v2 M3): a Mach-O must not ship as .dmg, an ELF must not ship as .AppImage.
const (
	ContainerDMG    = "dmg"
	ContainerZip    = "zip"
	ContainerTarGz  = "tar.gz"
	ContainerExe    = "exe"
	ContainerBinary = "bin" // raw executable kept as-is (rare)
)

// PackageResult is the file ready to label and sign.
type PackageResult struct {
	Path      string // absolute path of the packaged (or verified-raw) file
	Ext       string // including the leading dot, e.g. ".dmg", ".tar.gz", ".exe"
	Container string // ContainerDMG | ContainerZip | …
	Packaged  bool   // true when we wrapped a raw binary
}

// PackageNative takes a raw Go binary (or an already-packaged file) and ensures the download name's
// extension matches the content. On a Mac host with hdiutil, macOS targets become a real UDIF .dmg;
// otherwise macOS and Linux get .zip / .tar.gz. Windows stays .exe (PE). Already-packaged inputs
// (.dmg/.zip/.tar.gz/.AppImage/.exe that DetectContainer recognises) are returned as-is.
func PackageNative(src, platform, outDir, baseName string) (*PackageResult, error) {
	if baseName == "" {
		baseName = "app"
	}
	kind, ok := DetectContainer(src)
	if ok {
		ext := "." + kind
		if kind == ContainerTarGz {
			ext = ".tar.gz"
		}
		return &PackageResult{Path: src, Ext: ext, Container: kind, Packaged: false}, nil
	}
	// Raw executable: package per platform.
	switch platform {
	case PlatformMacArm64, PlatformMacIntel:
		if runtime.GOOS == "darwin" {
			if p, err := makeDMG(src, outDir, baseName); err == nil {
				return &PackageResult{Path: p, Ext: ".dmg", Container: ContainerDMG, Packaged: true}, nil
			}
		}
		p, err := makeZip(src, outDir, baseName)
		if err != nil {
			return nil, err
		}
		return &PackageResult{Path: p, Ext: ".zip", Container: ContainerZip, Packaged: true}, nil
	case PlatformLinux:
		p, err := makeTarGz(src, outDir, baseName)
		if err != nil {
			return nil, err
		}
		return &PackageResult{Path: p, Ext: ".tar.gz", Container: ContainerTarGz, Packaged: true}, nil
	case PlatformWindows:
		// PE .exe is already the right name; copy into outDir if needed.
		dst := filepath.Join(outDir, baseName+".exe")
		if filepath.Clean(src) == filepath.Clean(dst) {
			return &PackageResult{Path: src, Ext: ".exe", Container: ContainerExe, Packaged: false}, nil
		}
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		return &PackageResult{Path: dst, Ext: ".exe", Container: ContainerExe, Packaged: true}, nil
	default:
		return &PackageResult{Path: src, Ext: filepath.Ext(src), Container: ContainerBinary, Packaged: false}, nil
	}
}

// FilenamePacked is Filename with an explicit extension (including the leading dot). Used after
// PackageNative so a Go linux build ships as .tar.gz, not .AppImage.
func FilenamePacked(p Project, platform, ext string) string {
	parts := []string{slug(p.Name), p.Version}
	if ch := strings.ToLower(strings.TrimSpace(p.Channel)); ch != "" && ch != "stable" && ch != "release" {
		parts = append(parts, slug(ch))
	}
	parts = append(parts, platform)
	if ext == "" {
		ext = extFor(platform)
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.Join(parts, "-") + ext
}

// DetectContainer reports a known package/container format for path (dmg, zip, tar.gz, exe AppImage-ish).
func DetectContainer(path string) (kind string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	if n < 2 {
		return "", false
	}
	switch {
	case n >= 4 && head[0] == 'P' && head[1] == 'K':
		return ContainerZip, true
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		return ContainerTarGz, true // gzip; callers treat as .tar.gz for our packaging
	case n >= 4 && (bytes.Equal(head[:4], []byte("koly")) || isUDIF(head)):
		return ContainerDMG, true
	case head[0] == 'M' && head[1] == 'Z':
		return ContainerExe, true
	}
	// UDIF often starts with 'e' 'r' 0x02 0x00 (backup trailer is koly); also accept .dmg by name only
	// when the file is large and not a Mach-O/ELF — handled by caller via requireBinary path.
	if strings.HasSuffix(strings.ToLower(path), ".dmg") && !isMachOOrELF(head) {
		return ContainerDMG, true
	}
	if strings.HasSuffix(strings.ToLower(path), ".appimage") {
		return "AppImage", true
	}
	return "", false
}

func isUDIF(head []byte) bool {
	// UDIF data fork header may be 'e','r',0x02,0x00.
	return len(head) >= 4 && head[0] == 'e' && head[1] == 'r' && head[2] == 0x02
}

func isMachOOrELF(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	if head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		return true
	}
	for _, m := range [][]byte{{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}} {
		if bytes.Equal(head[:4], m) {
			return true
		}
	}
	return false
}

func makeDMG(src, outDir, baseName string) (string, error) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		return "", err
	}
	stage := filepath.Join(outDir, ".dmg-stage-"+baseName)
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	if err := copyFile(src, filepath.Join(stage, filepath.Base(src))); err != nil {
		return "", err
	}
	dst := filepath.Join(outDir, baseName+".dmg")
	_ = os.Remove(dst)
	cmd := exec.Command("hdiutil", "create", "-volname", baseName, "-srcfolder", stage, "-ov", "-format", "UDZO", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("hdiutil: %w (%s)", err, bytes.TrimSpace(out))
	}
	return dst, nil
}

func makeZip(src, outDir, baseName string) (string, error) {
	dst := filepath.Join(outDir, baseName+".zip")
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create(filepath.Base(src))
	if err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if _, err := io.Copy(w, in); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return dst, nil
}

func makeTarGz(src, outDir, baseName string) (string, error) {
	dst := filepath.Join(outDir, baseName+".tar.gz")
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return "", err
	}
	hdr, err := tar.FileInfoHeader(st, "")
	if err != nil {
		return "", err
	}
	hdr.Name = filepath.Base(src)
	if err := tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	if _, err := io.Copy(tw, in); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o755)
}
