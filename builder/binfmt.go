package builder

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Binary formats DetectBinary recognises.
const (
	FormatMachO = "mach-o"
	FormatPE    = "pe"
	FormatELF   = "elf"
)

// BinaryInfo is what an executable's own headers say it is: format, OS and the CPU architectures
// (Go spelling: arm64, amd64, 386; a universal Mach-O lists every slice).
type BinaryInfo struct {
	Format string
	OS     string // darwin | windows | linux
	Archs  []string
}

// ErrPlatformMismatch refuses an artifact whose real platform or chip is not the target's (QA v2 N5): a
// Mach-O labelled Linux, an ELF named app.exe, an arm64 binary labelled Intel. Nothing is labelled or signed.
type ErrPlatformMismatch struct {
	Platform string
	Want     string
	Got      string
}

func (e *ErrPlatformMismatch) Error() string {
	return fmt.Sprintf("the %s artifact is %s, not %s; refusing to label and sign it", e.Platform, e.Got, e.Want)
}

// DetectBinary reads the headers of path. ok is false (and err nil) when the file is not a Mach-O, PE or ELF
// executable, e.g. a .dmg, .zip, .apk or a plain file.
func DetectBinary(path string) (info BinaryInfo, ok bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return info, false, err
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return info, false, nil // shorter than any header
	}
	switch {
	case bytes.Equal(head, []byte{0x7f, 'E', 'L', 'F'}):
		ef, err := elf.NewFile(f)
		if err != nil {
			return info, false, fmt.Errorf("unreadable ELF header: %w", err)
		}
		return BinaryInfo{Format: FormatELF, OS: "linux", Archs: []string{elfArch(ef.Machine)}}, true, nil
	case head[0] == 'M' && head[1] == 'Z':
		pf, err := pe.NewFile(f)
		if err != nil {
			return info, false, nil // an MZ prefix that is not a PE image
		}
		return BinaryInfo{Format: FormatPE, OS: "windows", Archs: []string{peArch(pf.Machine)}}, true, nil
	case isMachOMagic(head):
		mf, err := macho.NewFile(f)
		if err != nil {
			return info, false, fmt.Errorf("unreadable Mach-O header: %w", err)
		}
		return BinaryInfo{Format: FormatMachO, OS: "darwin", Archs: []string{machoArch(mf.Cpu)}}, true, nil
	case bytes.Equal(head, []byte{0xca, 0xfe, 0xba, 0xbe}):
		ff, err := macho.NewFatFile(f)
		if err != nil {
			return info, false, nil // 0xcafebabe is also a Java class file
		}
		bi := BinaryInfo{Format: FormatMachO, OS: "darwin"}
		for _, a := range ff.Arches {
			bi.Archs = append(bi.Archs, machoArch(a.Cpu))
		}
		sort.Strings(bi.Archs)
		return bi, true, nil
	}
	return info, false, nil
}

func isMachOMagic(h []byte) bool {
	for _, m := range [][]byte{{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}} {
		if bytes.Equal(h, m) {
			return true
		}
	}
	return false
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	}
	return strings.ToLower(m.String())
}

func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	}
	return fmt.Sprintf("pe-machine-0x%x", m)
}

func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuAmd64:
		return "amd64"
	case macho.Cpu386:
		return "386"
	}
	return strings.ToLower(c.String())
}

// platformBinary is what a native executable for each desktop target must be. Windows and Linux labels
// carry no chip, so any of their usual architectures is accepted; Mac labels name the chip.
var platformBinary = map[string]struct {
	os    string
	archs []string
}{
	PlatformMacArm64: {"darwin", []string{"arm64"}},
	PlatformMacIntel: {"darwin", []string{"amd64"}},
	PlatformWindows:  {"windows", []string{"amd64", "arm64", "386"}},
	PlatformLinux:    {"linux", []string{"amd64", "arm64", "386"}},
}

// VerifyArtifactPlatform checks an artifact's real platform against the target before it is labelled and
// signed. Any Mach-O, PE or ELF executable must match the target's OS and chip (a universal Mac binary
// must contain the target's slice). Packaged outputs (.dmg, .zip, .apk, ...) are not executables and pass,
// unless requireBinary is set (the default Go build always leaves a native executable).
func VerifyArtifactPlatform(path, platform string, requireBinary bool) error {
	want, desktop := platformBinary[platform]
	info, ok, err := DetectBinary(path)
	if err != nil {
		return fmt.Errorf("%s: %w", platform, err)
	}
	if !desktop {
		return nil // extensions, Android and iOS ship packages, not desktop executables
	}
	wantDesc := want.os + "/" + strings.Join(want.archs, "|")
	if !ok {
		if requireBinary {
			return &ErrPlatformMismatch{Platform: platform, Want: wantDesc + " executable", Got: "not a Mach-O, PE or ELF executable"}
		}
		return nil
	}
	got := info.OS + "/" + strings.Join(info.Archs, "+") + " (" + info.Format + ")"
	if info.OS != want.os {
		return &ErrPlatformMismatch{Platform: platform, Want: wantDesc, Got: got}
	}
	for _, a := range info.Archs {
		for _, w := range want.archs {
			if a == w {
				return nil
			}
		}
	}
	return &ErrPlatformMismatch{Platform: platform, Want: wantDesc, Got: got}
}

// VerifyContainer ensures a packaged file's magic matches the extension we are about to ship (M3).
func VerifyContainer(path, container, platform string) error {
	if container == "" || container == ContainerBinary {
		return nil
	}
	got, ok := DetectContainer(path)
	if !ok {
		// Windows .exe we just copied: DetectContainer sees MZ.
		if container == ContainerExe {
			info, isBin, err := DetectBinary(path)
			if err != nil {
				return err
			}
			if !isBin || info.Format != FormatPE {
				return &ErrPlatformMismatch{Platform: platform, Want: "PE executable (.exe)", Got: "not a PE"}
			}
			return nil
		}
		return &ErrPlatformMismatch{Platform: platform, Want: container + " container", Got: "unrecognised file"}
	}
	if got != container && !(container == ContainerDMG && got == ContainerDMG) {
		// gzip-detected tar.gz is fine
		if container == ContainerTarGz && got == ContainerTarGz {
			return nil
		}
		if got != container {
			return &ErrPlatformMismatch{Platform: platform, Want: container, Got: got}
		}
	}
	return nil
}
