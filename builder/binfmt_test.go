package builder_test

import (
	"context"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/builder"
)

// writeFakeELF writes a tiny but parseable ELF64 for the given machine.
func writeFakeELF(t *testing.T, path string, machine elf.Machine) {
	t.Helper()
	// Minimal ELF64 header + program header that debug/elf.NewFile accepts.
	b := make([]byte, 64+56)
	copy(b[0:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2 // 64-bit
	b[5] = 1 // little-endian
	b[6] = 1
	b[16] = 2 // ET_EXEC
	binary.LittleEndian.PutUint16(b[18:], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:], 1)  // version
	binary.LittleEndian.PutUint64(b[32:], 64) // phoff
	binary.LittleEndian.PutUint16(b[52:], 64) // ehsize
	binary.LittleEndian.PutUint16(b[54:], 56) // phentsize
	binary.LittleEndian.PutUint16(b[56:], 1)  // phnum
	// One PT_LOAD program header so NewFile succeeds.
	binary.LittleEndian.PutUint32(b[64:], 1) // PT_LOAD
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFakeMachO(t *testing.T, path string, cpu macho.Cpu) {
	t.Helper()
	// 64-bit little-endian Mach-O header (MH_MAGIC_64 = 0xfeedfacf).
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(b[8:], 0)  // cputype subtype
	binary.LittleEndian.PutUint32(b[12:], 2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(b[16:], 0) // ncmds
	binary.LittleEndian.PutUint32(b[20:], 0) // sizeofcmds
	binary.LittleEndian.PutUint32(b[24:], 0) // flags
	binary.LittleEndian.PutUint32(b[28:], 0) // reserved
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func buildTinyGo(t *testing.T, out, goos, goarch string) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module tiny\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s/%s: %v\n%s", goos, goarch, err, outb)
	}
}

func TestDetectBinaryFormats(t *testing.T) {
	dir := t.TempDir()
	elfP := filepath.Join(dir, "linux")
	writeFakeELF(t, elfP, elf.EM_X86_64)
	info, ok, err := builder.DetectBinary(elfP)
	if err != nil || !ok || info.OS != "linux" || info.Format != builder.FormatELF || len(info.Archs) != 1 || info.Archs[0] != "amd64" {
		t.Fatalf("ELF: ok=%v err=%v info=%+v", ok, err, info)
	}

	peP := filepath.Join(dir, "win.exe")
	buildTinyGo(t, peP, "windows", "amd64")
	info, ok, err = builder.DetectBinary(peP)
	if err != nil || !ok || info.OS != "windows" || info.Format != builder.FormatPE || info.Archs[0] != "amd64" {
		t.Fatalf("PE: ok=%v err=%v info=%+v", ok, err, info)
	}

	macP := filepath.Join(dir, "mac")
	writeFakeMachO(t, macP, macho.CpuArm64)
	info, ok, err = builder.DetectBinary(macP)
	if err != nil || !ok || info.OS != "darwin" || info.Format != builder.FormatMachO || info.Archs[0] != "arm64" {
		t.Fatalf("Mach-O: ok=%v err=%v info=%+v", ok, err, info)
	}

	plain := filepath.Join(dir, "plain.txt")
	os.WriteFile(plain, []byte("not a binary"), 0o644)
	_, ok, err = builder.DetectBinary(plain)
	if err != nil || ok {
		t.Fatalf("plain file should not be detected as a binary: ok=%v err=%v", ok, err)
	}
}

func TestVerifyArtifactPlatformMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	// An ELF labelled as Windows must be refused.
	elfP := filepath.Join(dir, "app.exe")
	writeFakeELF(t, elfP, elf.EM_X86_64)
	err := builder.VerifyArtifactPlatform(elfP, builder.PlatformWindows, true)
	if _, ok := err.(*builder.ErrPlatformMismatch); !ok {
		t.Fatalf("want ErrPlatformMismatch for ELF-as-Windows, got %v", err)
	}
	// A Mach-O labelled as Linux must be refused.
	macP := filepath.Join(dir, "linux-app")
	writeFakeMachO(t, macP, macho.CpuArm64)
	err = builder.VerifyArtifactPlatform(macP, builder.PlatformLinux, true)
	if _, ok := err.(*builder.ErrPlatformMismatch); !ok {
		t.Fatalf("want ErrPlatformMismatch for Mach-O-as-Linux, got %v", err)
	}
	// An arm64 Mach-O labelled macos-intel must be refused.
	err = builder.VerifyArtifactPlatform(macP, builder.PlatformMacIntel, true)
	if _, ok := err.(*builder.ErrPlatformMismatch); !ok {
		t.Fatalf("want ErrPlatformMismatch for arm64-as-Intel, got %v", err)
	}
	// Matching: arm64 Mach-O as macos-arm64.
	if err := builder.VerifyArtifactPlatform(macP, builder.PlatformMacArm64, true); err != nil {
		t.Fatalf("matching Mach-O: %v", err)
	}
	// A .dmg (not an executable) is fine when requireBinary is false.
	dmg := filepath.Join(dir, "app.dmg")
	os.WriteFile(dmg, []byte("koly"), 0o644)
	if err := builder.VerifyArtifactPlatform(dmg, builder.PlatformMacArm64, false); err != nil {
		t.Fatalf("dmg with requireBinary=false: %v", err)
	}
	if err := builder.VerifyArtifactPlatform(dmg, builder.PlatformMacArm64, true); err == nil {
		t.Fatal("dmg with requireBinary=true must be refused")
	}
}

// N5 end-to-end: a Go default build that somehow produced the wrong format is refused before signing.
func TestBuilderRefusesMismatchedGoOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink / env quirks")
	}
	k, chain, _, now := devKey(t)
	dir := t.TempDir()
	// Project with a go.mod so FillDefaults picks the Go command, but the "command" we seed writes an ELF
	// and claims the macos-arm64 target — VerifyArtifactPlatform must refuse before signing.
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n"), 0o644)
	out := filepath.Join(dir, "dist", builder.PlatformMacArm64)
	os.MkdirAll(out, 0o755)
	fake := filepath.Join(out, "app")
	writeFakeELF(t, fake, elf.EM_X86_64)
	req := &builder.Request{
		Schema: builder.RequestSchema, ID: "mismatch-01",
		Project: builder.Project{Name: "X", ID: "com.x", Version: "1.0.0", Dir: dir},
		Targets: []builder.Target{{
			Platform: builder.PlatformMacArm64,
			// Prebuilt of the wrong format: same path the Go default would leave.
			Prebuilt: fake,
		}},
	}
	tg, err := req.Validate()
	if err != nil {
		t.Fatal(err)
	}
	b := &builder.Builder{Signer: k, Chain: chain, OutDir: t.TempDir(), Host: "darwin", Now: func() time.Time { return now }}
	_, err = b.Run(context.Background(), req, tg)
	// Prebuilt path: requireBinary is false, so a mismatch of format for a "prebuilt" that is still a
	// detectable binary of the wrong OS *is* refused (Verify always checks when DetectBinary succeeds).
	if _, ok := err.(*builder.ErrPlatformMismatch); !ok {
		// Err is wrapped as "macos-arm64: …"
		if err == nil || !containsMismatch(err) {
			t.Fatalf("want platform mismatch, got %v", err)
		}
	}
}

func containsMismatch(err error) bool {
	for err != nil {
		if _, ok := err.(*builder.ErrPlatformMismatch); ok {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
