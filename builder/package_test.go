package builder_test

import (
	"debug/elf"
	"debug/macho"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/builder"
)

func TestPackageNativeLinuxIsTarGzNotAppImage(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "app")
	writeFakeELF(t, bin, elf.EM_X86_64)
	out := t.TempDir()
	pr, err := builder.PackageNative(bin, builder.PlatformLinux, out, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Ext != ".tar.gz" || pr.Container != builder.ContainerTarGz {
		t.Fatalf("got %+v", pr)
	}
	name := builder.FilenamePacked(builder.Project{Name: "Hello", Version: "1.0.0"}, builder.PlatformLinux, pr.Ext)
	if !strings.HasSuffix(name, ".tar.gz") || strings.Contains(name, "AppImage") {
		t.Fatalf("name %q", name)
	}
	if err := builder.VerifyContainer(pr.Path, pr.Container, builder.PlatformLinux); err != nil {
		t.Fatal(err)
	}
}

func TestPackageNativeMacFallsBackToZipWithoutHdiutil(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("on darwin hdiutil may succeed; covered separately")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "app")
	writeFakeMachO(t, bin, macho.CpuArm64)
	out := t.TempDir()
	pr, err := builder.PackageNative(bin, builder.PlatformMacArm64, out, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Ext != ".zip" || pr.Container != builder.ContainerZip {
		t.Fatalf("want zip fallback, got %+v", pr)
	}
	if err := builder.VerifyContainer(pr.Path, pr.Container, builder.PlatformMacArm64); err != nil {
		t.Fatal(err)
	}
	// A raw Mach-O must not be accepted as a .dmg container.
	if err := builder.VerifyContainer(bin, builder.ContainerDMG, builder.PlatformMacArm64); err == nil {
		t.Fatal("raw Mach-O accepted as dmg")
	}
}

func TestFilenamePackedUsesExt(t *testing.T) {
	n := builder.FilenamePacked(builder.Project{Name: "QuickLaunch", Version: "1.0.0", Channel: "beta"}, builder.PlatformLinux, ".tar.gz")
	if n != "quicklaunch-1.0.0-beta-linux.tar.gz" {
		t.Fatal(n)
	}
}
