package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Codesign is what codesign and Gatekeeper said about an installed bundle or package.
type Codesign struct {
	Signed     bool   `json:"signed"`
	Valid      bool   `json:"valid"`
	Gatekeeper string `json:"gatekeeper"` // accepted | rejected | skipped
	Detail     string `json:"detail,omitempty"`
}

// Engine does the file work. Applications is the default destination (/Applications).
type Engine struct {
	R            Runner
	Applications string
	UserApps     string // ~/Applications
	Home         string
}

// ErrBadSignature: the bundle is code-signed but the signature does not hold (changed after signing).
var ErrBadSignature = errors.New("the app is code-signed but its signature is broken; it was not installed")

// CheckCodesign inspects a bundle. Unsigned is not an error (unsigned Red-XAI builds are allowed); a broken
// signature is.
func (e *Engine) CheckCodesign(ctx context.Context, path string) *Codesign {
	c := &Codesign{Gatekeeper: "skipped"}
	out, err := e.R.Run(ctx, "/usr/bin/codesign", "-dv", path)
	if err != nil && strings.Contains(string(out), "not signed at all") {
		c.Detail = "not code-signed"
		return c
	}
	c.Signed = true
	if out, err := e.R.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", path); err != nil {
		c.Detail = strings.TrimSpace(lastLine(string(out)))
		return c
	}
	c.Valid = true
	if _, err := e.R.Run(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", path); err != nil {
		c.Gatekeeper = "rejected"
		c.Detail = "signed, but not notarized for Gatekeeper"
	} else {
		c.Gatekeeper = "accepted"
	}
	return c
}

func (e *Engine) dest(d string) string {
	if d == "~/Applications" && e.UserApps != "" {
		return e.UserApps
	}
	if e.Applications != "" {
		return e.Applications
	}
	return "/Applications"
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".rottencore-w-")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// InstallApp copies an .app into the destination. An existing copy is kept aside and put back on any
// failure. Returns the installed path and the codesign result.
func (e *Engine) InstallApp(ctx context.Context, src, destination string) (string, *Codesign, error) {
	if !strings.HasSuffix(src, ".app") {
		return "", nil, fmt.Errorf("%s is not an .app bundle", src)
	}
	if st, err := os.Stat(filepath.Join(src, "Contents")); err != nil || !st.IsDir() {
		return "", nil, fmt.Errorf("%s is not an app bundle (no Contents folder)", filepath.Base(src))
	}
	dir := e.dest(destination)
	if err := os.MkdirAll(dir, 0o755); err != nil && !os.IsExist(err) {
		return "", nil, err
	}
	target := filepath.Join(dir, filepath.Base(src))
	run := e.R.Run
	if !writable(dir) {
		run = e.R.RunAdmin
	}
	old := ""
	if _, err := os.Lstat(target); err == nil {
		old = target + ".rottencore-old"
		_, _ = run(ctx, "/bin/rm", "-rf", old)
		if _, err := run(ctx, "/bin/mv", target, old); err != nil {
			return "", nil, fmt.Errorf("could not move the old copy aside: %w", err)
		}
	}
	restore := func() {
		_, _ = run(ctx, "/bin/rm", "-rf", target)
		if old != "" {
			_, _ = run(ctx, "/bin/mv", old, target)
		}
	}
	if _, err := run(ctx, "/usr/bin/ditto", src, target); err != nil {
		restore()
		return "", nil, fmt.Errorf("copy failed: %w", err)
	}
	cs := e.CheckCodesign(ctx, target)
	if cs.Signed && !cs.Valid {
		restore()
		return "", cs, ErrBadSignature
	}
	if old != "" {
		_, _ = run(ctx, "/bin/rm", "-rf", old)
	}
	return target, cs, nil
}

// InstallPkg runs Apple's installer as root and returns the receipt ids it added (plus known ones).
func (e *Engine) InstallPkg(ctx context.Context, pkg string, known []string) ([]string, *Codesign, error) {
	cs := &Codesign{Gatekeeper: "skipped"}
	if out, err := e.R.Run(ctx, "/usr/sbin/pkgutil", "--check-signature", pkg); err == nil {
		cs.Signed, cs.Valid = true, true
		cs.Detail = strings.TrimSpace(firstLines(string(out), 2))
	} else if strings.Contains(string(out), "no signature") || strings.Contains(string(out), "Status: no signature") {
		cs.Detail = "package is not signed"
	} else {
		cs.Signed = strings.Contains(string(out), "Status:")
		cs.Detail = strings.TrimSpace(lastLine(string(out)))
		if cs.Signed {
			return nil, cs, errors.New("the package is signed but its signature does not verify; it was not installed")
		}
	}
	before := e.pkgs(ctx)
	if _, err := e.R.RunAdmin(ctx, "/usr/sbin/installer", "-pkg", pkg, "-target", "/"); err != nil {
		return nil, cs, fmt.Errorf("installer failed: %w", err)
	}
	ids := map[string]bool{}
	for _, id := range known {
		ids[id] = true
	}
	for id := range e.pkgs(ctx) {
		if !before[id] {
			ids[id] = true
		}
	}
	out := []string{}
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, cs, nil
}

func (e *Engine) pkgs(ctx context.Context) map[string]bool {
	m := map[string]bool{}
	out, err := e.R.Run(ctx, "/usr/sbin/pkgutil", "--pkgs")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m[l] = true
		}
	}
	return m
}

func firstLines(s string, n int) string {
	l := strings.SplitN(s, "\n", n+1)
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}

// Mount attaches a dmg read-only at a private mount point. The returned func detaches it.
func (e *Engine) Mount(ctx context.Context, dmg, tmp string) (string, func(), error) {
	mp, err := os.MkdirTemp(tmp, "mnt-")
	if err != nil {
		return "", nil, err
	}
	out, err := e.R.Run(ctx, "/usr/bin/hdiutil", "attach", "-plist", "-nobrowse", "-readonly", "-noautoopen", "-noverify", "-mountpoint", mp, dmg)
	if err != nil {
		os.Remove(mp)
		return "", nil, fmt.Errorf("could not open the disk image: %w", err)
	}
	// An image that is already attached comes back at its existing mount point.
	if m := mountPointRe.FindStringSubmatch(string(out)); m != nil && m[1] != mp {
		os.Remove(mp)
		real := m[1]
		return real, func() {}, nil // not ours to detach
	}
	return mp, func() {
		if _, err := e.R.Run(context.Background(), "/usr/bin/hdiutil", "detach", mp); err != nil {
			_, _ = e.R.Run(context.Background(), "/usr/bin/hdiutil", "detach", "-force", mp)
		}
		os.Remove(mp)
	}, nil
}

var mountPointRe = regexp.MustCompile(`<key>mount-point</key>\s*<string>([^<]+)</string>`)

// Unzip extracts a zip with ditto (keeps bundle metadata) into a fresh folder.
func (e *Engine) Unzip(ctx context.Context, zip, tmp string) (string, error) {
	d, err := os.MkdirTemp(tmp, "zip-")
	if err != nil {
		return "", err
	}
	if _, err := e.R.Run(ctx, "/usr/bin/ditto", "-x", "-k", zip, d); err != nil {
		return "", fmt.Errorf("could not open the zip: %w", err)
	}
	return d, nil
}

// FindPayload picks the .app or .pkg at the top of a folder (a mounted dmg or an extracted zip): the
// manifest's choice when given, otherwise the only one there.
func FindPayload(dir string, spec *InstallSpec) (string, string, error) {
	if spec != nil && spec.Pkg != "" {
		return filepath.Join(dir, spec.Pkg), KindPKG, existsErr(filepath.Join(dir, spec.Pkg))
	}
	if spec != nil && spec.Bundle != "" {
		return filepath.Join(dir, spec.Bundle), KindApp, existsErr(filepath.Join(dir, spec.Bundle))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", "", err
	}
	var apps, pkgs []string
	for _, en := range ents {
		n := en.Name()
		if strings.HasPrefix(n, ".") {
			continue
		}
		switch KindOf(n) {
		case KindApp:
			if en.IsDir() {
				apps = append(apps, n)
			}
		case KindPKG:
			pkgs = append(pkgs, n)
		}
	}
	// An app's dmg may carry RottenCore Installer next to the app; RottenCore is the payload only when alone.
	if len(apps) > 1 {
		kept := apps[:0]
		for _, a := range apps {
			if a != "RottenCore Installer.app" {
				kept = append(kept, a)
			}
		}
		apps = kept
	}
	switch {
	case len(apps) == 1 && len(pkgs) == 0:
		return filepath.Join(dir, apps[0]), KindApp, nil
	case len(pkgs) == 1 && len(apps) == 0:
		return filepath.Join(dir, pkgs[0]), KindPKG, nil
	case len(apps)+len(pkgs) == 0:
		return "", "", errors.New("no .app or .pkg found inside")
	}
	return "", "", fmt.Errorf("more than one thing to install inside (%d apps, %d packages); the app's rottencore.json must say which (install.bundle or install.pkg)", len(apps), len(pkgs))
}

func existsErr(p string) error {
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("%s is not inside", filepath.Base(p))
	}
	return nil
}

// RemoveApp moves an installed .app to the Trash (deleting it when the Trash is on another disk). Only
// .app paths directly inside an Applications folder are touched.
func (e *Engine) RemoveApp(ctx context.Context, path string) error {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if !strings.HasSuffix(clean, ".app") || (parent != e.dest("") && parent != e.dest("~/Applications")) {
		return fmt.Errorf("refusing to remove %s: not an app in an Applications folder", path)
	}
	if _, err := os.Lstat(clean); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if e.Home != "" {
		trash := filepath.Join(e.Home, ".Trash")
		if os.MkdirAll(trash, 0o700) == nil {
			dst := filepath.Join(trash, filepath.Base(clean))
			if _, err := os.Lstat(dst); err == nil {
				dst = filepath.Join(trash, strings.TrimSuffix(filepath.Base(clean), ".app")+" "+randSuffix()+".app")
			}
			if os.Rename(clean, dst) == nil {
				return nil
			}
		}
	}
	run := e.R.Run
	if !writable(parent) {
		run = e.R.RunAdmin
	}
	_, err := run(ctx, "/bin/rm", "-rf", clean)
	return err
}

// protectedPrefixes are never removed by a package uninstall.
var protectedPrefixes = []string{"/System", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/share",
	"/private/etc", "/private/var/db", "/etc", "/var", "/Library/Apple", "/Library/Extensions", "/Library/Frameworks"}

// SafePkgPath reports whether a file a package receipt lists may be deleted.
func SafePkgPath(p string) bool {
	if !filepath.IsAbs(p) || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || filepath.Clean(p) == "/" {
		return false
	}
	c := filepath.Clean(p)
	for _, pre := range protectedPrefixes {
		if c == pre || strings.HasPrefix(c, pre+"/") {
			return false
		}
	}
	return strings.Count(c, "/") >= 2 // never a top-level folder
}

// RemovePkg deletes the files of one package receipt and forgets it. It must run as root (the CLI's
// hidden `pkg-remove` command, started through RunAdmin). Folders are removed only when empty.
func (e *Engine) RemovePkg(ctx context.Context, id string) ([]string, error) {
	if !ghNameRe.MatchString(id) {
		return nil, fmt.Errorf("invalid package id %q", id)
	}
	info, err := e.R.Run(ctx, "/usr/sbin/pkgutil", "--pkg-info", id)
	if err != nil {
		return nil, fmt.Errorf("package %s is not installed", id)
	}
	vol, loc := "/", ""
	for _, l := range strings.Split(string(info), "\n") {
		if v, ok := strings.CutPrefix(l, "volume: "); ok {
			vol = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "location: "); ok {
			loc = strings.TrimSpace(v)
		}
	}
	base := filepath.Join(vol, loc)
	files, _ := e.R.Run(ctx, "/usr/sbin/pkgutil", "--only-files", "--files", id)
	dirs, _ := e.R.Run(ctx, "/usr/sbin/pkgutil", "--only-dirs", "--files", id)
	removed, skipped := []string{}, []string{}
	for _, f := range strings.Split(string(files), "\n") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p := filepath.Join(base, f)
		if !SafePkgPath(p) {
			skipped = append(skipped, p)
			continue
		}
		if os.Remove(p) == nil {
			removed = append(removed, p)
		}
	}
	dl := strings.Split(string(dirs), "\n")
	sort.Slice(dl, func(i, j int) bool { return len(dl[i]) > len(dl[j]) }) // deepest first
	for _, d := range dl {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if p := filepath.Join(base, d); SafePkgPath(p) {
			_ = os.Remove(p) // only succeeds when empty
		}
	}
	if _, err := e.R.Run(ctx, "/usr/sbin/pkgutil", "--forget", id); err != nil {
		return removed, err
	}
	if len(skipped) > 0 {
		return removed, fmt.Errorf("kept %d system files the package listed (not removed for safety)", len(skipped))
	}
	return removed, nil
}
