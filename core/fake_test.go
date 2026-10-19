package core

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeRunner stands in for the macOS tools.
type fakeRunner struct {
	mu        sync.Mutex
	dmgs      map[string]string   // dmg path -> folder that is its contents
	pkgFiles  map[string][]byte   // xar entry name -> bytes (any pkg)
	pkgIDs    map[string][]string // pkg path -> receipt ids it installs
	installed map[string]bool     // receipt ids present
	where     map[string][]string // path -> kMDItemWhereFroms
	signed    map[string]string   // app base name -> "valid" | "broken"
	admin     [][]string
	calls     []string
}

func newFake() *fakeRunner {
	return &fakeRunner{dmgs: map[string]string{}, pkgFiles: map[string][]byte{}, pkgIDs: map[string][]string{}, installed: map[string]bool{},
		where: map[string][]string{}, signed: map[string]string{}}
}

func (f *fakeRunner) RunAdmin(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.admin = append(f.admin, append([]string{name}, args...))
	f.mu.Unlock()
	return f.Run(ctx, name, args...)
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	switch filepath.Base(name) {
	case "ditto":
		if args[0] == "-x" {
			return nil, unzipTo(args[2], args[3])
		}
		return nil, copyTree(args[0], args[1])
	case "rm":
		return nil, os.RemoveAll(args[len(args)-1])
	case "mv":
		return nil, os.Rename(args[0], args[1])
	case "hdiutil":
		if args[0] == "attach" {
			src, ok := f.dmgs[args[len(args)-1]]
			if !ok {
				return nil, errors.New("not a disk image")
			}
			return nil, copyTree(src, args[len(args)-2]+"/")
		}
		return nil, nil
	case "codesign":
		st := f.signed[filepath.Base(args[len(args)-1])]
		if args[0] == "-dv" && st == "" {
			return []byte("code object is not signed at all"), errors.New("exit 1")
		}
		if args[0] == "--verify" && st == "broken" {
			return []byte("a sealed resource is missing or invalid"), errors.New("exit 1")
		}
		return nil, nil
	case "spctl":
		return []byte("rejected"), errors.New("exit 3")
	case "pkgutil":
		switch args[0] {
		case "--check-signature":
			return []byte("Status: no signature"), errors.New("exit 1")
		case "--pkgs":
			var b strings.Builder
			for id := range f.installed {
				b.WriteString(id + "\n")
			}
			return []byte(b.String()), nil
		case "--pkg-info":
			if !f.installed[args[1]] {
				return nil, errors.New("no receipt")
			}
			return []byte("package-id: " + args[1] + "\nvolume: /\nlocation: /\n"), nil
		case "--only-files", "--only-dirs":
			return nil, nil
		case "--expand":
			return nil, errors.New("not a package")
		case "--forget":
			delete(f.installed, args[1])
			return nil, nil
		}
	case "installer":
		for _, id := range f.pkgIDs[args[1]] {
			f.installed[id] = true
		}
		return nil, nil
	case "xar":
		if args[0] == "-tf" {
			var b strings.Builder
			for n := range f.pkgFiles {
				b.WriteString(n + "\n")
			}
			return []byte(b.String()), nil
		}
		name := args[len(args)-1]
		dst := filepath.Join(args[3], name)
		os.MkdirAll(filepath.Dir(dst), 0o755)
		return nil, os.WriteFile(dst, f.pkgFiles[name], 0o644)
	case "mdls":
		u := f.where[args[len(args)-1]]
		if len(u) == 0 {
			return []byte("(null)"), nil
		}
		return []byte("(\n    \"" + strings.Join(u, "\",\n    \"") + "\"\n)"), nil
	case "xattr":
		if args[0] == "-dr" {
			return nil, nil
		}
		return nil, errors.New("no such xattr")
	case "rottencore":
		return nil, nil // pkg-remove as root: covered by Engine.RemovePkg tests
	}
	return nil, fmt.Errorf("fake: unexpected %s %v", name, args)
}

func copyTree(src, dst string) error {
	if strings.HasSuffix(dst, "/") { // copy contents into an existing folder
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, info.Mode())
	})
}

func unzipTo(zp, dst string) error {
	z, err := zip.OpenReader(zp)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, f := range z.File {
		p := filepath.Join(dst, f.Name)
		if strings.HasSuffix(f.Name, "/") {
			os.MkdirAll(p, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// makeApp builds a minimal .app folder with an optional embedded manifest.
func makeApp(t *testing.T, dir, name, id, version string, manifest string) string {
	t.Helper()
	app := filepath.Join(dir, name+".app")
	os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755)
	os.MkdirAll(filepath.Join(app, "Contents", "Resources"), 0o755)
	plist := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + id +
		`</string><key>CFBundleName</key><string>` + name + `</string><key>CFBundleShortVersionString</key><string>` + version + `</string></dict></plist>`
	os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644)
	os.WriteFile(filepath.Join(app, "Contents", "MacOS", name), []byte("#!/bin/sh\necho "+version+"\n"), 0o755)
	if manifest != "" {
		os.WriteFile(filepath.Join(app, "Contents", "Resources", ManifestName), []byte(manifest), 0o644)
	}
	return app
}

// zipApp zips an .app folder (top level = the .app).
func zipApp(t *testing.T, app, out string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	base := filepath.Dir(app)
	filepath.Walk(app, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		w, _ := zw.Create(filepath.ToSlash(rel))
		b, _ := os.ReadFile(p)
		w.Write(b)
		return nil
	})
	zw.Close()
	if out != "" {
		os.WriteFile(out, buf.Bytes(), 0o644)
	}
	return buf.Bytes()
}
