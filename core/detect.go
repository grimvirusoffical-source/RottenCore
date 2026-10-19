package core

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// found is what was read from one place.
type found struct {
	manifest    []byte
	attestation []byte
	where       string
}

func readSmall(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil
	}
	return b
}

// fromDir reads rottencore.json / rottencore.attestation.json at the root of a folder (a mounted dmg,
// an extracted pkg) or in an app's Contents/Resources.
func fromDir(dir, where string) *found {
	f := &found{where: where}
	for _, d := range []string{dir, filepath.Join(dir, "Contents", "Resources")} {
		if f.manifest == nil {
			f.manifest = readSmall(filepath.Join(d, ManifestName))
		}
		if f.attestation == nil {
			f.attestation = readSmall(filepath.Join(d, AttestationName))
		}
	}
	if f.manifest == nil && f.attestation == nil {
		return nil
	}
	return f
}

// fromZip reads the files from a zip: at its root or in a top-level app's Contents/Resources.
func fromZip(path string) *found {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer z.Close()
	f := &found{where: "embedded:zip"}
	for _, e := range z.File {
		n := strings.TrimPrefix(e.Name, "./")
		parts := strings.Split(n, "/")
		base := parts[len(parts)-1]
		ok := len(parts) == 1 || (len(parts) == 4 && strings.HasSuffix(parts[0], ".app") && parts[1] == "Contents" && parts[2] == "Resources")
		if !ok || (base != ManifestName && base != AttestationName) || e.UncompressedSize64 > 1<<20 {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if base == ManifestName && f.manifest == nil {
			f.manifest = b
		} else if base == AttestationName && f.attestation == nil {
			f.attestation = b
		}
	}
	if f.manifest == nil && f.attestation == nil {
		return nil
	}
	return f
}

// fromPkg lists a flat package with xar and extracts the two files if they are in it.
func fromPkg(ctx context.Context, r Runner, pkg, tmp string) *found {
	out, err := r.Run(ctx, "/usr/bin/xar", "-tf", pkg)
	if err != nil {
		return nil
	}
	var want []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		b := filepath.Base(l)
		if (b == ManifestName || b == AttestationName) && !strings.Contains(l, "..") && strings.Count(l, "/") <= 2 {
			want = append(want, l)
		}
	}
	if len(want) == 0 {
		return nil
	}
	d, err := os.MkdirTemp(tmp, "pkg-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(d)
	f := &found{where: "embedded:pkg"}
	for _, w := range want {
		if _, err := r.Run(ctx, "/usr/bin/xar", "-xf", pkg, "-C", d, w); err != nil {
			continue
		}
		b := readSmall(filepath.Join(d, w))
		if filepath.Base(w) == ManifestName && f.manifest == nil {
			f.manifest = b
		} else if filepath.Base(w) == AttestationName && f.attestation == nil {
			f.attestation = b
		}
	}
	if f.manifest == nil && f.attestation == nil {
		return nil
	}
	return f
}

var quotedRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// whereFroms reads Spotlight's kMDItemWhereFroms (the URLs a browser saved the file from).
func whereFroms(ctx context.Context, r Runner, path string) []string {
	out, err := r.Run(ctx, "/usr/bin/mdls", "-raw", "-name", "kMDItemWhereFroms", path)
	if err != nil {
		return nil
	}
	var urls []string
	for _, m := range quotedRe.FindAllStringSubmatch(string(out), 4) {
		urls = append(urls, m[1])
	}
	return urls
}

// quarantineAgent reads the app that downloaded the file from com.apple.quarantine ("flags;time;agent;uuid").
func quarantineAgent(ctx context.Context, r Runner, path string) (string, bool) {
	out, err := r.Run(ctx, "/usr/bin/xattr", "-p", "com.apple.quarantine", path)
	if err != nil {
		return "", false
	}
	p := strings.Split(strings.TrimSpace(string(out)), ";")
	if len(p) >= 3 {
		return p[2], true
	}
	return "", true
}

// bundleInfo reads CFBundleIdentifier, CFBundleName and CFBundleShortVersionString from an app's
// Info.plist (XML; binary plists are converted with plutil).
func bundleInfo(ctx context.Context, r Runner, app string) (id, name, version string) {
	p := filepath.Join(app, "Contents", "Info.plist")
	b := readSmall(p)
	if len(b) > 6 && string(b[:6]) == "bplist" {
		out, err := r.Run(ctx, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", p)
		if err != nil {
			return "", "", ""
		}
		b = out
	}
	kv := plistStrings(b)
	return kv["CFBundleIdentifier"], firstNonEmpty(kv["CFBundleDisplayName"], kv["CFBundleName"]), kv["CFBundleShortVersionString"]
}

func plistStrings(b []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = false
	depth, key, inKey, inStr := 0, "", false, false
	for {
		t, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		switch v := t.(type) {
		case xml.StartElement:
			depth++
			inKey, inStr = v.Name.Local == "key", v.Name.Local == "string"
		case xml.EndElement:
			depth--
			inKey, inStr = false, false
		case xml.CharData:
			s := strings.TrimSpace(string(v))
			if inKey {
				key = s
			} else if inStr && key != "" && depth == 3 {
				if _, ok := out[key]; !ok {
					out[key] = s
				}
				key = ""
			}
		}
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
