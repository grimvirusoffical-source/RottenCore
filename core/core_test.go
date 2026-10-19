package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sumOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// fakeGitHub serves releases and assets for one repo.
type fakeGitHub struct {
	srv      *httptest.Server
	releases map[string][]Asset // tag -> assets
	files    map[string][]byte  // asset name@tag -> bytes
	latest   string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{releases: map[string][]Asset{}, files: map[string][]byte{}}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/repos/acme/tool/releases/") {
			tag := strings.TrimPrefix(p, "/repos/acme/tool/releases/")
			if tag == "latest" {
				tag = g.latest
			} else {
				tag = strings.TrimPrefix(tag, "tags/")
			}
			as, ok := g.releases[tag]
			if !ok {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(Release{TagName: tag, HTMLURL: "https://github.com/acme/tool/releases/tag/" + tag, Assets: as})
			return
		}
		if strings.HasPrefix(p, "/dl/") {
			b, ok := g.files[strings.TrimPrefix(p, "/dl/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// publish adds a release with the given files and a SHA256SUMS (sums can be overridden to simulate tampering).
func (g *fakeGitHub) publish(tag string, files map[string][]byte, badSum string) {
	var sums strings.Builder
	as := []Asset{}
	for n, b := range files {
		g.files[n+"@"+tag] = b
		as = append(as, Asset{Name: n, Size: int64(len(b)), URL: g.srv.URL + "/dl/" + n + "@" + tag})
		s := sumOf(b)
		if n == badSum {
			s = strings.Repeat("0", 64)
		}
		fmt.Fprintf(&sums, "%s  %s\n", s, n)
	}
	g.files["SHA256SUMS@"+tag] = []byte(sums.String())
	as = append(as, Asset{Name: "SHA256SUMS", URL: g.srv.URL + "/dl/SHA256SUMS@" + tag})
	g.releases[tag] = as
	g.latest = tag
}

func testCore(t *testing.T, f *fakeRunner, ghAPI string, pins []ed25519.PublicKey) *Core {
	t.Helper()
	d := t.TempDir()
	home := filepath.Join(d, "home")
	os.MkdirAll(filepath.Join(home, "Applications"), 0o755)
	os.MkdirAll(filepath.Join(d, "Applications"), 0o755)
	return &Core{
		Net:    &Net{AllowLoopbackHTTP: true, GitHubAPI: ghAPI},
		Engine: &Engine{R: f, Applications: filepath.Join(d, "Applications"), UserApps: filepath.Join(home, "Applications"), Home: home},
		State:  &State{Dir: filepath.Join(d, "support")},
		Pins:   pins, TmpDir: filepath.Join(d, "tmp"), SelfPath: "/usr/local/bin/rottencore", Arch: "arm64",
	}
}

const ghManifest = `{"schema":1,"appId":"com.acme.tool","name":"Tool","version":"%s","source":"github",
 "github":{"owner":"acme","repo":"tool","assetPattern":"tool-{version}-macos-universal.zip"},"ageRating":"everyone"}`

func TestManifestParsing(t *testing.T) {
	ok := []string{
		fmt.Sprintf(ghManifest, "1.0.0"),
		`{"schema":1,"appId":"com.redxai.redx","name":"RedX","version":"0.4.3","source":"store","store":{"listingId":4},"install":{"bundle":"RedX.app"}}`,
	}
	for _, s := range ok {
		if _, err := ParseManifest([]byte(s)); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		"unknown field": `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"github","github":{"owner":"a","repo":"b"},"trusted":true}`,
		"schema":        `{"schema":2,"appId":"com.a.b","name":"A","version":"1","source":"store"}`,
		"source":        `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"web"}`,
		"github repo":   `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"github"}`,
		"app id":        `{"schema":1,"appId":"A B","name":"A","version":"1","source":"store"}`,
		"version":       `{"schema":1,"appId":"com.a.b","name":"A","version":"latest","source":"store"}`,
		"http store":    `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","store":{"url":"http://evil.example"}}`,
		"path asset":    `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"github","github":{"owner":"a","repo":"b","asset":"../x"}}`,
		"bundle path":   `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","install":{"bundle":"../../etc/x.app"}}`,
		"destination":   `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","install":{"destination":"/usr/bin"}}`,
		"sha":           `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","artifact":{"sha256":"xyz"}}`,
		"trailing":      `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store"} {}`,
		"age rating":    `{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","ageRating":"7+"}`,
	}
	for name, s := range bad {
		if _, err := ParseManifest([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSHA256SUMS(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	m, err := ParseSHA256SUMS([]byte(a + "  redx.dmg\n" + b + " *./redx.pkg\n\n# comment\n"))
	if err != nil || m["redx.dmg"] != a || m["redx.pkg"] != b {
		t.Fatalf("%v %v", m, err)
	}
	for _, s := range []string{"zz  x\n", a + "\n", a + "  ../x\n", a + "  x\n" + b + "  x\n"} {
		if _, err := ParseSHA256SUMS([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestVersionsAndAssets(t *testing.T) {
	cases := [][3]interface{}{{"1.2.10", "1.2.9", 1}, {"v1.0.0", "1.0.0", 0}, {"1.0.0-rc1", "1.0.0", -1}, {"0.4.4", "0.4.3", 1}, {"2", "1.9.9", 1}}
	for _, c := range cases {
		if got := CompareVersions(c[0].(string), c[1].(string)); got != c[2].(int) {
			t.Errorf("%v vs %v = %d", c[0], c[1], got)
		}
	}
	rel := &Release{TagName: "v0.4.3", Assets: []Asset{{Name: "redx-0.4.3-linux-amd64.tar.gz"}, {Name: "redx-0.4.3-macos-amd64.dmg"},
		{Name: "redx-0.4.3-macos-arm64.pkg"}, {Name: "redx-0.4.3-macos-universal.dmg"}, {Name: "redx-0.4.3-macos-universal.pkg"}, {Name: "SHA256SUMS"}}}
	if a := PickMacAsset(rel, "", KindPKG, "arm64"); a == nil || a.Name != "redx-0.4.3-macos-universal.pkg" {
		t.Fatalf("pkg pick %v", a)
	}
	if a := PickMacAsset(rel, "", "", "x86_64"); a == nil || a.Name != "redx-0.4.3-macos-universal.dmg" {
		t.Fatalf("default pick %v", a)
	}
	if a := PickMacAsset(rel, "redx-{version}-macos-arm64.pkg", "", ""); a == nil || a.Name != "redx-0.4.3-macos-arm64.pkg" {
		t.Fatalf("pattern pick %v", a)
	}
}

func TestStateTracking(t *testing.T) {
	s := &State{Dir: t.TempDir()}
	if l, err := s.List(); err != nil || len(l) != 0 {
		t.Fatal(l, err)
	}
	if err := s.Put(Entry{AppID: "com.a.b", Name: "B", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Entry{AppID: "com.a.a", Name: "A", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Entry{AppID: "com.a.b", Name: "B", Version: "2"}); err != nil {
		t.Fatal(err)
	}
	l, _ := s.List()
	if len(l) != 2 || l[0].Name != "A" || l[1].Version != "2" {
		t.Fatalf("%+v", l)
	}
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(i int) { done <- s.Put(Entry{AppID: fmt.Sprintf("com.x.n%d", i), Name: fmt.Sprint(i)}) }(i)
	}
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if l, _ := s.List(); len(l) != 12 {
		t.Fatalf("concurrent puts lost entries: %d", len(l))
	}
	s.Remove("com.a.b")
	if e, _ := s.Get("com.a.b"); e != nil {
		t.Fatal("not removed")
	}
	if st, err := os.Stat(filepath.Join(s.Dir, "installed.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("installed.json mode %v %v", st, err)
	}
}

func TestOriginsAreHTTPSOnly(t *testing.T) {
	for _, u := range []string{"https://api.rottenapplestore.org", "https://github.com"} {
		if !ValidOrigin(u, false) {
			t.Errorf("refused %s", u)
		}
	}
	for _, u := range []string{"http://api.rottenapplestore.org", "http://127.0.0.1:8080", "file:///etc/passwd", "https://user@x.org", "ftp://x"} {
		if ValidOrigin(u, false) {
			t.Errorf("accepted %s", u)
		}
	}
	if !ValidOrigin("http://127.0.0.1:9", true) || ValidOrigin("http://10.0.0.1", true) {
		t.Error("loopback rule")
	}
}

func TestGitHubZipInstallUpdateUninstall(t *testing.T) {
	ctx := context.Background()
	g := newFakeGitHub(t)
	f := newFake()
	c := testCore(t, f, g.srv.URL, nil)
	src := t.TempDir()
	v1 := zipApp(t, makeApp(t, filepath.Join(src, "1"), "Tool", "com.acme.tool", "1.0.0", fmt.Sprintf(ghManifest, "1.0.0")), "")
	g.publish("v1.0.0", map[string][]byte{"tool-1.0.0-macos-universal.zip": v1}, "")

	in, err := c.FetchGitHub(ctx, "acme", "tool", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if in.Source != SourceGitHub || in.AppID != "com.acme.tool" || in.Verdict.Checksum != "match" || in.Verdict.Trusted {
		t.Fatalf("inspection %+v %+v", in, in.Verdict)
	}
	if in.Verdict.Warning != UntrustedWarning {
		t.Fatalf("warning %q", in.Verdict.Warning)
	}
	// untrusted: refused until the person accepts the warning
	if _, err := c.Install(ctx, in, InstallOptions{}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("installed without accepting: %v", err)
	}
	e, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true})
	if err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(c.Engine.Applications, "Tool.app")
	if b, err := os.ReadFile(filepath.Join(app, "Contents", "MacOS", "Tool")); err != nil || !strings.Contains(string(b), "1.0.0") {
		t.Fatalf("not installed: %v", err)
	}
	if e.Version != "1.0.0" || !e.AcceptedRisk || e.GitHub == nil || e.GitHub.AssetPattern == "" || e.SHA256 != sumOf(v1) {
		t.Fatalf("entry %+v", e)
	}
	// a new release shows up as an update
	v2 := zipApp(t, makeApp(t, filepath.Join(src, "2"), "Tool", "com.acme.tool", "1.1.0", fmt.Sprintf(ghManifest, "1.1.0")), "")
	g.publish("v1.1.0", map[string][]byte{"tool-1.1.0-macos-universal.zip": v2}, "")
	ups, err := c.CheckUpdates(ctx)
	if err != nil || len(ups) != 1 || !ups[0].Newer || ups[0].Available != "1.1.0" || ups[0].Asset != "tool-1.1.0-macos-universal.zip" {
		t.Fatalf("updates %+v %v", ups, err)
	}
	up, err := c.PrepareUpdate(ctx, "com.acme.tool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Install(ctx, up, InstallOptions{AcceptUntrusted: true}); err != nil {
		t.Fatal(err)
	}
	up.Close()
	if b, _ := os.ReadFile(filepath.Join(app, "Contents", "MacOS", "Tool")); !strings.Contains(string(b), "1.1.0") {
		t.Fatal("update not installed")
	}
	if e, _ := c.State.Get("com.acme.tool"); e.Version != "1.1.0" {
		t.Fatalf("state %+v", e)
	}
	// uninstall: to the Trash, and forgotten
	if _, err := c.Uninstall(ctx, "com.acme.tool"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(app); !os.IsNotExist(err) {
		t.Fatal("app still there")
	}
	if _, err := os.Stat(filepath.Join(c.Engine.Home, ".Trash", "Tool.app")); err != nil {
		t.Fatal("not in the Trash")
	}
	if e, _ := c.State.Get("com.acme.tool"); e != nil {
		t.Fatal("still listed")
	}
}

func TestChecksumMismatchIsAHardRefusal(t *testing.T) {
	ctx := context.Background()
	g := newFakeGitHub(t)
	c := testCore(t, newFake(), g.srv.URL, nil)
	z := zipApp(t, makeApp(t, t.TempDir(), "Tool", "com.acme.tool", "1.0.0", fmt.Sprintf(ghManifest, "1.0.0")), "")
	g.publish("v1.0.0", map[string][]byte{"tool-1.0.0-macos-universal.zip": z}, "tool-1.0.0-macos-universal.zip")
	in, err := c.FetchGitHub(ctx, "acme", "tool", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if !in.Verdict.Refuse || in.Verdict.Checksum != "mismatch" {
		t.Fatalf("%+v", in.Verdict)
	}
	if _, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true}); !errors.Is(err, ErrRefused) {
		t.Fatalf("mismatch installed after accepting: %v", err)
	}
	if l, _ := c.State.List(); len(l) != 0 {
		t.Fatal("recorded")
	}
}

// fakeStore serves a listing and an attestation.
func fakeStore(t *testing.T, l Listing, att func() *Signed) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == fmt.Sprintf("/v1/catalog/apps/%d", l.ID), r.URL.Path == "/v1/catalog/lookup" && r.URL.Query().Get("appId") == l.AppID:
			json.NewEncoder(w).Encode(l)
		case r.URL.Path == fmt.Sprintf("/v1/catalog/apps/%d/attestation", l.ID) && att != nil:
			json.NewEncoder(w).Encode(att())
		case r.URL.Path == "/v1/catalog/apps":
			json.NewEncoder(w).Encode([]Listing{l})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func attest(t *testing.T, priv ed25519.PrivateKey, appID string, b []byte, kind string) *Signed {
	var a Attestation
	a.AppID, a.Version, a.Build = appID, "2.0.0", 7
	a.Artifact.Name, a.Artifact.Kind, a.Artifact.SHA256, a.Artifact.Bytes = "x."+kind, kind, sumOf(b), int64(len(b))
	s, err := SignAttestation(priv, a)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A dmg whose manifest says store, with a store attestation for its exact bytes.
func storeDMG(t *testing.T, f *fakeRunner, storeURL string) (string, []byte) {
	dir := t.TempDir()
	contents := filepath.Join(dir, "contents")
	makeApp(t, contents, "Notes", "com.rotten.notes", "2.0.0", "")
	os.WriteFile(filepath.Join(contents, ManifestName), []byte(`{"schema":1,"appId":"com.rotten.notes","name":"Notes","version":"2.0.0","source":"store","store":{"listingId":7}}`), 0o644)
	dmg := filepath.Join(dir, "Notes.dmg")
	b := []byte("fake dmg bytes " + dir)
	os.WriteFile(dmg, b, 0o644)
	f.dmgs[dmg] = contents
	return dmg, b
}

func TestStoreTrustNeedsAPinnedSignature(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil) // throwaway TEST key
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	var current func() *Signed
	var storeURL string
	srv := fakeStore(t, Listing{ID: 7, AppID: "com.rotten.notes", Name: "Notes", Version: "2.0.0", AgeRating: "13+"}, func() *Signed { return current() })
	storeURL = srv.URL

	inspect := func(pins []ed25519.PublicKey, a func(b []byte) *Signed) (*Core, *Inspection) {
		f := newFake()
		c := testCore(t, f, "", pins)
		c.StoreURL = storeURL
		dmg, b := storeDMG(t, f, storeURL)
		current = func() *Signed { return a(b) }
		in, err := c.Inspect(ctx, dmg, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(in.Close)
		return c, in
	}
	// the real thing: trusted, installs with no warning, shows the store's age rating
	c, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed { return attest(t, priv, "com.rotten.notes", b, KindDMG) })
	if !in.Verdict.Trusted || in.Verdict.Warning != "" || in.AgeRating != "13+" || in.Source != SourceStore {
		t.Fatalf("store app not trusted: %+v %+v", in.Verdict, in)
	}
	e, err := c.Install(ctx, in, InstallOptions{})
	if err != nil || !e.Trusted || e.AcceptedRisk || e.Paths[0] != filepath.Join(c.Engine.Applications, "Notes.app") {
		t.Fatalf("store install %+v %v", e, err)
	}

	// spoof 1: the same file and manifest, but RottenCore pins no key (v0.1.0 production)
	if _, in := inspect(PinnedStoreKeys, func(b []byte) *Signed { return attest(t, priv, "com.rotten.notes", b, KindDMG) }); in.Verdict.Trusted || in.Verdict.Warning != UntrustedWarning {
		t.Fatal("trusted without a pinned key")
	}
	// spoof 2: signed by someone else's key
	if _, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed { return attest(t, otherPriv, "com.rotten.notes", b, KindDMG) }); in.Verdict.Trusted {
		t.Fatal("trusted under a foreign key")
	}
	// spoof 3: a genuine attestation for another app
	if _, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed { return attest(t, priv, "com.rotten.other", b, KindDMG) }); in.Verdict.Trusted {
		t.Fatal("trusted with another app's attestation")
	}
	// spoof 4: a genuine attestation for other bytes is a mismatch: hard refusal
	c4, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed { return attest(t, priv, "com.rotten.notes", []byte("other"), KindDMG) })
	if !in.Verdict.Refuse {
		t.Fatal("attested sha mismatch not refused")
	}
	if _, err := c4.Install(ctx, in, InstallOptions{AcceptUntrusted: true}); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	// spoof 5: a document edited after signing
	if _, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed {
		s := attest(t, priv, "com.rotten.notes", b, KindDMG)
		doc, _ := base64.StdEncoding.DecodeString(s.Doc)
		s.Doc = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(doc), `"build":7`, `"build":8`, 1)))
		return s
	}); in.Verdict.Trusted {
		t.Fatal("trusted an edited attestation")
	}
	// spoof 6: a store review receipt (other domain, same key) replayed as an attestation
	if _, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed {
		s := attest(t, priv, "com.rotten.notes", b, KindDMG)
		doc, _ := base64.StdEncoding.DecodeString(s.Doc)
		s.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte("RARXAI-RECEIPT-v1\x00"), doc...)))
		return s
	}); in.Verdict.Trusted {
		t.Fatal("trusted a signature from another domain")
	}
	// spoof 7: manifest says "store", no attestation at all
	if _, in := inspect([]ed25519.PublicKey{pub}, func(b []byte) *Signed { return &Signed{} }); in.Verdict.Trusted || in.Verdict.Warning != UntrustedWarning {
		t.Fatal("trusted on the manifest's word")
	} else if !strings.Contains(strings.Join(in.Verdict.Reasons, " "), "claim is ignored") {
		t.Fatalf("reasons %v", in.Verdict.Reasons)
	}
}

func TestEmbeddedAttestationAndSidecarSpoof(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newFake()
	c := testCore(t, f, "", []ed25519.PublicKey{pub})
	c.StoreURL = ""
	dir := t.TempDir()
	z := filepath.Join(dir, "Notes.zip")
	b := zipApp(t, makeApp(t, filepath.Join(dir, "a"), "Notes", "com.rotten.notes", "2.0.0", `{"schema":1,"appId":"com.rotten.notes","name":"Notes","version":"2.0.0","source":"store"}`), z)
	// a sidecar attestation for the exact bytes, signed by the pinned key: trusted (offline)
	att, _ := json.Marshal(attest(t, priv, "com.rotten.notes", b, KindZIP))
	os.WriteFile(z+".rottencore-attestation.json", att, 0o644)
	in, err := c.Inspect(ctx, z, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Verdict.Trusted {
		t.Fatalf("%+v", in.Verdict)
	}
	in.Close()
	// a sidecar manifest naming a different sha256 is a mismatch
	os.Remove(z + ".rottencore-attestation.json")
	os.WriteFile(z+".rottencore.json", []byte(`{"schema":1,"appId":"com.rotten.notes","name":"Notes","version":"2.0.0","source":"store","artifact":{"sha256":"`+strings.Repeat("1", 64)+`"}}`), 0o644)
	in, _ = c.Inspect(ctx, z, nil)
	if !in.Verdict.Refuse {
		t.Fatalf("sidecar sha mismatch: %+v", in.Verdict)
	}
	in.Close()
}

func TestDetectionFallsBackToWhereFroms(t *testing.T) {
	ctx := context.Background()
	g := newFakeGitHub(t)
	f := newFake()
	c := testCore(t, f, g.srv.URL, nil)
	dir := t.TempDir()
	z := filepath.Join(dir, "tool-1.0.0-macos-universal.zip")
	b := zipApp(t, makeApp(t, filepath.Join(dir, "a"), "Tool", "com.acme.tool", "1.0.0", ""), z) // no manifest
	g.publish("v1.0.0", map[string][]byte{"tool-1.0.0-macos-universal.zip": b}, "")
	f.where[z] = []string{"https://github.com/acme/tool/releases/download/v1.0.0/tool-1.0.0-macos-universal.zip", "https://github.com/acme/tool/releases"}
	in, err := c.Inspect(ctx, z, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if in.Source != SourceGitHub || in.GitHub.Repo != "tool" || in.Verdict.Checksum != "match" || in.Verdict.Trusted {
		t.Fatalf("%+v %+v", in, in.Verdict)
	}
	// nothing at all: unknown source, no checksum, untrusted
	z2 := filepath.Join(dir, "other.zip")
	zipApp(t, makeApp(t, filepath.Join(dir, "b"), "Other", "com.x.other", "1", ""), z2)
	in2, _ := c.Inspect(ctx, z2, nil)
	defer in2.Close()
	if in2.Source != SourceUnknown || in2.Verdict.Checksum != "none" || in2.Verdict.Trusted {
		t.Fatalf("%+v", in2.Verdict)
	}
	e, err := c.Install(ctx, in2, InstallOptions{AcceptUntrusted: true})
	if err != nil || e.AppID != "com.x.other" {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestPkgInstallAndUninstall(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	c := testCore(t, f, "", nil)
	dir := t.TempDir()
	pkg := filepath.Join(dir, "redx-0.4.3-macos-universal.pkg")
	os.WriteFile(pkg, []byte("xar!"), 0o644)
	f.pkgIDs[pkg] = []string{"com.redxai.redx.pkg"}
	f.pkgFiles["Resources/rottencore.json"] = []byte(`{"schema":1,"appId":"com.redxai.redx","name":"RedX","version":"0.4.3","source":"github","github":{"owner":"grimvirusoffical-source","repo":"RedX","tag":"v0.4.3"}}`)
	c.Net.GitHubAPI = "http://127.0.0.1:1" // offline: no checksum available
	in, err := c.Inspect(ctx, pkg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if in.AppID != "com.redxai.redx" || in.Source != SourceGitHub || in.Verdict.Checksum != "none" {
		t.Fatalf("%+v %+v", in, in.Verdict)
	}
	e, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true})
	if err != nil || len(e.PkgIDs) != 1 || e.PkgIDs[0] != "com.redxai.redx.pkg" {
		t.Fatalf("%+v %v", e, err)
	}
	if len(f.admin) != 1 || f.admin[0][0] != "/usr/sbin/installer" {
		t.Fatalf("installer not run as admin: %v", f.admin)
	}
	if _, err := c.Uninstall(ctx, "com.redxai.redx"); err != nil {
		t.Fatal(err)
	}
	last := f.admin[len(f.admin)-1]
	if strings.Join(last, " ") != "/usr/local/bin/rottencore pkg-remove com.redxai.redx.pkg" {
		t.Fatalf("pkg removal %v", last)
	}
	// the root step itself
	f.installed["com.redxai.redx.pkg"] = true
	if _, err := c.Engine.RemovePkg(ctx, "com.redxai.redx.pkg"); err != nil || f.installed["com.redxai.redx.pkg"] {
		t.Fatalf("forget: %v", err)
	}
}

func TestBrokenSignatureRestoresTheOldCopy(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	c := testCore(t, f, "", nil)
	old := makeApp(t, t.TempDir(), "Tool", "com.acme.tool", "1.0.0", "")
	if _, _, err := c.Engine.InstallApp(ctx, old, ""); err != nil {
		t.Fatal(err)
	}
	f.signed["Tool.app"] = "broken"
	nw := makeApp(t, t.TempDir(), "Tool", "com.acme.tool", "2.0.0", "")
	if _, _, err := c.Engine.InstallApp(ctx, nw, ""); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("broken signature accepted: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(c.Engine.Applications, "Tool.app", "Contents", "MacOS", "Tool"))
	if !strings.Contains(string(b), "1.0.0") {
		t.Fatal("old copy not restored")
	}
	f.signed["Tool.app"] = "valid"
	_, cs, err := c.Engine.InstallApp(ctx, nw, "")
	if err != nil || !cs.Signed || !cs.Valid || cs.Gatekeeper != "rejected" {
		t.Fatalf("%+v %v", cs, err)
	}
}

func TestSafePkgPaths(t *testing.T) {
	for _, p := range []string{"/Applications/RedX.app/Contents/MacOS/redx", "/usr/local/bin/redx", "/Library/Application Support/RedX/x"} {
		if !SafePkgPath(p) {
			t.Errorf("refused %s", p)
		}
	}
	for _, p := range []string{"/", "/usr/bin/ls", "/System/Library/x", "/etc/hosts", "/private/etc/sudoers", "relative/x", "/Applications", "/usr/local/../bin/ls", "/Library/Apple/x"} {
		if SafePkgPath(p) {
			t.Errorf("allowed %s", p)
		}
	}
}

func TestRemoveAppStaysInApplications(t *testing.T) {
	c := testCore(t, newFake(), "", nil)
	for _, p := range []string{"/etc", filepath.Join(c.Engine.Applications, "..", "x.app"), filepath.Join(c.Engine.Applications, "Sub", "x.app"), filepath.Join(c.Engine.Applications, "notes.txt")} {
		if err := c.Engine.RemoveApp(context.Background(), p); err == nil {
			t.Errorf("removed %s", p)
		}
	}
}

func TestRarxaiGoesToTheLauncher(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	c := testCore(t, f, "", nil)
	c.StoreURL = ""
	p := filepath.Join(t.TempDir(), "com.rotten.notes.rarxai")
	os.WriteFile(p, []byte("rarxai"), 0o644)
	in, err := c.Inspect(ctx, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Source != SourceStore || in.Verdict.Trusted {
		t.Fatalf("%+v", in.Verdict)
	}
	t.Setenv("ROTTENCORE_RA_LAUNCHER", "/nonexistent/ra-launcher")
	t.Setenv("PATH", "")
	if _, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true}); err == nil || !strings.Contains(err.Error(), "Rotten Apple launcher") {
		t.Fatalf("%v", err)
	}
	if l, _ := StoreInstallLink("https://api.rottenapplestore.org", "com.rotten.notes"); l != "rottenapple://install?app=com.rotten.notes&store=https%3A%2F%2Fapi.rottenapplestore.org" {
		t.Fatal(l)
	}
}

func TestOIDCDiscoveryAndPKCE(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Discovery{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/oauth2/authorize", TokenEndpoint: srv.URL + "/oauth2/token",
				UserinfoEndpoint: srv.URL + "/oauth2/userinfo", JWKSURI: srv.URL + "/oauth2/jwks"})
		case "/oauth2/token":
			r.ParseForm()
			if r.Form.Get("code_verifier") == "" || r.Form.Get("client_id") != "rottencore" || r.Form.Get("grant_type") != "authorization_code" {
				http.Error(w, "bad", 400)
				return
			}
			json.NewEncoder(w).Encode(Tokens{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 600})
		}
	}))
	defer srv.Close()
	o := &OIDCAccounts{Issuer: srv.URL, Net: &Net{AllowLoopbackHTTP: true}}
	if _, err := o.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := NewPKCE()
	u, _ := o.AuthorizeURL(p, "http://127.0.0.1:5000/callback")
	if !strings.Contains(u, "code_challenge_method=S256") || !strings.Contains(u, "client_id=rottencore") || strings.Contains(u, p.Verifier) {
		t.Fatal(u)
	}
	if tk, err := o.Exchange(context.Background(), p, "code", "http://127.0.0.1:5000/callback"); err != nil || tk.AccessToken != "at" {
		t.Fatal(err)
	}
	if _, err := (&OIDCAccounts{Net: &Net{}}).SignIn(context.Background()); !errors.Is(err, ErrAccountsComingSoon) {
		t.Fatal(err)
	}
}

func TestProductionPinsAreEmpty(t *testing.T) {
	if len(PinnedStoreKeys) != 0 {
		t.Fatal("v0.1.0 must ship with no store key until Red-XAI provisions it; update the release notes when this changes")
	}
}

func TestGitHubTokenOnlyGoesToTheAPIHost(t *testing.T) {
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get("Authorization")
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	n := &Net{AllowLoopbackHTTP: true, GitHubAPI: "https://api.github.com", GitHubToken: "tok"}
	var v map[string]interface{}
	n.GetJSON(context.Background(), srv.URL+"/other", &v)
	if seen["/other"] != "" {
		t.Fatal("token sent to another host")
	}
}
