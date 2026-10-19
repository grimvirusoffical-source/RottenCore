package builder_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/builder"
	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

func devKey(t *testing.T) (core.Signer, []core.Cert, core.ChainPolicy, time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	root, _, err := ca.NewRoot(ctx, &ca.Mixer{}, ca.DefaultTiers(), "Red-XAI TEST Root", true, now)
	if err != nil {
		t.Fatal(err)
	}
	iss, _, err := root.IssueIntermediate(ctx, "ra-core TEST Issuing")
	if err != nil {
		t.Fatal(err)
	}
	k, _, err := ca.GenerateKey(ctx, &ca.Mixer{}, core.AlgEd25519, "dev")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := ca.NewRequest(k, core.CertSubject{Name: "Josh"}, core.CertKindDeveloper, now)
	_, chain, err := iss.Issue(req, ca.Account{DevID: "josh", TeamID: "T-josh", Role: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	return k, chain, core.ChainPolicy{Roots: []core.CARoot{root.Root()}, Now: now}, now
}

func TestLabelAndFilename(t *testing.T) {
	p := builder.Project{Name: "QuickLaunch", ID: "com.redx.quicklaunch", Version: "1.0.0", Channel: "beta"}
	if got := builder.Label(p, builder.PlatformMacArm64); got != "QuickLaunch Beta 1.0.0 (Mac, M1 chip)" {
		t.Fatalf("label %q", got)
	}
	if got := builder.Filename(p, builder.PlatformMacArm64); got != "quicklaunch-1.0.0-beta-macos-arm64.dmg" {
		t.Fatalf("filename %q", got)
	}
	// distinct filenames per platform
	seen := map[string]bool{}
	for _, pl := range builder.Platforms {
		n := builder.Filename(p, pl)
		if seen[n] {
			t.Fatalf("duplicate filename %q", n)
		}
		seen[n] = true
	}
}

func TestSigningDevicePolicy(t *testing.T) {
	// Mac signs only Mac and iOS; Windows signs only Windows and Android; Linux/extensions are host-neutral.
	want := map[string]map[string]bool{
		"darwin":  {builder.PlatformMacArm64: true, builder.PlatformMacIntel: true, builder.PlatformIOS: true, builder.PlatformWindows: false, builder.PlatformAndroid: false, builder.PlatformLinux: true, builder.PlatformExtensions: true},
		"windows": {builder.PlatformMacArm64: false, builder.PlatformMacIntel: false, builder.PlatformIOS: false, builder.PlatformWindows: true, builder.PlatformAndroid: true, builder.PlatformLinux: true, builder.PlatformExtensions: true},
	}
	for host, m := range want {
		for pl, ok := range m {
			if builder.CanSignOn(pl, host) != ok {
				t.Fatalf("CanSignOn(%s,%s)=%v, want %v", pl, host, !ok, ok)
			}
		}
	}
	if builder.DeviceFor(builder.PlatformWindows) != "a Windows device" || builder.DeviceFor(builder.PlatformIOS) != "a Mac" {
		t.Fatal("device wording")
	}
}

func TestSplitForHost(t *testing.T) {
	targets := []builder.Target{{Platform: builder.PlatformAndroid}, {Platform: builder.PlatformIOS}, {Platform: builder.PlatformMacArm64}, {Platform: builder.PlatformWindows}}
	b, d := builder.SplitForHost(targets, "darwin")
	if len(b) != 2 || b[0].Platform != builder.PlatformMacArm64 || b[1].Platform != builder.PlatformIOS {
		t.Fatalf("mac buildable %+v", b)
	}
	if len(d) != 2 || d[0].Platform != builder.PlatformWindows || d[1].Platform != builder.PlatformAndroid {
		t.Fatalf("mac deferred %+v", d)
	}
}

func TestSignFileHostRefusalAndRoundTrip(t *testing.T) {
	k, chain, pol, now := devKey(t)
	dir := t.TempDir()
	dmg := filepath.Join(dir, "quicklaunch-1.0.0-macos-arm64.dmg")
	os.WriteFile(dmg, []byte("fake mac disk image"), 0o644)
	// a Windows host must refuse a Mac asset
	if _, err := builder.SignFile(dmg, "com.redx.quicklaunch", "1.0.0", "", "windows", k, chain, now); err == nil {
		t.Fatal("Windows host signed a Mac asset")
	} else if _, ok := err.(*builder.ErrWrongHost); !ok {
		t.Fatalf("wrong error type %T", err)
	}
	// a Mac host signs it, writes .rasig and SHA256SUMS, and the signature verifies
	art, err := builder.SignFile(dmg, "com.redx.quicklaunch", "1.0.0", "", "darwin", k, chain, now)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := core.ParseFileSignature(mustReadFile(t, art.SigPath))
	if err != nil {
		t.Fatal(err)
	}
	if r := core.VerifyFileSignature(sig, art.SHA256, art.Bytes, pol, freshRev(t, now)); r.Status != core.SigValid {
		t.Fatalf("verify: %+v", r)
	}
	// SHA256SUMS lists the dmg with its real hash and not the .rasig
	sums := string(mustReadFile(t, filepath.Join(dir, "SHA256SUMS")))
	h := sha256.Sum256([]byte("fake mac disk image"))
	if want := hex.EncodeToString(h[:]) + "  " + filepath.Base(dmg) + "\n"; sums != want {
		t.Fatalf("SHA256SUMS = %q, want %q", sums, want)
	}
	// Windows and Android still need a Windows device from here
	if builder.DeviceFor(builder.PlatformAndroid) != "a Windows device" {
		t.Fatal("android device")
	}
}

func TestBuilderRunRefusesForeignTargetAndSignsNativeOnes(t *testing.T) {
	k, chain, pol, now := devKey(t)
	// prebuilt artifacts so no real build command runs
	src := t.TempDir()
	mk := func(n string) string {
		p := filepath.Join(src, n)
		os.WriteFile(p, []byte(n+" bytes"), 0o644)
		return p
	}
	out := t.TempDir()
	b := &builder.Builder{Signer: k, Chain: chain, OutDir: out, Host: "darwin", Now: func() time.Time { return now }}
	// contains a Windows target -> refused on a Mac host
	bad := &builder.Request{Schema: builder.RequestSchema, ID: "build-001", Project: builder.Project{Name: "QuickLaunch", ID: "com.redx.quicklaunch", Version: "1.0.0"},
		Targets: []builder.Target{{Platform: builder.PlatformMacArm64, Prebuilt: mk("a")}, {Platform: builder.PlatformWindows, Prebuilt: mk("b")}}}
	tg, _ := bad.Validate()
	if _, err := b.Run(context.Background(), bad, tg); err == nil {
		t.Fatal("Mac builder accepted a Windows target")
	}
	// only Mac/iOS targets -> builds, signs, writes SHA256SUMS
	good := &builder.Request{Schema: builder.RequestSchema, ID: "build-002", Project: builder.Project{Name: "QuickLaunch", ID: "com.redx.quicklaunch", Version: "1.0.0", Channel: "beta"},
		Targets: []builder.Target{{Platform: builder.PlatformIOS, Prebuilt: mk("ios")}, {Platform: builder.PlatformMacArm64, Prebuilt: mk("mac")}}}
	tg, _ = good.Validate()
	res, err := b.Run(context.Background(), good, tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 2 || res.Artifacts[0].Platform != builder.PlatformMacArm64 {
		t.Fatalf("order/count %+v", res.Artifacts)
	}
	for _, a := range res.Artifacts {
		if a.Label != builder.Label(good.Project, a.Platform) {
			t.Fatalf("label %q", a.Label)
		}
		sig, err := core.ParseFileSignature(mustReadFile(t, a.SigPath))
		if err != nil {
			t.Fatal(err)
		}
		if r := core.VerifyFileSignature(sig, a.SHA256, a.Bytes, pol, freshRev(t, now)); r.Status != core.SigValid {
			t.Fatalf("verify %s: %+v", a.Platform, r)
		}
	}
	if _, err := os.Stat(res.SumsPath); err != nil {
		t.Fatal("no SHA256SUMS")
	}
}

func freshRev(t *testing.T, now time.Time) *core.RevocationState {
	t.Helper()
	_, store, _ := ed25519.GenerateKey(nil)
	rl := &ca.RevocationList{}
	tk, err := rl.Ticket(store, now)
	if err != nil {
		t.Fatal(err)
	}
	st, err := core.VerifyStatusTicket([]ed25519.PublicKey{store.Public().(ed25519.PublicKey)}, tk)
	if err != nil {
		t.Fatal(err)
	}
	return &core.RevocationState{Ticket: st}
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIconForPlatform(t *testing.T) {
	root := "../assets/icons"
	cases := map[string]string{
		builder.PlatformMacArm64:   "AppIcon.icns",
		builder.PlatformMacIntel:   "AppIcon.icns",
		builder.PlatformIOS:        "AppIcon.icns",
		builder.PlatformWindows:    "AppIcon.ico",
		builder.PlatformLinux:      "icon-512.png",
		builder.PlatformAndroid:    "icon-512.png",
		builder.PlatformExtensions: "icon-128.png",
	}
	for _, product := range []string{builder.IconRottenCore, builder.IconPoisonApple} {
		for pl, want := range cases {
			got, err := builder.IconForPlatform(root, product, pl)
			if err != nil || filepathBase(got) != want {
				t.Fatalf("%s/%s -> %q %v", product, pl, got, err)
			}
		}
	}
	if _, err := builder.IconForPlatform(root, "nope", builder.PlatformWindows); err == nil {
		t.Fatal("missing product icon accepted")
	}
}

func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func TestBuilderContextGatesDeviceSDKAndSignsManifest(t *testing.T) {
	k, chain, pol, now := devKey(t)
	src := t.TempDir()
	mk := func(n string) string { p := filepath.Join(src, n); os.WriteFile(p, []byte(n), 0o644); return p }
	req := &builder.Request{Schema: builder.RequestSchema, ID: "build-ctx", Project: builder.Project{Name: "QuickLaunch", ID: "com.redx.quicklaunch", Version: "1.0.0"},
		Targets: []builder.Target{{Platform: builder.PlatformMacArm64, Prebuilt: mk("mac")}}, SDKs: []string{"analytics", "updates"}}
	tg, _ := req.Validate()
	macDev := &devhub.Device{Platform: devhub.PlatformMac, Approved: true, TeamID: "T-josh"}

	// no build API key -> the exact ErrNoBuildKey message
	b := &builder.Builder{Signer: k, Chain: chain, OutDir: t.TempDir(), Host: "darwin", Now: func() time.Time { return now },
		Context: &devhub.BuildContext{Role: "developer", TeamID: "T-josh", Device: macDev, SDKs: devhub.SDKSelection{Selected: []string{"analytics", "updates"}, Unlocked: []string{"analytics", "updates"}}}}
	if _, err := b.Run(context.Background(), req, tg); err != devhub.ErrNoBuildKey {
		t.Fatalf("missing build key: %v", err)
	}

	// an undeclared/unselected SDK is refused
	b.Context.BuildKey = "ra_sk_x"
	bad := *req
	bad.SDKs = []string{"corepay"}
	if _, err := b.Run(context.Background(), &bad, tg); err == nil {
		t.Fatal("unselected SDK built")
	}

	// a Windows target on a Mac device is refused by the device-platform rule (before the host check even)
	winReq := &builder.Request{Schema: builder.RequestSchema, ID: "build-win-01", Project: req.Project, Targets: []builder.Target{{Platform: builder.PlatformWindows, Prebuilt: mk("w")}}}
	winTg, _ := winReq.Validate()
	if _, err := b.Run(context.Background(), winReq, winTg); err == nil {
		t.Fatal("mac device built a windows target")
	}

	// happy path: builds, signs artifacts, writes a signed build manifest naming the SDKs and account
	res, err := b.Run(context.Background(), req, tg)
	if err != nil {
		t.Fatal(err)
	}
	if res.ManifestPath == "" {
		t.Fatal("no build manifest")
	}
	m, err := builder.VerifyBuildManifest(mustReadFile(t, res.ManifestPath), pol)
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	if m.DevicePlatform != "mac" || m.Account != "team T-josh" || len(m.SDKs) != 2 || m.SDKs[0] != "analytics" || m.SDKExempt {
		t.Fatalf("manifest: %+v", m)
	}
	if len(m.Artifacts) != 1 || m.Artifacts[0].Platform != builder.PlatformMacArm64 {
		t.Fatalf("manifest artifacts: %+v", m.Artifacts)
	}
}

func Testbuilder.PlatformFromName(t *testing.T) {
	cases := map[string]string{
		"rotten-apple-0.1.0-darwin-arm64.tar.gz": "macos-arm64",
		"rotten-apple-0.1.0-darwin-amd64.tar.gz": "macos-intel",
		"redx-0.4.5-macos-arm64.dmg":             "macos-arm64",
		"redx-0.4.5-macos-amd64.pkg":             "macos-intel",
		"redx-0.4.5-linux-amd64.tar.gz":          "linux",
		"redx_0.4.5_amd64.deb":                   "linux",
		"QuickLaunch-1.0.0-beta.1-darwin-x64.dmg": "macos-intel",
		"rotten-apple-extension-0.1.0.zip":       "extensions",
		"GenDragoon-Cloud-SSD-Mac-v0.18.0.zip":   "macos-intel",
		"install-macos.py":                      "macos-intel",
		"something-windows-x64.exe":              "windows",
		"app-android.apk":                        "android",
	}
	for name, want := range cases {
		if got := builder.PlatformFromName(name); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}
