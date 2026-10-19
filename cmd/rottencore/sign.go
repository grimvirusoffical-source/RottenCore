package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/builder"
	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
)

// Signing flags (set in main's flag set, read here).
var (
	signKey      string
	signBundle   string
	signApp      string
	signVersion  string
	signPlatform string
	signHost     string // override the detected host GOOS (tests / cross-check); default runtime.GOOS
	buildOut     string
	signKeychain bool   // load the signing key from the macOS Keychain instead of --key
	signLabel    string // Keychain account / label (e.g. josh-mega); used with --keychain
	signService  string // Keychain service (default com.redx.rottencore.ca)
)

// runSign handles `rottencore sign` and `rottencore build`. It returns false for anything else.
//
//	rottencore sign <file> (--key dev.key.json | --keychain --label josh-mega) --bundle dev.bundle.json --app com.redx.x --app-version 1.0.0 [--platform P]
//	rottencore build <request.json> (--key | --keychain --label) --bundle dev.bundle.json [--out DIR]
//
// Both enforce Josh's signing-device policy: a Mac signs only Mac and iOS assets; a Windows machine only
// Windows and Android assets. A refused asset names the device it needs.
func runSign(ctx context.Context, cmd string, rest []string) bool {
	switch cmd {
	case "sign":
		need(rest, 1)
		k, chain := loadSigner()
		host := signHost
		if host == "" {
			host = builder.HostOS()
		}
		art, err := builder.SignFile(rest[0], signApp, signVersion, signPlatform, host, k, chain, time.Now())
		if wh, ok := err.(*builder.ErrWrongHost); ok {
			fail(errors.New(wh.Error()), 4)
		}
		check(err)
		out(art, func() {
			fmt.Printf("signed %s (%s)\n  %s\n  SHA256SUMS regenerated in %s\n", art.Filename, builder.Label(builder.Project{Name: signApp, Version: signVersion}, art.Platform), art.SigPath, filepath.Dir(art.Path))
		})
	case "build-inbox":
		need(rest, 1)
		path := builder.InboxPath(core.SupportDir(), rest[0])
		rest = []string{path}
		fallthrough
	case "build":
		need(rest, 1)
		k, chain := loadSigner()
		req, targets, err := builder.ReadRequest(rest[0])
		check(err)
		if req.BuildAPIKey != "" {
			// QuickLaunch passed the build API key in the 0600 inbox file; expose it for this process only.
			_ = os.Setenv("RA_API_KEY", req.BuildAPIKey)
		}
		host := signHost
		if host == "" {
			host = builder.HostOS()
		}
		buildable, deferred := builder.SplitForHost(targets, host)
		if len(buildable) == 0 {
			fail(fmt.Errorf("none of these targets can be built and signed on this %s host", host), 4)
		}
		odir := buildOut
		if odir == "" {
			odir = filepath.Join(core.SupportDir(), "builds", req.ID)
		}
		bctx, cerr := buildContext()
		check(cerr)
		b := &builder.Builder{Signer: k, Chain: chain, OutDir: odir, Host: host, Context: bctx,
			IconsRoot: iconsRoot(), Emit: progressEmitter()}
		res, err := b.Run(ctx, req, buildable)
		check(err)
		out(map[string]interface{}{"result": res, "deferred": deferredList(deferred)}, func() {
			for _, a := range res.Artifacts {
				fmt.Printf("built %s -> %s\n", a.Label, a.Filename)
			}
			for _, d := range deferred {
				fmt.Printf("deferred %s: build and sign on %s\n", d.Platform, builder.DeviceFor(d.Platform))
			}
			fmt.Println("SHA256SUMS:", res.SumsPath)
		})
	default:
		return false
	}
	return true
}

func deferredList(d []builder.Target) []map[string]string {
	out := make([]map[string]string, 0, len(d))
	for _, t := range d {
		out = append(out, map[string]string{"platform": t.Platform, "needs": builder.DeviceFor(t.Platform)})
	}
	return out
}

func loadSigner() (core.Signer, []core.Cert) {
	if signBundle == "" {
		fail(errors.New("signing needs --bundle (make it with rottencore-ca)"), 2)
	}
	var (
		k   core.Signer
		err error
	)
	switch {
	case signKeychain:
		if signLabel == "" {
			fail(errors.New("signing with --keychain needs --label (e.g. josh-mega)"), 2)
		}
		if signKey != "" {
			fail(errors.New("pass either --keychain --label or --key, not both"), 2)
		}
		k, err = ca.KeychainStore{Service: signService}.Get(signLabel)
	case signKey != "":
		k, err = ca.ReadKey(signKey)
	default:
		fail(errors.New("signing needs --key <file> or --keychain --label <label> (and --bundle)"), 2)
	}
	check(err)
	b, err := ca.ReadBundle(signBundle)
	check(err)
	if len(b.Chain) == 0 {
		fail(errors.New("the certificate bundle has no chain"), 2)
	}
	return k, b.Chain
}

// iconsRoot locates the app-icon sets. ROTTENCORE_ICONS overrides; otherwise assets/icons beside the binary
// or the repo. "" (not found) disables icon embedding rather than failing a local build.
func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func iconsRoot() string {
	if v := envOr("ROTTENCORE_ICONS", ""); v != "" {
		return v
	}
	for _, c := range []string{"assets/icons", "../assets/icons"} {
		if dirExists(c) {
			return c
		}
	}
	return ""
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
