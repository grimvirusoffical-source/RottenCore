package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	case "sign-batch":
		// One Keychain read for the whole rollout (each read is an Allow prompt, QA F2).
		// <list.tsv>: one asset per line: path<TAB>app<TAB>version[<TAB>platform]
		need(rest, 1)
		jobs, err := readSignList(rest[0])
		check(err)
		k, chain := loadSigner()
		host := signHost
		if host == "" {
			host = builder.HostOS()
		}
		var arts []*builder.Artifact
		for _, j := range jobs {
			art, err := builder.SignFile(j[0], j[1], j[2], j[3], host, k, chain, time.Now())
			if wh, ok := err.(*builder.ErrWrongHost); ok {
				fail(fmt.Errorf("%s: %s", j[0], wh.Error()), 4)
			}
			if err != nil {
				fail(fmt.Errorf("%s: %w", j[0], err), 1)
			}
			arts = append(arts, art)
			if !o.json {
				fmt.Printf("signed %s -> %s\n", art.Path, art.SigPath)
			}
		}
		if o.json {
			out(arts, func() {})
		}
	case "signing":
		// `rottencore signing setup --bundle PATH --label LABEL` writes config.json signing so the
		// app hand-off works without hand-editing (QA v2 M1).
		need(rest, 1)
		sub := rest[0]
		if sub != "setup" {
			fail(fmt.Errorf("unknown signing subcommand %q (want setup)", sub), 2)
		}
		if signBundle == "" || signLabel == "" {
			fail(errors.New("signing setup needs --bundle PATH and --label LABEL (Keychain account)"), 2)
		}
		dir := core.SupportDir()
		cfg, err := core.LoadConfig(dir)
		check(err)
		cfg.Signing = &core.SigningConfig{Bundle: signBundle, Label: signLabel, Service: signService}
		check(core.SaveConfig(dir, cfg))
		out(cfg.Signing, func() {
			fmt.Printf("saved signing config\n  bundle: %s\n  label:  %s\n  file:   %s/config.json\n",
				signBundle, signLabel, dir)
		})
	case "build-inbox":
		need(rest, 1)
		req, targets, path, err := builder.OpenInboxRequest(core.SupportDir(), rest[0])
		check(err)
		if !o.yes {
			// N3: never start a URL-handed build without an explicit confirmation (the app shows a sheet).
			// --json (app confirm sheet) exits 0 with the filled-in commands (L5); interactive exits 2.
			prev := builder.MakePreview(req, targets, path)
			out(prev, func() {
				fmt.Printf("confirm build %s (%s %s) in %s — re-run with --yes after the user confirms\n",
					prev.ID, prev.App, prev.Version, prev.Dir)
			})
			if o.json {
				return true
			}
			fail(builder.ErrConfirmRequired, 2)
		}
		runBuild(ctx, req, targets, path)
	case "build":
		need(rest, 1)
		req, targets, err := builder.ReadRequest(rest[0])
		check(err)
		runBuild(ctx, req, targets, "")
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

// runBuild signs and builds. inboxPath, when set, is consumed (deleted) after the build so the request
// cannot be replayed; the scoped build API key is kept for Rotten Core's own API calls only and is never
// exported into child build processes (builder.scrubBuildEnv).
func runBuild(ctx context.Context, req *builder.Request, targets []builder.Target, inboxPath string) {
	// L2: always consume the inbox request (and drop the scoped key) on success *or* failure so a
	// failed build cannot leave the key sitting in the inbox for a retry attack.
	if inboxPath != "" {
		onExit(func() {
			_ = builder.ConsumeRequest(inboxPath)
			_ = os.Unsetenv("ROTTENCORE_BUILD_API_KEY")
		})
	}
	k, chain := loadSigner()
	if req.BuildAPIKey != "" {
		// Scoped build key for our own API calls (dev-hub / uploader). Not exported to build commands.
		_ = os.Setenv("ROTTENCORE_BUILD_API_KEY", req.BuildAPIKey)
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
	if bctx != nil && req.BuildAPIKey != "" {
		bctx.BuildKey = req.BuildAPIKey
	}
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
}

// readSignList parses a sign-batch list: path<TAB>app<TAB>version[<TAB>platform]; # comments allowed.
func readSignList(path string) ([][4]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jobs [][4]string
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || len(f) > 4 || f[0] == "" || f[1] == "" || f[2] == "" {
			return nil, fmt.Errorf("%s:%d: want path<TAB>app<TAB>version[<TAB>platform]", path, i+1)
		}
		if !filepath.IsAbs(f[0]) {
			return nil, fmt.Errorf("%s:%d: asset path must be absolute", path, i+1)
		}
		var j [4]string
		copy(j[:], f)
		jobs = append(jobs, j)
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("%s: no assets listed", path)
	}
	return jobs, nil
}

// applySigningDefaults fills --bundle/--label/--service from config.json or signing.json when flags are empty
// so a Finder- or URL-launched app (no shell env) still finds the signing identity (QA v2 N2).
func applySigningDefaults() {
	if signBundle != "" && (signLabel != "" || signKey != "") {
		return
	}
	dir := core.SupportDir()
	if cfg, err := core.LoadConfig(dir); err == nil && cfg.Signing != nil {
		if signBundle == "" {
			signBundle = cfg.Signing.Bundle
		}
		if signLabel == "" {
			signLabel = cfg.Signing.Label
		}
		if signService == "" {
			signService = cfg.Signing.Service
		}
	}
	if signBundle == "" || signLabel == "" {
		if b, err := os.ReadFile(filepath.Join(dir, "signing.json")); err == nil {
			var sc core.SigningConfig
			if json.Unmarshal(b, &sc) == nil {
				if signBundle == "" {
					signBundle = sc.Bundle
				}
				if signLabel == "" {
					signLabel = sc.Label
				}
				if signService == "" {
					signService = sc.Service
				}
			}
		}
	}
	if signLabel == "" {
		// Device registration may record the Keychain label.
		if b, err := os.ReadFile(filepath.Join(dir, "devhub", "device.json")); err == nil {
			var d map[string]interface{}
			if json.Unmarshal(b, &d) == nil {
				for _, k := range []string{"keychainLabel", "label"} {
					if v, ok := d[k].(string); ok && v != "" {
						signLabel = v
						break
					}
				}
			}
		}
	}
}

func loadSigner() (core.Signer, []core.Cert) {
	applySigningDefaults()
	if signBundle == "" {
		fail(errors.New("signing is not set up: pass --bundle, or save signing.bundle in Rotten Core's config.json (or signing.json in the support dir)"), 2)
	}
	var (
		k   core.Signer
		err error
	)
	switch {
	case signKeychain || (signLabel != "" && signKey == ""):
		if signLabel == "" {
			fail(errors.New("signing with the Keychain needs --label (e.g. josh-mega), or signing.label in config.json"), 2)
		}
		if signKey != "" {
			fail(errors.New("pass either --keychain --label or --key, not both"), 2)
		}
		signKeychain = true
		k, err = ca.KeychainStore{Service: signService}.Get(signLabel)
	case signKey != "":
		k, err = ca.ReadKey(signKey)
	default:
		fail(errors.New("signing needs --key <file> or --keychain --label <label> (and --bundle); or save them under signing in config.json"), 2)
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
