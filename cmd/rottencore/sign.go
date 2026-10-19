package main

import (
	"context"
	"errors"
	"fmt"
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
)

// runSign handles `rottencore sign` and `rottencore build`. It returns false for anything else.
//
//	rottencore sign <file> --key dev.key.json --bundle dev.bundle.json --app com.redx.x --app-version 1.0.0 [--platform P]
//	rottencore build <request.json> --key dev.key.json --bundle dev.bundle.json [--out DIR]
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
	case "build":
		need(rest, 1)
		k, chain := loadSigner()
		req, targets, err := builder.ReadRequest(rest[0])
		check(err)
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
		b := &builder.Builder{Signer: k, Chain: chain, OutDir: odir, Host: host, Emit: progressEmitter()}
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
	if signKey == "" || signBundle == "" {
		fail(errors.New("signing needs --key and --bundle (make them with rottencore-ca)"), 2)
	}
	k, err := ca.ReadKey(signKey)
	check(err)
	b, err := ca.ReadBundle(signBundle)
	check(err)
	if len(b.Chain) == 0 {
		fail(errors.New("the certificate bundle has no chain"), 2)
	}
	return k, b.Chain
}
