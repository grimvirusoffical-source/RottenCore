// Command rottencore-ca is the Red-XAI certificate generator for the ra-core CA path.
//
// By default it makes TEST roots (every certificate carries test:true and is refused by production
// verifiers). Pass --production to ceremony-root for a real root. Keys and bundles are written 0600
// through the ENCRYPTION-HOOKs in package ca (no encryption today). Entropy health is logged to stderr
// as JSON; samples never are.
//
//	rottencore-ca ceremony-root --out root.cert.json [--keychain --label L] [--production] [--mic] [--alg ed25519|p384]
//	rottencore-ca issuing-csr   --out csr.json [--keychain --label L] [--dir D] [--alg ed25519|p384]
//	rottencore-ca sign-intermediate --req csr.json --out bundle.json [--keychain --label root] --dir D
//	rottencore-ca init-root   --dir D [--mic] [--tiers tiers.json]           TEST root (P-384)
//	rottencore-ca intermediate --dir D [--mic]                              ra-core issuing CA under the root
//	rottencore-ca keygen      --out key.json --alg ed25519|p384 [--mic]     a developer/host key (local)
//	rottencore-ca request     --key key.json --name N [--kind developer|update-signer] --out req.json
//	rottencore-ca issue       --dir D --req req.json --dev ID --team T --role developer|owner|admin [--mega] --out bundle.json
//	rottencore-ca certify-host --dir D --pub BASE64 [--alg ed25519] --host NAME --team T --role owner --out chain.json
//	rottencore-ca revoke      --dir D --kind cert|build|app --value V
//	rottencore-ca root-hex    --dir D                                       hex of the root key (for --trust-test-root)
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "", "CA directory")
	mic := fs.Bool("mic", false, "add the microphone as an extra noise source (optional, never alone)")
	tiersPath := fs.String("tiers", "", "tiers JSON (magnitude overrides)")
	out := fs.String("out", "", "output file")
	alg := fs.String("alg", "ed25519", "ed25519 | p384")
	keyPath := fs.String("key", "", "key file")
	name := fs.String("name", "", "subject name")
	kind := fs.String("kind", core.CertKindDeveloper, "developer | update-signer")
	reqPath := fs.String("req", "", "request file")
	dev := fs.String("dev", "", "developer id")
	team := fs.String("team", "", "team id")
	role := fs.String("role", "developer", "developer | owner | admin")
	mega := fs.Bool("mega", false, "account holds a Mega license")
	pub := fs.String("pub", "", "host public key (base64)")
	host := fs.String("host", "", "host name")
	value := fs.String("value", "", "revocation value (revoke uses --kind cert|build|app)")
	keychain := fs.Bool("keychain", false, "store/load the key in the macOS login Keychain (Josh's Mac) instead of a file")
	label := fs.String("label", "", "key label in the keystore (Keychain account / file base name)")
	service := fs.String("service", "", "Keychain service name (default com.redx.rottencore.ca)")
	production := fs.Bool("production", false, "ceremony-root: make a PRODUCTION (non-TEST) root; omit for a TEST root")
	fs.Parse(os.Args[2:])
	ctx := context.Background()
	tiers, err := ca.LoadTiers(*tiersPath)
	check(err)
	mixer := &ca.Mixer{Sources: []ca.NoiseSource{ca.JitterNoise{}}, Log: func(h ca.Health) {
		b, _ := json.Marshal(map[string]interface{}{"entropyHealth": h})
		fmt.Fprintln(os.Stderr, string(b))
		audit(*dir, "entropy-health", h)
	}}
	if *mic {
		mixer.Sources = append(mixer.Sources, ca.MicrophoneNoise{})
	}
	switch cmd {
	case "init-root":
		need(*dir)
		a, _, err := ca.NewRoot(ctx, mixer, tiers, "Red-XAI TEST Root", true, time.Now())
		check(err)
		check(ca.WriteKey(filepath.Join(*dir, "root.key.json"), a.Key))
		check(ca.WriteBundle(filepath.Join(*dir, "root.bundle.json"), ca.CertBundle{Chain: a.Chain, KeyFile: "root.key.json", Tier: ca.TierRoot}))
		audit(*dir, "init-root", map[string]string{"fingerprint": a.Chain[0].Fingerprint(), "alg": a.Key.Alg()})
		fmt.Println("TEST root", a.Chain[0].Fingerprint())
	case "intermediate":
		need(*dir)
		root := load(*dir, "root", tiers, mixer)
		iss, _, err := root.IssueIntermediate(ctx, "ra-core TEST Issuing CA")
		check(err)
		check(ca.WriteKey(filepath.Join(*dir, "issuing.key.json"), iss.Key))
		check(ca.WriteBundle(filepath.Join(*dir, "issuing.bundle.json"), ca.CertBundle{Chain: iss.Chain, KeyFile: "issuing.key.json", Tier: ca.TierIssuing}))
		audit(*dir, "intermediate", map[string]string{"fingerprint": iss.Chain[0].Fingerprint()})
		fmt.Println("issuing CA", iss.Chain[0].Fingerprint())
	case "keygen":
		k, _, err := ca.GenerateKey(ctx, mixer, *alg, "local|"+*label+*out)
		check(err)
		if *keychain {
			need(*label)
			check(keystore(true, *dir, *service).Put(*label, k))
		} else {
			need(*out)
			check(ca.WriteKey(*out, k))
		}
		fmt.Println(*alg, "key", core.KeyFingerprint(k.Public()))
	case "request":
		need(*out)
		var k core.Signer
		var err error
		if *keychain {
			need(*label)
			k, err = keystore(true, *dir, *service).Get(*label)
		} else {
			need(*keyPath)
			k, err = ca.ReadKey(*keyPath)
		}
		check(err)
		r, err := ca.NewRequest(k, core.CertSubject{Name: *name}, *kind, time.Now())
		check(err)
		writeJSON(*out, r)
	case "issue":
		need(*dir, *reqPath, *out)
		iss := loadAuthority(*dir, "issuing", firstNonEmpty(*label, "rottencore-issuing"), *keychain, *service, tiers, mixer)
		var r ca.Request
		readJSON(*reqPath, &r)
		leaf, chain, err := iss.Issue(&r, ca.Account{DevID: *dev, TeamID: *team, Name: *name, Role: *role, Mega: *mega})
		check(err)
		check(ca.WriteBundle(*out, ca.CertBundle{Chain: chain, Tier: ca.TierForRole(*role, *mega)}))
		audit(*dir, "issue", map[string]string{"fingerprint": leaf.Fingerprint(), "team": *team, "dev": *dev, "alg": r.Alg})
		fmt.Println("issued", leaf.Fingerprint())
	case "certify-host":
		need(*dir, *pub, *host, *out)
		iss := loadAuthority(*dir, "issuing", firstNonEmpty(*label, "rottencore-issuing"), *keychain, *service, tiers, mixer)
		raw, err := base64.StdEncoding.DecodeString(*pub)
		check(err)
		leaf, chain, err := iss.IssueUpdateSigner(*alg, raw, *host, ca.Account{TeamID: *team, Role: *role})
		check(err)
		writeJSON(*out, chain)
		audit(*dir, "certify-host", map[string]string{"fingerprint": leaf.Fingerprint(), "host": *host})
		fmt.Println("host update key certified", leaf.Fingerprint(), "- serve this chain as \"chain\" in /v1/updates/keys")
	case "revoke":
		need(*dir, *value)
		k := *kind
		p := filepath.Join(*dir, "revocations.json")
		var l ca.RevocationList
		if b, err := os.ReadFile(p); err == nil {
			check(json.Unmarshal(b, &l))
		}
		check(l.Revoke(k, *value))
		writeJSON(p, l)
		audit(*dir, "revoke", map[string]string{"kind": k, "value": *value})
		fmt.Println("revocation list seq", l.Seq, "- ra-core publishes it in the next status ticket")
	case "ceremony-root":
		// Root key ceremony (run on Josh's Mac). Generates the root key where it lives (Keychain), mixes
		// optional microphone noise through HKDF, and exports ONLY the public root certificate. The private
		// key never leaves the keystore. Until the real ceremony this makes a TEST root.
		need(*out)
		lbl := firstNonEmpty(*label, "rottencore-root")
		tr := tiers
		if *alg != "" {
			tr = withAlg(tiers, ca.TierRoot, *alg)
		}
		rootName := "Red-XAI TEST Root"
		mode := "TEST"
		if *production {
			rootName = "Red-XAI Root"
			mode = "PRODUCTION"
		}
		a, _, err := ca.NewRoot(ctx, mixer, tr, rootName, !*production, time.Now())
		check(err)
		check(keystore(*keychain, *dir, *service).Put(lbl, a.Key))
		// export the public root certificate only (no key)
		writeJSON(*out, a.Chain[0])
		if *dir != "" {
			writeJSON(filepath.Join(*dir, "root.cert.json"), a.Chain[0])
		}
		audit(*dir, "ceremony-root", map[string]string{"fingerprint": a.Chain[0].Fingerprint(), "alg": a.Key.Alg(), "store": keystore(*keychain, *dir, *service).Kind(), "label": lbl, "mode": mode})
		fmt.Printf("%s root key stored in %s (label %q); public cert -> %s\n  %s\n", mode, keystore(*keychain, *dir, *service).Kind(), lbl, *out, a.Chain[0].Fingerprint())
	case "issuing-csr":
		// Generate the ra-core issuing key WHERE IT WILL LIVE and emit only a CSR for the root to sign.
		need(*out)
		lbl := firstNonEmpty(*label, "rottencore-issuing")
		t := tiers[ca.TierIssuing]
		a := *alg
		if a == "" {
			a = t.Alg
		}
		k, _, err := ca.GenerateKey(ctx, mixer, a, "issuing|"+lbl)
		check(err)
		check(keystore(*keychain, *dir, *service).Put(lbl, k))
		csr, err := ca.NewRequest(k, core.CertSubject{Name: "ra-core Issuing CA"}, core.CertKindCA, time.Now())
		check(err)
		writeJSON(*out, csr)
		fmt.Printf("issuing key stored in %s (label %q); CSR -> %s (send ONLY this to the root)\n", keystore(*keychain, *dir, *service).Kind(), lbl, *out)
	case "sign-intermediate":
		// On the root (Josh's Mac): sign an issuing-CA CSR. The root key stays in its keystore.
		need(*reqPath, *out)
		lbl := firstNonEmpty(*label, "rottencore-root")
		rk, err := keystore(*keychain, *dir, *service).Get(lbl)
		check(err)
		var rootCert core.Cert
		readJSON(filepath.Join(*dir, "root.cert.json"), &rootCert)
		tr := tiers
		if *alg != "" {
			tr = withAlg(tiers, ca.TierIssuing, *alg)
		}
		root := &ca.Authority{Key: rk, Chain: []core.Cert{rootCert}, Tiers: tr, Mixer: mixer, Test: rootCert.Test}
		var csr ca.Request
		readJSON(*reqPath, &csr)
		cert, _, err := root.SignIntermediateRequest(&csr, "ra-core Issuing CA")
		check(err)
		check(ca.WriteBundle(*out, ca.CertBundle{Chain: []core.Cert{*cert, rootCert}, Tier: ca.TierIssuing}))
		audit(*dir, "sign-intermediate", map[string]string{"fingerprint": cert.Fingerprint()})
		fmt.Println("issuing CA certified", cert.Fingerprint())
	case "root-hex":
		need(*dir)
		root := load(*dir, "root", tiers, mixer)
		fmt.Println(hex.EncodeToString(root.Chain[0].PublicKey))
	default:
		usage()
	}
}

func keystore(keychain bool, dir, service string) ca.KeyStore {
	if keychain {
		var trust []string
		// ROTTEN_KEYCHAIN_TRUST=colon-separated absolute binary paths for -T. NOTE (QA F2): reads go through
		// /usr/bin/security, so this does not authorise our binaries and items are not non-exportable; the
		// rollout leaves it unset (-T "", every read prompts: click Allow, never Always Allow). Paths are
		// validated in KeychainStore.Put (absolute, safe characters).
		for _, p := range strings.Split(os.Getenv("ROTTEN_KEYCHAIN_TRUST"), ":") {
			p = strings.TrimSpace(p)
			if p != "" {
				trust = append(trust, p)
			}
		}
		return ca.KeychainStore{Service: service, TrustedApps: trust}
	}
	return ca.FileStore{Dir: dir}
}

func load(dir, which string, tiers map[string]ca.Tier, m *ca.Mixer) *ca.Authority {
	return loadAuthority(dir, which, which, false, "", tiers, m)
}

// loadAuthority loads a CA: the public bundle always from <dir>/<which>.bundle.json, the private key
// either from the macOS Keychain (label) or from <dir>/<which>.key.json. The Keychain path is what
// tonight's Mac-hosted issuing CA uses (label rottencore-issuing); the public bundle later gets
// loaded into ra-core through the runbook process.
func loadAuthority(dir, which, label string, keychain bool, service string, tiers map[string]ca.Tier, m *ca.Mixer) *ca.Authority {
	b, err := ca.ReadBundle(filepath.Join(dir, which+".bundle.json"))
	check(err)
	var k core.Signer
	if keychain {
		k, err = keystore(true, dir, service).Get(label)
	} else {
		k, err = ca.ReadKey(filepath.Join(dir, which+".key.json"))
	}
	check(err)
	return &ca.Authority{Key: k, Chain: b.Chain, Tiers: tiers, Mixer: m, Test: b.Chain[0].Test}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func withAlg(t map[string]ca.Tier, tier, alg string) map[string]ca.Tier {
	out := map[string]ca.Tier{}
	for k, v := range t {
		out[k] = v
	}
	e := out[tier]
	e.Alg = alg
	out[tier] = e
	return out
}

func audit(dir, event string, v interface{}) {
	if dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]interface{}{"at": time.Now().UTC(), "event": event, "data": v})
	f.Write(append(b, '\n'))
}

func writeJSON(p string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	check(os.WriteFile(p, append(b, '\n'), 0o600))
}

func readJSON(p string, v interface{}) {
	b, err := os.ReadFile(p)
	check(err)
	check(json.Unmarshal(b, v))
}

func need(v ...string) {
	for _, s := range v {
		if s == "" {
			usage()
		}
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "rottencore-ca:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, errors.New("usage: rottencore-ca ceremony-root|issuing-csr|sign-intermediate|init-root|intermediate|keygen|request|issue|certify-host|revoke|root-hex [flags] (see source header)"))
	os.Exit(2)
}
