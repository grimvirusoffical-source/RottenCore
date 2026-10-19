// Command rottencore-ca is the Red-XAI certificate generator for the ra-core CA path.
//
// Until Josh's root ceremony it only makes TEST roots (every certificate carries test:true and is refused
// by production verifiers). Keys and bundles are written 0600 through the ENCRYPTION-HOOKs in package ca
// (no encryption today). Entropy health is logged to stderr as JSON; samples never are.
//
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
		need(*out)
		k, _, err := ca.GenerateKey(ctx, mixer, *alg, "local|"+*out)
		check(err)
		check(ca.WriteKey(*out, k))
		fmt.Println(*alg, "key", core.KeyFingerprint(k.Public()))
	case "request":
		need(*keyPath, *out)
		k, err := ca.ReadKey(*keyPath)
		check(err)
		r, err := ca.NewRequest(k, core.CertSubject{Name: *name}, *kind, time.Now())
		check(err)
		writeJSON(*out, r)
	case "issue":
		need(*dir, *reqPath, *out)
		iss := load(*dir, "issuing", tiers, mixer)
		var r ca.Request
		readJSON(*reqPath, &r)
		leaf, chain, err := iss.Issue(&r, ca.Account{DevID: *dev, TeamID: *team, Name: *name, Role: *role, Mega: *mega})
		check(err)
		check(ca.WriteBundle(*out, ca.CertBundle{Chain: chain, Tier: ca.TierForRole(*role, *mega)}))
		audit(*dir, "issue", map[string]string{"fingerprint": leaf.Fingerprint(), "team": *team, "dev": *dev, "alg": r.Alg})
		fmt.Println("issued", leaf.Fingerprint())
	case "certify-host":
		need(*dir, *pub, *host, *out)
		iss := load(*dir, "issuing", tiers, mixer)
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
	case "root-hex":
		need(*dir)
		root := load(*dir, "root", tiers, mixer)
		fmt.Println(hex.EncodeToString(root.Chain[0].PublicKey))
	default:
		usage()
	}
}

func load(dir, which string, tiers map[string]ca.Tier, m *ca.Mixer) *ca.Authority {
	b, err := ca.ReadBundle(filepath.Join(dir, which+".bundle.json"))
	check(err)
	k, err := ca.ReadKey(filepath.Join(dir, which+".key.json"))
	check(err)
	return &ca.Authority{Key: k, Chain: b.Chain, Tiers: tiers, Mixer: m, Test: b.Chain[0].Test}
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
	fmt.Fprintln(os.Stderr, errors.New("usage: rottencore-ca init-root|intermediate|keygen|request|issue|certify-host|revoke|root-hex [flags] (see source header)"))
	os.Exit(2)
}
