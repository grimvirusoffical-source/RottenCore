package ca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

func TestMixerAlwaysNeedsOSRandomAndOnlyAddsNoise(t *testing.T) {
	ctx := context.Background()
	if _, _, err := (&Mixer{OS: failReader{}, Sources: []NoiseSource{JitterNoise{}}}).Material(ctx, "x", 32); !errors.Is(err, ErrNoOSRandom) {
		t.Fatal("noise must never replace the OS CSPRNG")
	}
	fixedOS := func() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{7}, 64)) }
	noise := func(b byte) NoiseSource {
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = byte(i*131) ^ b
		}
		return ReaderNoise{Label: "test", R: bytes.NewReader(buf)}
	}
	a, h, _ := (&Mixer{OS: fixedOS(), Sources: []NoiseSource{noise(1)}}).Material(ctx, "x", 32)
	b, _, _ := (&Mixer{OS: fixedOS(), Sources: []NoiseSource{noise(2)}}).Material(ctx, "x", 32)
	c, _, _ := (&Mixer{OS: fixedOS()}).Material(ctx, "x", 32)
	if bytes.Equal(a, b) || bytes.Equal(a, c) || !h[0].Used {
		t.Fatal("healthy noise must change the material")
	}
	// tampered noise (constant) fails health and is not used: same as no noise at all
	stuck := ReaderNoise{Label: "stuck", R: bytes.NewReader(make([]byte, 4096))}
	var logged []Health
	d, h2, err := (&Mixer{OS: fixedOS(), Sources: []NoiseSource{stuck}, Log: func(x Health) { logged = append(logged, x) }}).Material(ctx, "x", 32)
	if err != nil || h2[0].OK || h2[0].Used || !bytes.Equal(d, c) || len(logged) != 1 || !strings.Contains(logged[0].Problem, "repetition") {
		t.Fatalf("stuck noise: %+v", h2)
	}
	// a missing microphone is skipped, keygen continues
	_, h3, err := (&Mixer{Sources: []NoiseSource{MicrophoneNoise{Command: []string{"/nonexistent/recorder"}}, JitterNoise{}}}).Material(ctx, "x", 32)
	if err != nil || h3[0].Used || h3[0].Problem == "" {
		t.Fatalf("mic: %+v %v", h3, err)
	}
	// jitter health is reported (whatever the outcome); reports never contain samples
	if h3[1].Bytes != 4096 {
		t.Fatalf("%+v", h3[1])
	}
}

func TestHKDFRFC5869Shape(t *testing.T) {
	a := hkdfSHA512([]byte("ikm"), []byte("salt"), []byte("info"), 100)
	b := hkdfSHA512([]byte("ikm"), []byte("salt"), []byte("info2"), 100)
	if len(a) != 100 || bytes.Equal(a[:32], b[:32]) || !bytes.Equal(a[:64], hkdfSHA512([]byte("ikm"), []byte("salt"), []byte("info"), 64)) {
		t.Fatal("hkdf")
	}
}

func testAuthority(t *testing.T) (*Authority, *Authority, time.Time) {
	ctx := context.Background()
	now := time.Now()
	m := &Mixer{Sources: []NoiseSource{JitterNoise{}}, Samples: 1024}
	root, _, err := NewRoot(ctx, m, DefaultTiers(), "Red-XAI TEST Root", true, now)
	if err != nil {
		t.Fatal(err)
	}
	iss, _, err := root.IssueIntermediate(ctx, "ra-core TEST Issuing")
	if err != nil {
		t.Fatal(err)
	}
	return root, iss, now
}

func TestMagnitudeTiersAndChains(t *testing.T) {
	ctx := context.Background()
	root, iss, now := testAuthority(t)
	if root.Key.Alg() != core.AlgP384 || iss.Key.Alg() != core.AlgP384 {
		t.Fatal("root and issuing must be P-384")
	}
	pol := core.ChainPolicy{Roots: []core.CARoot{root.Root()}, Now: now}
	m := &Mixer{}
	cases := []struct {
		acct Account
		alg  string
	}{
		{Account{DevID: "d1", TeamID: "T1", Role: "developer"}, core.AlgEd25519},
		{Account{DevID: "josh", TeamID: "T-josh", Role: "developer", Mega: true}, core.AlgP384},
		{Account{DevID: "o", TeamID: "T-own", Role: "owner"}, core.AlgP384},
		{Account{DevID: "a", TeamID: "T-adm", Role: "admin"}, core.AlgP384},
	}
	for _, tc := range cases {
		k, _, err := GenerateKey(ctx, m, tc.alg, "dev")
		if err != nil {
			t.Fatal(err)
		}
		req, _ := NewRequest(k, core.CertSubject{Name: "x"}, core.CertKindDeveloper, now)
		leaf, chain, err := iss.Issue(req, tc.acct)
		if err != nil {
			t.Fatalf("%+v: %v", tc.acct, err)
		}
		if got, err := core.VerifyCertChain(chain, pol); err != nil || got.Subject.TeamID != tc.acct.TeamID || !got.Test {
			t.Fatalf("%+v: chain %v", tc.acct, err)
		}
		days := (leaf.NotAfter - leaf.NotBefore) / 86400
		if want := int64(DefaultTiers()[TierForRole(tc.acct.Role, tc.acct.Mega)].ValidityDays); days != want {
			t.Fatalf("validity %d, want %d", days, want)
		}
		// a file signed with this key verifies end to end
		d := core.FileSigDoc{AppID: "com.redx.app", Version: "1.0.0"}
		d.Artifact.Name, d.Artifact.Kind, d.Artifact.SHA256, d.Artifact.Bytes = "a.dmg", "dmg", strings.Repeat("a", 64), 1
		sig, _ := core.SignFileDocWith(k, chain, d)
		_, store, _ := ed25519.GenerateKey(nil)
		rl := &RevocationList{}
		tk, _ := rl.Ticket(store, now)
		st, _ := core.VerifyStatusTicket([]ed25519.PublicKey{store.Public().(ed25519.PublicKey)}, tk)
		if r := core.VerifyFileSignature(sig, d.Artifact.SHA256, 1, pol, &core.RevocationState{Ticket: st}); r.Status != core.SigValid {
			t.Fatalf("%+v", r)
		}
		// revocation list update with this (Ed25519 or P-384) cert
		rl.Revoke("cert", chain[0].Fingerprint())
		tk, _ = rl.Ticket(store, now)
		st, _ = core.VerifyStatusTicket([]ed25519.PublicKey{store.Public().(ed25519.PublicKey)}, tk)
		if r := core.VerifyFileSignature(sig, d.Artifact.SHA256, 1, pol, &core.RevocationState{Ticket: st}); r.Status != core.SigRevoked {
			t.Fatalf("revoked %s cert accepted", tc.alg)
		}
	}
	// wrong key type for the tier, forged proof of possession, wrong kind
	k, _, _ := GenerateKey(ctx, m, core.AlgEd25519, "x")
	req, _ := NewRequest(k, core.CertSubject{}, core.CertKindDeveloper, now)
	if _, _, err := iss.Issue(req, Account{Role: "owner"}); err == nil {
		t.Fatal("owner tier issued an Ed25519 cert")
	}
	req.Subject.Name = "changed after signing"
	if _, _, err := iss.Issue(req, Account{Role: "developer"}); err == nil {
		t.Fatal("bad proof of possession accepted")
	}
	// production verifiers refuse the TEST CA
	pol.Production = true
	req, _ = NewRequest(k, core.CertSubject{}, core.CertKindDeveloper, now)
	_, chain, _ := iss.Issue(req, Account{Role: "developer"})
	if _, err := core.VerifyCertChain(chain, pol); err == nil {
		t.Fatal("TEST chain accepted in production")
	}
}

func TestHostUpdateSignerCert(t *testing.T) {
	_, iss, now := testAuthority(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := iss.IssueUpdateSigner(core.AlgEd25519, pub, "redx.example", Account{Role: "developer"}); err == nil {
		t.Fatal("developer certified a host key")
	}
	leaf, chain, err := iss.IssueUpdateSigner(core.AlgEd25519, pub, "redx.example", Account{Role: "owner", TeamID: "T-redx"})
	if err != nil || leaf.Kind != core.CertKindUpdateSigner {
		t.Fatal(err)
	}
	pol := core.ChainPolicy{Roots: []core.CARoot{{Alg: core.AlgP384, PublicKey: iss.Chain[len(iss.Chain)-1].PublicKey, Test: true}}, Now: now, LeafKind: core.CertKindUpdateSigner}
	if _, err := core.VerifyCertChain(chain, pol); err != nil {
		t.Fatal(err)
	}
}

func TestKeyAndBundleFilesRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for _, alg := range []string{core.AlgEd25519, core.AlgP384} {
		k, _, _ := GenerateKey(ctx, &Mixer{}, alg, "f")
		p := filepath.Join(dir, alg+".key.json")
		if err := WriteKey(p, k); err != nil {
			t.Fatal(err)
		}
		if err := WriteKey(p, k); err == nil {
			t.Fatal("key file overwritten")
		}
		k2, err := ReadKey(p)
		if err != nil || !bytes.Equal(k2.Public(), k.Public()) {
			t.Fatal(err)
		}
		msg := []byte("m")
		s, _ := k2.Sign(msg)
		if !core.VerifySig(alg, k.Public(), msg, s) {
			t.Fatal("reloaded key does not sign")
		}
	}
	_, iss, _ := testAuthority(t)
	bp := filepath.Join(dir, "b.json")
	if err := WriteBundle(bp, CertBundle{Chain: iss.Chain, Tier: TierIssuing}); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadBundle(bp); err != nil || len(b.Chain) != 2 {
		t.Fatal(err)
	}
}

func TestIntermediateFromCSRKeepsKeyWhereItLives(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	root, _, err := NewRoot(ctx, &Mixer{}, DefaultTiers(), "Red-XAI TEST Root", true, now)
	if err != nil {
		t.Fatal(err)
	}
	// the issuing key is made where ra-core will run; only a CSR goes to the root
	issKey, _, err := GenerateKey(ctx, &Mixer{}, DefaultTiers()[TierIssuing].Alg, "issuing")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewRequest(issKey, core.CertSubject{Name: "ra-core TEST Issuing"}, core.CertKindCA, now)
	if err != nil {
		t.Fatal(err)
	}
	issCert, _, err := root.SignIntermediateRequest(csr, "ra-core TEST Issuing")
	if err != nil {
		t.Fatal(err)
	}
	// the issuing authority holds its own key (never sent to the root) plus the signed cert
	iss := &Authority{Key: issKey, Chain: []core.Cert{*issCert, root.Chain[0]}, Tiers: DefaultTiers(), Mixer: &Mixer{}, Test: true}
	devKey, _, _ := GenerateKey(ctx, &Mixer{}, core.AlgEd25519, "dev")
	req, _ := NewRequest(devKey, core.CertSubject{Name: "Dev"}, core.CertKindDeveloper, now)
	_, chain, err := iss.Issue(req, Account{DevID: "d", TeamID: "T", Role: "developer"})
	if err != nil {
		t.Fatal(err)
	}
	pol := core.ChainPolicy{Roots: []core.CARoot{root.Root()}, Now: now}
	if _, err := core.VerifyCertChain(chain, pol); err != nil {
		t.Fatalf("chain from a CSR-signed intermediate did not verify: %v", err)
	}
	// a request that is not a CA CSR is refused as an intermediate
	if _, _, err := root.SignIntermediateRequest(req, "x"); err == nil {
		t.Fatal("a developer CSR was accepted as an intermediate")
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	fs := FileStore{Dir: t.TempDir()}
	if fs.Kind() != "file" {
		t.Fatal("kind")
	}
	k, _, _ := GenerateKey(context.Background(), &Mixer{}, core.AlgEd25519, "x")
	if err := fs.Put("root", k); err != nil {
		t.Fatal(err)
	}
	if err := fs.Put("root", k); err == nil {
		t.Fatal("store overwrote an existing key")
	}
	got, err := fs.Get("root")
	if err != nil || string(got.Public()) != string(k.Public()) {
		t.Fatal(err)
	}
}
