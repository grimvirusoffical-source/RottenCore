package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vector struct {
	RootPub      string   `json:"rootPub"`
	StorePub     string   `json:"storePub"`
	DevSeed      string   `json:"devSeed"`
	Chain        []Cert   `json:"chain"`
	Fingerprints []string `json:"fingerprints"`
	Status       *Signed  `json:"status"`
	NowUnix      int64    `json:"nowUnix"`
}

func loadVector(t *testing.T) *vector {
	t.Helper()
	b, err := os.ReadFile("testdata/rarxai_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func b64key(t *testing.T, s string) ed25519.PublicKey {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatal("bad key in vector")
	}
	return k
}

// The store's own code (rarxai) made this chain and ticket; RottenCore must accept them byte for byte.
func TestRarxaiCompatVector(t *testing.T) {
	v := loadVector(t)
	now := time.Unix(v.NowUnix, 0)
	pol := ChainPolicy{Roots: []CARoot{{Name: "test", PublicKey: b64key(t, v.RootPub), Test: true}}, Now: now}
	leaf, err := VerifyCertChain(v.Chain, pol)
	if err != nil {
		t.Fatalf("chain from rarxai rejected: %v", err)
	}
	if leaf.Subject.TeamID != "T1" {
		t.Fatalf("leaf = %+v", leaf.Subject)
	}
	for i := range v.Chain {
		if got := v.Chain[i].Fingerprint(); got != v.Fingerprints[i] {
			t.Fatalf("fingerprint %d = %s, rarxai says %s", i, got, v.Fingerprints[i])
		}
	}
	tk, err := VerifyStatusTicket([]ed25519.PublicKey{b64key(t, v.StorePub)}, v.Status)
	if err != nil {
		t.Fatalf("status ticket from rarxai rejected: %v", err)
	}
	if len(tk.RevokedApps) != 1 || tk.RevokedApps[0] != "com.bad.app" || len(tk.MegaApps) != 1 {
		t.Fatalf("ticket = %+v", tk)
	}
	// Production mode refuses the test chain.
	pol.Production = true
	if _, err := VerifyCertChain(v.Chain, pol); err == nil {
		t.Fatal("production policy accepted a test chain")
	}
}

type pki struct {
	root, inter, dev ed25519.PrivateKey
	chain            []Cert
	pol              ChainPolicy
}

func newPKI(t *testing.T, now time.Time) *pki {
	t.Helper()
	gen := func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(nil); return k }
	p := &pki{root: gen(), inter: gen(), dev: gen()}
	ic := Cert{Serial: "i1", Kind: CertKindCA, PublicKey: p.inter.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour * 24 * 365).Unix(), Test: true}
	if err := SignCert(&ic, p.root); err != nil {
		t.Fatal(err)
	}
	dc := Cert{Serial: "d1", Kind: CertKindDeveloper, Subject: CertSubject{Name: "Josh (Mega)", TeamID: "T-josh", DevID: "dev-1"}, PublicKey: p.dev.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour * 24 * 30).Unix(), Test: true}
	if err := SignCert(&dc, p.inter); err != nil {
		t.Fatal(err)
	}
	p.chain = []Cert{dc, ic}
	p.pol = ChainPolicy{Roots: []CARoot{{Name: "test", PublicKey: p.root.Public().(ed25519.PublicKey), Test: true}}, Now: now}
	return p
}

func (p *pki) sign(t *testing.T, app, sum string, size int64) *FileSignature {
	d := FileSigDoc{AppID: app, Version: "1.0.0", SignedMs: 1}
	d.Artifact.Name, d.Artifact.Kind, d.Artifact.SHA256, d.Artifact.Bytes = "x.dmg", "dmg", sum, size
	s, err := SignFileDoc(p.dev, p.chain, d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ticket(t *testing.T, store ed25519.PrivateKey, now time.Time, st StatusTicket) *RevocationState {
	st.IssuedMs, st.ExpiresMs = now.UnixMilli(), now.Add(StatusTicketTTL).UnixMilli()
	s, err := SignStatusTicket(store, st)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := VerifyStatusTicket([]ed25519.PublicKey{store.Public().(ed25519.PublicKey)}, s)
	if err != nil {
		t.Fatal(err)
	}
	return &RevocationState{Ticket: tk}
}

const sumA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestFileSignatureDecisions(t *testing.T) {
	now := time.Unix(1800000000, 0)
	p := newPKI(t, now)
	_, store, _ := ed25519.GenerateKey(nil)
	clean := ticket(t, store, now, StatusTicket{})
	sig := p.sign(t, "com.redx.app", sumA, 100)

	if r := VerifyFileSignature(sig, sumA, 100, p.pol, clean); r.Status != SigValid || !r.Trusted() || r.Revocation != "fresh" || r.Signer.TeamID != "T-josh" {
		t.Fatalf("valid: %+v", r)
	}
	if r := VerifyFileSignature(nil, sumA, 100, p.pol, clean); r.Status != SigNone {
		t.Fatalf("none: %+v", r)
	}
	if r := VerifyFileSignature(sig, strings.Repeat("b", 64), 100, p.pol, clean); r.Status != SigInvalid {
		t.Fatalf("other bytes: %+v", r)
	}
	if r := VerifyFileSignature(sig, sumA, 101, p.pol, clean); r.Status != SigInvalid {
		t.Fatalf("other size: %+v", r)
	}
	// Foreign root.
	other := newPKI(t, now)
	if r := VerifyFileSignature(sig, sumA, 100, other.pol, clean); r.Status != SigInvalid {
		t.Fatalf("foreign root: %+v", r)
	}
	// Production refuses test certs.
	prod := p.pol
	prod.Production = true
	if r := VerifyFileSignature(sig, sumA, 100, prod, clean); r.Status != SigInvalid {
		t.Fatalf("production/test: %+v", r)
	}
	// Expired leaf.
	late := p.pol
	late.Now = now.Add(60 * 24 * time.Hour)
	if r := VerifyFileSignature(sig, sumA, 100, late, clean); r.Status != SigInvalid {
		t.Fatalf("expired: %+v", r)
	}
	// Tampered doc and chain swap (another dev's cert with this signature).
	bad := *sig
	bad.Doc = base64.StdEncoding.EncodeToString([]byte(`{"v":1}`))
	if r := VerifyFileSignature(&bad, sumA, 100, p.pol, clean); r.Status != SigInvalid {
		t.Fatalf("tampered doc: %+v", r)
	}
	swap := *sig
	swap.Chain = other.chain
	if r := VerifyFileSignature(&swap, sumA, 100, other.pol, clean); r.Status != SigInvalid {
		t.Fatalf("chain swap: %+v", r)
	}
	// A cert-chain signature cannot be replayed as a status ticket or vice versa (domains differ).
	if _, err := VerifyStatusTicket([]ed25519.PublicKey{p.dev.Public().(ed25519.PublicKey)}, &Signed{Doc: sig.Doc, Key: KeyFingerprint(p.dev.Public().(ed25519.PublicKey)), Sig: sig.Sig}); err == nil {
		t.Fatal("file signature accepted as a status ticket")
	}
}

func TestRevocation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	p := newPKI(t, now)
	_, store, _ := ed25519.GenerateKey(nil)
	sig := p.sign(t, "com.redx.app", sumA, 100)
	leafFP, interFP := p.chain[0].Fingerprint(), p.chain[1].Fingerprint()

	for name, st := range map[string]StatusTicket{
		"leaf":  {RevokedCerts: []string{leafFP}},
		"inter": {RevokedCerts: []string{interFP}},
		"app":   {RevokedApps: []string{"com.redx.app"}},
		"build": {RevokedBuilds: []string{"sha256:" + sumA}},
	} {
		if r := VerifyFileSignature(sig, sumA, 100, p.pol, ticket(t, store, now, st)); r.Status != SigRevoked || !r.Refuse() {
			t.Fatalf("%s revoked: %+v", name, r)
		}
	}
	clean := ticket(t, store, now, StatusTicket{})
	// Offline: inside the 7-day grace still valid, after it unverifiable, never valid.
	g := p.pol
	g.Now = now.Add(StatusTicketTTL + 24*time.Hour)
	if r := VerifyFileSignature(sig, sumA, 100, g, clean); r.Status != SigValid || r.Revocation != "grace" {
		t.Fatalf("grace: %+v", r)
	}
	g.Now = now.Add(StatusTicketTTL + StatusOfflineGrace + time.Minute)
	if r := VerifyFileSignature(sig, sumA, 100, g, clean); r.Status != SigUnverifiable || r.Trusted() {
		t.Fatalf("stale: %+v", r)
	}
	if r := VerifyFileSignature(sig, sumA, 100, p.pol, nil); r.Status != SigUnverifiable {
		t.Fatalf("no list: %+v", r)
	}
	// A stale list still revokes.
	old := ticket(t, store, now, StatusTicket{RevokedCerts: []string{leafFP}})
	if r := VerifyFileSignature(sig, sumA, 100, g, old); r.Status != SigRevoked {
		t.Fatalf("stale revoke: %+v", r)
	}
}

func TestRevocationCache(t *testing.T) {
	now := time.Now()
	_, store, _ := ed25519.GenerateKey(nil)
	_, evil, _ := ed25519.GenerateKey(nil)
	c := &RevocationCache{Path: filepath.Join(t.TempDir(), "status-ticket.json"), Pins: []ed25519.PublicKey{store.Public().(ed25519.PublicKey)}}
	if s := c.Load(); s.Ticket != nil || s.Freshness(now) != "none" {
		t.Fatal("empty cache has a ticket")
	}
	mk := func(k ed25519.PrivateKey, at time.Time, revoked ...string) *Signed {
		s, err := SignStatusTicket(k, StatusTicket{IssuedMs: at.UnixMilli(), ExpiresMs: at.Add(StatusTicketTTL).UnixMilli(), RevokedCerts: revoked})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	fp := "sha256:" + sumA
	if s, err := c.Store(mk(store, now, fp)); err != nil || s.Ticket == nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(c.Path); st.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %v", st.Mode())
	}
	// An older ticket (replay) cannot replace the newer one and un-revoke.
	if s, _ := c.Store(mk(store, now.Add(-time.Hour))); len(s.Ticket.RevokedCerts) != 1 {
		t.Fatal("older ticket replaced the cache")
	}
	// A ticket from an unpinned key is refused and the cache kept.
	if _, err := c.Store(mk(evil, now.Add(time.Hour))); err == nil {
		t.Fatal("unpinned ticket accepted")
	}
	if s := c.Load(); len(s.Ticket.RevokedCerts) != 1 {
		t.Fatal("cache lost")
	}
	// Tampered file on disk -> treated as no list.
	os.WriteFile(c.Path, []byte(`{"doc":"e30=","key":"x","sig":"y"}`), 0o600)
	if s := c.Load(); s.Ticket != nil {
		t.Fatal("tampered cache accepted")
	}
}

func TestNoProductionRootsPinnedYet(t *testing.T) {
	if len(PinnedCARoots) != 0 || len(PinnedUpdateKeyFingerprints) != 0 {
		t.Fatal("production keys must be pinned deliberately, with a release note; update this test when that happens")
	}
}
