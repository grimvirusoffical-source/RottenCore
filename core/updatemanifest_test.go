package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const manifestJSON = `{
  "schema": "redx.update-manifest/v1",
  "app": "redx",
  "version": "0.4.5",
  "channel": "stable",
  "published_at": "2026-10-19T18:00:00Z",
  "sequence": 42,
  "source": {
    "kind": "host",
    "github": { "repo": "grimvirusoffical-source/RedX", "tag": "v0.4.5", "commit": "d7dc555bb335af43f01293f08457868fa23c232a", "release_id": 0 },
    "host": { "build_id": "hb_1", "commit": "d7dc555bb335af43f01293f08457868fa23c232a" }
  },
  "outcome": { "tags": ["+security", "+perf", "-breaking"], "summary": "Faster sync", "risk": { "score": 0.18, "level": "low", "reasons": ["small"] }, "changelog_md": "..." },
  "requires": { "min_from": "0.4.0", "restart": true, "migrations": ["accounts-v1"] },
  "artifacts": [
    { "id": "macos-universal-dmg", "label": "RedX 0.4.5 (Mac, Universal)", "os": "macos", "arch": "universal", "kind": "dmg", "filename": "redx-0.4.5-macos-universal.dmg", "url": "https://github.com/x/redx-0.4.5-macos-universal.dmg", "mirrors": [], "size": 20, "sha256": "` + sumA + `", "delta_from": null },
    { "id": "macos-arm64-dmg", "label": "RedX 0.4.5 (Mac, M1 chip)", "os": "macos", "arch": "arm64", "kind": "dmg", "filename": "redx-0.4.5-macos-arm64.dmg", "url": "https://github.com/x/redx-0.4.5-macos-arm64.dmg", "mirrors": ["https://host.example/v1/updates/redx/0.4.5/artifacts/macos-arm64-dmg"], "size": 13390211, "sha256": "` + sumA + `", "delta_from": null },
    { "id": "macos-amd64-dmg", "label": "RedX 0.4.5 (Mac, Intel chip)", "os": "macos", "arch": "amd64", "kind": "dmg", "filename": "redx-0.4.5-macos-amd64.dmg", "url": "https://github.com/x/redx-0.4.5-macos-amd64.dmg", "mirrors": [], "size": 10, "sha256": "` + sumA + `", "delta_from": null }
  ],
  "live_patch": [],
  "certificate": null
}`

// hostPKI issues a ra-core "update-signer" certificate for a fresh host key under a test CA.
func hostPKI(t *testing.T, now time.Time) (*pki, ed25519.PrivateKey, UpdateKey) {
	p := newPKI(t, now)
	pub, priv, _ := ed25519.GenerateKey(nil)
	leaf := Cert{Serial: "h1", Kind: CertKindUpdateSigner, Subject: CertSubject{Name: "RedX host", TeamID: "T-redx", DevID: "host-1"}, PublicKey: pub,
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour * 90).Unix(), Test: true}
	if err := SignCert(&leaf, p.inter); err != nil {
		t.Fatal(err)
	}
	return p, priv, UpdateKey{KID: "k1", Alg: "ed25519", Pub: base64.StdEncoding.EncodeToString(pub), NotAfter: "2099-01-01T00:00:00Z", Chain: []Cert{leaf, p.chain[1]}}
}

func hostKeys(t *testing.T) (ed25519.PrivateKey, map[string]TrustedKey) {
	now := time.Now()
	p, priv, k := hostPKI(t, now)
	_, store, _ := ed25519.GenerateKey(nil)
	keys, why := TrustedUpdateKeys([]UpdateKey{k}, p.pol, ticket(t, store, now, StatusTicket{}))
	if len(keys) != 1 {
		t.Fatalf("certified key not trusted: %v", why)
	}
	return priv, keys
}

func sigHdr(priv ed25519.PrivateKey, b []byte) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
}

func code(err error) string {
	var e *ErrUpdateManifest
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestUpdateManifestVerify(t *testing.T) {
	priv, keys := hostKeys(t)
	body := []byte(manifestJSON)
	m, err := VerifyUpdateManifest(body, sigHdr(priv, body), "k1", keys, 41)
	if err != nil {
		t.Fatal(err)
	}
	if m.Outcome.Risk.Level != "low" || len(m.Artifacts) != 3 {
		t.Fatalf("%+v", m)
	}
	// arm64 Mac first, then universal; Intel gets amd64.
	if a, _ := m.PickArtifact("darwin", "arm64", "0.4.4", "dmg"); a.ID != "macos-arm64-dmg" {
		t.Fatalf("arm64 picked %s", a.ID)
	}
	if a, _ := m.PickArtifact("darwin", "amd64", "0.4.4", "dmg"); a.ID != "macos-amd64-dmg" {
		t.Fatalf("amd64 picked %s", a.ID)
	}
	if _, err := m.PickArtifact("windows", "amd64", "", ""); code(err) != "bad_artifact" {
		t.Fatal("windows should have no build")
	}
	a, _ := m.PickArtifact("darwin", "arm64", "", "")
	if a.CheckArtifact(sumA, 13390211) != nil || code(a.CheckArtifact(sumA, 1)) != "bad_artifact" {
		t.Fatal("artifact check")
	}

	// Signature over other bytes (one changed byte), wrong key, wrong kid, malformed header.
	edited := []byte(strings.Replace(manifestJSON, `"0.4.5",`, `"0.4.6",`, 1))
	for name, c := range map[string]struct {
		b   []byte
		sig string
		kid string
	}{
		"edited":    {edited, sigHdr(priv, body), "k1"},
		"wrong kid": {body, sigHdr(priv, body), "k2"},
		"no prefix": {body, strings.TrimPrefix(sigHdr(priv, body), "ed25519:"), ""},
	} {
		if _, err := VerifyUpdateManifest(c.b, c.sig, c.kid, keys, 0); code(err) != "bad_signature" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyUpdateManifest(body, sigHdr(other, body), "", keys, 0); code(err) != "bad_signature" {
		t.Fatal("unpinned key accepted")
	}
	// Rollback protection.
	for _, last := range []int64{42, 99} {
		if _, err := VerifyUpdateManifest(body, sigHdr(priv, body), "k1", keys, last); code(err) != "sequence_regression" {
			t.Fatalf("sequence %d: %v", last, err)
		}
	}
	// Strict schema: a correctly signed but invalid manifest is still refused.
	for name, mut := range map[string][2]string{
		"unknown field": {`"channel": "stable",`, `"channel": "stable", "extra": 1,`},
		"bad tag":       {`"+perf"`, `"+speedy"`},
		"bad channel":   {`"channel": "stable"`, `"channel": "nightly"`},
		"http url":      {`"url": "https://github.com/x/redx-0.4.5-macos-arm64.dmg"`, `"url": "http://github.com/x/redx-0.4.5-macos-arm64.dmg"`},
		"dup filename":  {`redx-0.4.5-macos-amd64.dmg"`, `redx-0.4.5-macos-arm64.dmg"`},
		"bad schema":    {`redx.update-manifest/v1`, `redx.update-manifest/v2`},
		"risk range":    {`"score": 0.18`, `"score": 1.5`},
	} {
		b := []byte(strings.Replace(manifestJSON, mut[0], mut[1], 1))
		if _, err := VerifyUpdateManifest(b, sigHdr(priv, b), "k1", keys, 0); code(err) != "bad_manifest" {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestUpdateKeysNeedRaCoreChainAndRevocation(t *testing.T) {
	now := time.Now()
	p, _, k := hostPKI(t, now)
	_, store, _ := ed25519.GenerateKey(nil)
	clean := ticket(t, store, now, StatusTicket{})
	trusted := func(keys []UpdateKey, pol ChainPolicy, rev *RevocationState) int {
		got, _ := TrustedUpdateKeys(keys, pol, rev)
		return len(got)
	}
	if trusted([]UpdateKey{k}, p.pol, clean) != 1 {
		t.Fatal("certified key rejected")
	}
	noChain := k
	noChain.Chain = nil
	if trusted([]UpdateKey{noChain}, p.pol, clean) != 0 {
		t.Fatal("key without a chain trusted")
	}
	other := k
	pub2, _, _ := ed25519.GenerateKey(nil)
	other.Pub = base64.StdEncoding.EncodeToString(pub2) // certificate is for a different key
	if trusted([]UpdateKey{other}, p.pol, clean) != 0 {
		t.Fatal("key/cert mismatch trusted")
	}
	devLeaf := k
	devLeaf.Chain = p.chain // a developer certificate is not an update-signer certificate
	if trusted([]UpdateKey{devLeaf}, p.pol, clean) != 0 {
		t.Fatal("developer cert accepted as update signer")
	}
	expired := k
	expired.NotAfter = now.Add(-time.Minute).Format(time.RFC3339)
	if trusted([]UpdateKey{expired}, p.pol, clean) != 0 {
		t.Fatal("expired key trusted")
	}
	if trusted([]UpdateKey{k}, newPKI(t, now).pol, clean) != 0 {
		t.Fatal("foreign root trusted")
	}
	for _, fp := range []string{k.Chain[0].Fingerprint(), k.Chain[1].Fingerprint()} {
		if trusted([]UpdateKey{k}, p.pol, ticket(t, store, now, StatusTicket{RevokedCerts: []string{fp}})) != 0 {
			t.Fatal("revoked host key trusted")
		}
	}
	if trusted([]UpdateKey{k}, p.pol, nil) != 0 {
		t.Fatal("trusted with no revocation list")
	}
	prod := p.pol
	prod.Production = true
	if trusted([]UpdateKey{k}, prod, clean) != 0 {
		t.Fatal("test chain trusted in production")
	}
}

func TestUpdateManifestP384HostKey(t *testing.T) {
	now := time.Now()
	p := newPKI(t, now)
	hk, err := NewP384Signer()
	if err != nil {
		t.Fatal(err)
	}
	leaf := Cert{Serial: "h2", Kind: CertKindUpdateSigner, Alg: AlgP384, PublicKey: hk.Public(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(), Test: true}
	if err := SignCert(&leaf, p.inter); err != nil {
		t.Fatal(err)
	}
	_, store, _ := ed25519.GenerateKey(nil)
	keys, why := TrustedUpdateKeys([]UpdateKey{{KID: "p", Alg: AlgP384, Pub: base64.StdEncoding.EncodeToString(hk.Public()), Chain: []Cert{leaf, p.chain[1]}}}, p.pol, ticket(t, store, now, StatusTicket{}))
	if len(keys) != 1 {
		t.Fatal(why)
	}
	body := []byte(manifestJSON)
	sig, _ := hk.Sign(body)
	if _, err := VerifyUpdateManifest(body, "p384:"+base64.StdEncoding.EncodeToString(sig), "p", keys, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpdateManifest(body, "ed25519:"+base64.StdEncoding.EncodeToString(sig), "p", keys, 0); code(err) != "bad_signature" {
		t.Fatal("algorithm confusion accepted")
	}
}

func TestUpdateSources(t *testing.T) {
	if got := UpdateSourceOptions(false); len(got) != 1 || got[0] != "github" {
		t.Fatalf("not hosted offers %v", got)
	}
	if got := UpdateSourceOptions(true); len(got) != 3 {
		t.Fatalf("hosted offers %v", got)
	}
	if code(ValidUpdateSource("host", false)) != "not_hosted" || code(ValidUpdateSource("both", false)) != "not_hosted" || ValidUpdateSource("both", true) != nil || ValidUpdateSource("github", false) != nil {
		t.Fatal("source rules")
	}
}
