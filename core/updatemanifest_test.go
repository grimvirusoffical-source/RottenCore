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

func hostKeys(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keys := TrustedUpdateKeys([]UpdateKey{{KID: "k1", Alg: "ed25519", Pub: base64.StdEncoding.EncodeToString(pub), NotAfter: "2099-01-01T00:00:00Z"}}, []string{KeyFingerprint(pub)}, time.Now())
	if len(keys) != 1 {
		t.Fatal("pinned key not trusted")
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

func TestUpdateKeysAndSources(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	p := base64.StdEncoding.EncodeToString(pub)
	fp := KeyFingerprint(pub)
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	if len(TrustedUpdateKeys([]UpdateKey{{KID: "a", Alg: "ed25519", Pub: p}}, nil, now)) != 0 {
		t.Fatal("unpinned key trusted")
	}
	if len(TrustedUpdateKeys([]UpdateKey{{KID: "a", Alg: "ed25519", Pub: p, NotAfter: "2026-01-01T00:00:00Z"}}, []string{fp}, now)) != 0 {
		t.Fatal("expired key trusted")
	}
	if len(TrustedUpdateKeys([]UpdateKey{{KID: "a", Alg: "rsa", Pub: p}}, []string{fp}, now)) != 0 {
		t.Fatal("non-ed25519 key trusted")
	}
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
