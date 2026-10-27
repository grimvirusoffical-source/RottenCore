package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCanonicalOmitsSignature(t *testing.T) {
	pub := strings.Repeat("ab", 32)
	sum := strings.Repeat("cd", 32)
	p := Payload{
		Type: TypeRottenCoreSigned, SigID: "rxa_01", AppID: "com.acme.tool", Version: "1.0.0",
		Cert: Cert{ID: "cert1", PubKey: pub, Issuer: Issuer}, Hash: sum, Nonce: "aa",
		Platforms: []string{"macos"}, LauncherRequired: false, Sig: "should-not-appear",
	}
	b, err := Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"rotten_core_signed","sig_id":"rxa_01","app_id":"com.acme.tool","version":"1.0.0","cert":{"id":"cert1","pubkey":"` + pub + `","issuer":"red-x-accounts-owner"},"hash":"` + sum + `","nonce":"aa","platforms":["macos"],"launcher_required":false}`
	if string(b) != want {
		t.Fatalf("canonical\n got %s\nwant %s", b, want)
	}
	p.PrevSigID = "rxa_00"
	b, err = Canonical(p)
	if err != nil || !bytes.Contains(b, []byte(`"prev_sig_id":"rxa_00"`)) || bytes.Contains(b, []byte("should-not-appear")) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(priv)
	p := Payload{
		Type: TypeRottenCoreSigned, SigID: "rxa_01", AppID: "com.acme.tool", Version: "1.2.3",
		Cert:      Cert{ID: "cert1", PubKey: hex.EncodeToString(pub), Issuer: Issuer},
		Hash:      strings.Repeat("cd", 32),
		Nonce:     "0011",
		Platforms: []string{"linux"},
	}
	signed, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed); err != nil {
		t.Fatal(err)
	}
	carrier, err := Marshal(signed)
	if err != nil || bytes.Contains(carrier, priv) || bytes.Contains(carrier, []byte(hex.EncodeToString(priv.Seed()))) {
		t.Fatalf("carrier leaked key material: %v %s", err, carrier)
	}
	again, err := Parse(carrier)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(again); err != nil {
		t.Fatal(err)
	}
	again.LauncherRequired = true
	if err := Verify(again); err == nil {
		t.Fatal("flipping launcher_required still verified")
	}
	bad := append([]byte(nil), carrier...)
	bad = bytes.Replace(bad, []byte("1.2.3"), []byte("9.9.9"), 1)
	if parsed, err := Parse(bad); err == nil {
		if err := Verify(parsed); err == nil {
			t.Fatal("tampered version verified")
		}
	}
}

func TestParsePrivateKeyMatchesPubAndWipesOnMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(priv)
	got, err := ParsePrivateKey([]byte(hex.EncodeToString(priv)), hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(got)
	if !bytes.Equal(got, priv) {
		t.Fatal("parsed key differs")
	}
	seed, err := ParsePrivateKey([]byte(strings.ToUpper(hex.EncodeToString(priv.Seed()))), hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	Wipe(seed)
	if _, err := ParsePrivateKey([]byte(hex.EncodeToString(priv)), strings.Repeat("00", 32)); err == nil {
		t.Fatal("mismatched public key accepted")
	}
}
