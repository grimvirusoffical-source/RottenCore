package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// QA L5: pin ONE serialisation per use, the same as ra-core (RottenApple rxa-cert-ids @ 711171b):
//   - signed bytes (cert TBS, fingerprint): rarxai/pki.go tbs()/Fingerprint() use json.Encoder with
//     SetEscapeHTML(false). core.canonJSON does the same, so it must NOT switch to json.Marshal: that would
//     break the signature of every ra-core certificate whose name contains < > &.
//   - wire bytes (cert.subject, /certs leaf, account.subject): json.Marshal / json.Encoder, HTML-escaped.
//     The identity check compares wire bytes with wire bytes, and the bundle keeps the wire bytes.
const ampName = "A<B & C>"

// rarxaiTBS is a verbatim copy of rarxai (*Cert).tbs() at 711171b, applied to core.Cert (same fields, same order).
func rarxaiTBS(c Cert) []byte {
	c.Signature = nil
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(&c)
	return append([]byte("RARXAI-CERT-v1\x00"), bytes.TrimRight(buf.Bytes(), "\n")...)
}

func rarxaiFingerprint(c Cert) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(&c)
	s := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestCanonJSONMatchesRaCoreForHTMLChars(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	issPub, issPriv, _ := ed25519.GenerateKey(nil)
	leafPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	iss := Cert{Serial: "1", Kind: CertKindCA, Subject: CertSubject{Name: "Issuing <&>"}, PublicKey: issPub, NotBefore: now - 60, NotAfter: now + 3600}
	if err := SignCert(&iss, rootPriv); err != nil {
		t.Fatal(err)
	}
	team := "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"
	dev := "rxa_LVWECFKVPN6XMPISHYONVY6WUB"
	leaf := Cert{Serial: "2", Kind: CertKindDeveloper, Subject: CertSubject{Name: ampName, TeamID: team, DevID: dev}, PublicKey: leafPub, NotBefore: now - 60, NotAfter: now + 3600}
	if err := SignCert(&leaf, issPriv); err != nil { // fills version, alg, issuer
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.Signature, ed25519.Sign(issPriv, rarxaiTBS(leaf))) {
		t.Fatal("core.SignCert does not sign the ra-core TBS bytes")
	}

	// 1. our TBS is byte-identical to ra-core's (escape-off)
	ours, err := leaf.tbs()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours, rarxaiTBS(leaf)) || !bytes.Contains(ours, []byte(`"name":"A<B & C>"`)) {
		t.Fatalf("core TBS != ra-core TBS:\n%s\n%s", ours, rarxaiTBS(leaf))
	}
	// 2. a cert signed the ra-core way verifies; one signed over json.Marshal (escaped) bytes does not
	pol := ChainPolicy{Roots: []CARoot{{Name: "r", PublicKey: rootPub}}, Production: true}
	good := leaf
	good.Signature = ed25519.Sign(issPriv, rarxaiTBS(leaf))
	if _, err := VerifyCertChain([]Cert{good, iss}, pol); err != nil {
		t.Fatalf("ra-core-signed cert with %q refused: %v", ampName, err)
	}
	escaped, _ := json.Marshal(func() Cert { c := leaf; c.Signature = nil; return c }())
	if bytes.Equal(escaped, bytes.TrimPrefix(rarxaiTBS(leaf), []byte("RARXAI-CERT-v1\x00"))) {
		t.Fatal("test premise: json.Marshal must escape < > &")
	}
	bad := leaf
	bad.Signature = ed25519.Sign(issPriv, append([]byte("RARXAI-CERT-v1\x00"), escaped...))
	if _, err := VerifyCertChain([]Cert{bad, iss}, pol); err == nil {
		t.Fatal("a signature over HTML-escaped TBS verified: canonJSON no longer matches ra-core")
	}
	// 3. the wire form (ra-core writeJSON = escaped) round-trips: still verifies, same fingerprint
	wire, _ := json.Marshal(good)
	if !bytes.Contains(wire, []byte(`A\u003cB \u0026 C\u003e`)) {
		t.Fatalf("wire form not escaped: %s", wire)
	}
	var back Cert
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCertChain([]Cert{back, iss}, pol); err != nil {
		t.Fatalf("wire round trip broke the signature: %v", err)
	}
	if back.Fingerprint() != rarxaiFingerprint(good) {
		t.Fatal("fingerprint differs from ra-core's")
	}
	// 4. identity check: wire leaf vs ra-core CertSubjectString (json.Marshal) — equal; vs escape-off — not
	srvSubject, _ := json.Marshal(struct {
		Name   string `json:"name"`
		TeamID string `json:"teamId"`
		DevID  string `json:"devId"`
	}{ampName, team, dev})
	if err := EqualSubjectBytes(wire, srvSubject); err != nil {
		t.Fatalf("wire vs wire: %v", err)
	}
	raw := strings.ReplaceAll(string(srvSubject), `\u003c`, "<")
	raw = strings.ReplaceAll(strings.ReplaceAll(raw, `\u003e`, ">"), `\u0026`, "&")
	if EqualSubjectBytes(wire, []byte(raw)) == nil {
		t.Fatal("escape-off subject matched the wire bytes: the exact compare must be against bytes as served")
	}
}
