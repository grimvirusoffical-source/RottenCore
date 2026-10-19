package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Red-XAI code signing (docs/SIGNING.md). We sign with OUR OWN certificates, not Apple's: ra-core
// (https://api.rottenapplestore.org) is the certificate authority and issues developer certificates to
// Red-XAI Accounts developer accounts. A downloaded file is "signed by one of our dev accounts" when its
// RottenCore signature (rottencore.signature.json inside, or <file>.rasig next to it) verifies under a
// developer certificate whose chain ends at a pinned Red-XAI CA root, and no certificate in the chain, the
// app or the build is on the store's signed revocation list (revocation.go).
//
// The certificate format is wire-compatible with the store's rarxai.Cert (rotten-apple/rarxai/pki.go):
// canonical JSON, Ed25519, domain "RARXAI-CERT-v1\0", leaf kind "developer", intermediates kind "ca",
// at most 3 certificates. testdata/rarxai_vector.json is produced by the store's own code and checked in
// TestRarxaiCompatVector, so the two implementations cannot drift apart silently.

// Certificate kinds.
const (
	CertKindCA        = "ca"
	CertKindDeveloper = "developer"
)

const (
	certDomain    = "RARXAI-CERT-v1\x00"
	fileSigDomain = "ROTTENCORE-FILESIG-v1\x00"
	// SignatureName is the embedded signature file; a sidecar is <file>.rasig.
	SignatureName    = "rottencore.signature.json"
	SignatureSidecar = ".rasig"
	maxSigFile       = 256 << 10
)

// CertSubject identifies the holder (same JSON as rarxai.Subject).
type CertSubject struct {
	Name   string `json:"name"`
	TeamID string `json:"teamId"`
	DevID  string `json:"devId"`
}

// Cert is a Red-XAI certificate (same JSON as rarxai.Cert).
type Cert struct {
	Version   int         `json:"version"`
	Serial    string      `json:"serial"`
	Kind      string      `json:"kind"`
	Subject   CertSubject `json:"subject"`
	PublicKey []byte      `json:"publicKey"`
	NotBefore int64       `json:"notBefore"`
	NotAfter  int64       `json:"notAfter"`
	Test      bool        `json:"test"`
	Issuer    string      `json:"issuer"`
	Signature []byte      `json:"signature"`
}

func (c *Cert) tbs() ([]byte, error) {
	t := *c
	t.Signature = nil
	b, err := canonJSON(&t)
	if err != nil {
		return nil, err
	}
	return append([]byte(certDomain), b...), nil
}

// Fingerprint is sha256 of the full canonical certificate (signature included), as the store computes it.
// Revocation lists name certificates by this value.
func (c *Cert) Fingerprint() string {
	b, _ := canonJSON(c)
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// SignCert signs c with the issuer key (tests, and the reference for ra-core's CA).
func SignCert(c *Cert, issuer ed25519.PrivateKey) error {
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return errors.New("certificate has no public key")
	}
	c.Version = 1
	c.Issuer = KeyFingerprint(issuer.Public().(ed25519.PublicKey))
	msg, err := c.tbs()
	if err != nil {
		return err
	}
	c.Signature = ed25519.Sign(issuer, msg)
	return nil
}

func (c *Cert) verifyBy(issuer ed25519.PublicKey) error {
	if len(c.Signature) != ed25519.SignatureSize || len(issuer) != ed25519.PublicKeySize {
		return errors.New("bad signature or key size")
	}
	if KeyFingerprint(issuer) != c.Issuer {
		return errors.New("issuer fingerprint does not match the signing key")
	}
	msg, err := c.tbs()
	if err != nil {
		return err
	}
	if !ed25519.Verify(issuer, msg, c.Signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

// CARoot is a pinned Red-XAI CA root public key.
type CARoot struct {
	Name      string
	PublicKey ed25519.PublicKey
	Test      bool // refused when the policy is Production
}

// PinnedCARoots are the production Red-XAI developer-CA roots. EMPTY until Red-XAI provisions the
// production CA (ra-core today only has the test CA tool ra-ca). Like PinnedStoreKeys, a root can only be
// added in code, never from a file, an environment variable or a manifest.
var PinnedCARoots = []CARoot{}

// ChainPolicy configures VerifyCertChain.
type ChainPolicy struct {
	Roots      []CARoot
	Production bool // refuse test certificates and test roots
	Now        time.Time
}

// ErrCertChain wraps chain failures.
var ErrCertChain = errors.New("certificate chain rejected")

func chainErr(f string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCertChain, fmt.Sprintf(f, a...))
}

// VerifyCertChain checks chain[0] (developer) up to a pinned root, the same rules as rarxai.VerifyChain.
// Revocation is checked separately against the status ticket (CheckRevocation) so the caller can tell
// "revoked" from "could not check".
func VerifyCertChain(chain []Cert, pol ChainPolicy) (*Cert, error) {
	if len(chain) == 0 || len(chain) > 3 {
		return nil, chainErr("chain must have 1 to 3 certificates")
	}
	now := pol.Now
	if now.IsZero() {
		now = time.Now()
	}
	for i := range chain {
		c := &chain[i]
		if c.Version != 1 {
			return nil, chainErr("certificate %d: unsupported version %d", i, c.Version)
		}
		if len(c.PublicKey) != ed25519.PublicKeySize {
			return nil, chainErr("certificate %d: bad public key", i)
		}
		want := CertKindCA
		if i == 0 {
			want = CertKindDeveloper
		}
		if c.Kind != want {
			return nil, chainErr("certificate %d: kind %q, expected %q", i, c.Kind, want)
		}
		if pol.Production && c.Test {
			return nil, chainErr("certificate %d is a test certificate", i)
		}
		if t := now.Unix(); t < c.NotBefore || t > c.NotAfter {
			return nil, chainErr("certificate %d is not valid at this time", i)
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].verifyBy(ed25519.PublicKey(chain[i+1].PublicKey)); err != nil {
			return nil, chainErr("certificate %d: %v", i, err)
		}
	}
	top := &chain[len(chain)-1]
	for _, r := range pol.Roots {
		if pol.Production && r.Test {
			continue
		}
		if top.verifyBy(r.PublicKey) == nil {
			return &chain[0], nil
		}
	}
	return nil, chainErr("no Red-XAI CA root signed this chain")
}

// FileSigDoc is what a developer signs about one file.
type FileSigDoc struct {
	V        int    `json:"v"`
	AppID    string `json:"appId"`
	Version  string `json:"version"`
	Artifact struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"artifact"`
	SignedMs int64 `json:"signedMs"`
}

// FileSignature is rottencore.signature.json / <file>.rasig.
type FileSignature struct {
	Alg   string `json:"alg"` // ed25519
	Doc   string `json:"doc"` // base64 canonical FileSigDoc
	Sig   string `json:"sig"` // base64 Ed25519 over fileSigDomain || doc, by chain[0]
	Chain []Cert `json:"chain"`
}

// SignFileDoc signs a document with a developer key (tests; production signing is the uploader's job).
func SignFileDoc(priv ed25519.PrivateKey, chain []Cert, d FileSigDoc) (*FileSignature, error) {
	d.V = 1
	b, err := canonJSON(&d)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, append([]byte(fileSigDomain), b...))
	return &FileSignature{Alg: "ed25519", Doc: base64.StdEncoding.EncodeToString(b), Sig: base64.StdEncoding.EncodeToString(sig), Chain: chain}, nil
}

// ParseFileSignature decodes a signature file strictly.
func ParseFileSignature(b []byte) (*FileSignature, error) {
	if len(b) > maxSigFile {
		return nil, errors.New("signature file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s FileSignature
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("signature file: %w", err)
	}
	return &s, nil
}

// SigStatus is the outcome of a signature check.
type SigStatus string

const (
	SigNone         SigStatus = "none"         // no signature found
	SigValid        SigStatus = "valid"        // chain + signature + bytes OK and not revoked (fresh or in grace)
	SigUnverifiable SigStatus = "unverifiable" // chain + signature OK but revocation could not be checked (no list, or past grace)
	SigInvalid      SigStatus = "invalid"      // bad chain, bad signature, or signed for other bytes
	SigRevoked      SigStatus = "revoked"      // on the store's revocation list: hard refusal
)

// SigResult is the decision about one file's Red-XAI signature.
type SigResult struct {
	Status     SigStatus    `json:"status"`
	Signer     *CertSubject `json:"signer,omitempty"`
	CertFPs    []string     `json:"certFingerprints,omitempty"`
	AppID      string       `json:"appId,omitempty"`
	Version    string       `json:"version,omitempty"`
	Revocation string       `json:"revocation"` // fresh | grace | stale | none
	Reasons    []string     `json:"reasons"`
}

// Trusted reports whether the signature makes the file trusted (install prompt without the untrusted warning).
func (r *SigResult) Trusted() bool { return r != nil && r.Status == SigValid }

// Refuse reports a hard refusal.
func (r *SigResult) Refuse() bool { return r != nil && r.Status == SigRevoked }

// VerifyFileSignature checks sig for a file with the given sha256 and size. rev may be nil (no list).
func VerifyFileSignature(sig *FileSignature, sum string, size int64, pol ChainPolicy, rev *RevocationState) *SigResult {
	r := &SigResult{Status: SigNone, Revocation: "none", Reasons: []string{}}
	if sig == nil {
		r.Reasons = append(r.Reasons, "the file carries no Red-XAI signature")
		return r
	}
	bad := func(why string) *SigResult {
		r.Status = SigInvalid
		r.Reasons = append(r.Reasons, why)
		return r
	}
	if sig.Alg != "ed25519" {
		return bad("unsupported signature algorithm " + sig.Alg)
	}
	leaf, err := VerifyCertChain(sig.Chain, pol)
	if err != nil {
		return bad(err.Error())
	}
	for i := range sig.Chain {
		r.CertFPs = append(r.CertFPs, sig.Chain[i].Fingerprint())
	}
	doc, err := base64.StdEncoding.DecodeString(sig.Doc)
	if err != nil || len(doc) > 64<<10 {
		return bad("signature document is not base64")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return bad("signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(leaf.PublicKey), append([]byte(fileSigDomain), doc...), raw) {
		return bad("signature does not verify under the developer certificate")
	}
	var d FileSigDoc
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return bad("signature document does not parse: " + err.Error())
	}
	if again, err := canonJSON(&d); err != nil || !bytes.Equal(again, doc) {
		return bad("signature document is not canonical")
	}
	if d.V != 1 || !sha256Re.MatchString(d.Artifact.SHA256) || d.Artifact.Bytes <= 0 || !appIDRe.MatchString(d.AppID) {
		return bad("signature document is malformed")
	}
	if d.Artifact.SHA256 != sum || d.Artifact.Bytes != size {
		return bad("the signature is for different bytes: the file was changed or damaged")
	}
	sub := leaf.Subject
	r.Signer, r.AppID, r.Version = &sub, d.AppID, d.Version
	reason, state := CheckRevocation(rev, d.AppID, "sha256:"+sum, r.CertFPs, pol.Now)
	r.Revocation = state
	switch {
	case reason != "":
		r.Status = SigRevoked
		r.Reasons = append(r.Reasons, reason)
	case state == "fresh" || state == "grace":
		r.Status = SigValid
		r.Reasons = append(r.Reasons, fmt.Sprintf("signed by Red-XAI developer %s (team %s) as %s %s", sub.Name, sub.TeamID, d.AppID, d.Version))
		if state == "grace" {
			r.Reasons = append(r.Reasons, "offline: using the last revocation list RottenCore downloaded (still inside the 7-day grace)")
		}
	default:
		r.Status = SigUnverifiable
		r.Reasons = append(r.Reasons, "signature is valid, but RottenCore could not check the store's revocation list; connect to the internet and try again")
	}
	return r
}
