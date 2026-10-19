package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
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

// Certificate kinds. A leaf is "developer" (signs apps and releases) or "update-signer" (a Red-XAI Host's
// update-manifest key, issued by ra-core so hosts share the one chain of trust and one way to revoke).
const (
	CertKindCA           = "ca"
	CertKindDeveloper    = "developer"
	CertKindUpdateSigner = "update-signer"
)

// Key algorithms. Version 1 certificates are Ed25519 only (no "alg" field, exactly rarxai.Cert). Version 2
// adds "alg": "ed25519" or "p384" (ECDSA P-384 with SHA-384; public key = 97-byte uncompressed X9.63 point,
// signature = 96-byte raw r||s: the same encodings as Apple CryptoKit's P384 x963Representation and
// rawRepresentation). P-384 is the "magnitude" tier for Mega, owner/admin, the issuing CA and the root.
const (
	AlgEd25519 = "ed25519"
	AlgP384    = "p384"
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
	Alg       string      `json:"alg,omitempty"` // v2 only; "" = ed25519 (v1)
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

// Signer is a private key RottenCore can sign with (tests, and the reference for ra-core's CA).
type Signer interface {
	Alg() string
	Public() []byte
	Sign(msg []byte) ([]byte, error)
}

// Ed25519Signer wraps an Ed25519 private key.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

func (s Ed25519Signer) Alg() string                     { return AlgEd25519 }
func (s Ed25519Signer) Public() []byte                  { return s.Key.Public().(ed25519.PublicKey) }
func (s Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.Key, msg), nil }

// P384Signer wraps an ECDSA P-384 private key.
type P384Signer struct{ Key *ecdsa.PrivateKey }

func (s P384Signer) Alg() string { return AlgP384 }
func (s P384Signer) Public() []byte {
	pk, _ := s.Key.PublicKey.ECDH()
	return pk.Bytes()
}
func (s P384Signer) Sign(msg []byte) ([]byte, error) {
	h := sha512.Sum384(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 96)
	r.FillBytes(out[:48])
	ss.FillBytes(out[48:])
	return out, nil
}

// NewP384Signer makes a P-384 key from crypto/rand (tests).
func NewP384Signer() (P384Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return P384Signer{k}, err
}

// algOf normalises "" to ed25519.
func algOf(a string) string {
	if a == "" {
		return AlgEd25519
	}
	return a
}

// validPublicKey checks the key encoding for the algorithm.
func validPublicKey(alg string, pub []byte) bool {
	switch algOf(alg) {
	case AlgEd25519:
		return len(pub) == ed25519.PublicKeySize
	case AlgP384:
		_, err := ecdh.P384().NewPublicKey(pub) // rejects points not on the curve
		return len(pub) == 97 && err == nil
	}
	return false
}

// VerifySig checks sig over msg with pub under alg (ed25519, or p384 = ECDSA P-384/SHA-384, raw r||s).
func VerifySig(alg string, pub, msg, sig []byte) bool {
	switch algOf(alg) {
	case AlgEd25519:
		return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	case AlgP384:
		if len(sig) != 96 || !validPublicKey(AlgP384, pub) {
			return false
		}
		x, y := elliptic.Unmarshal(elliptic.P384(), pub) //nolint:staticcheck // point already validated by crypto/ecdh
		if x == nil {
			return false
		}
		h := sha512.Sum384(msg)
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, h[:], new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:]))
	}
	return false
}

// SignCert signs c with an Ed25519 issuer key (v1 when c.Alg is "" and the issuer is Ed25519).
func SignCert(c *Cert, issuer ed25519.PrivateKey) error {
	return SignCertWith(c, Ed25519Signer{issuer})
}

// SignCertWith signs c with any issuer. A certificate that holds a non-Ed25519 key, or is signed by one,
// is version 2 (with "alg"); everything else stays version 1, byte-identical to rarxai.
func SignCertWith(c *Cert, issuer Signer) error {
	if !validPublicKey(c.Alg, c.PublicKey) {
		return errors.New("certificate public key does not match its algorithm")
	}
	c.Version = 1
	if c.Alg != "" || issuer.Alg() != AlgEd25519 {
		c.Version, c.Alg = 2, algOf(c.Alg)
	}
	c.Issuer = KeyFingerprint(issuer.Public())
	msg, err := c.tbs()
	if err != nil {
		return err
	}
	c.Signature, err = issuer.Sign(msg)
	return err
}

// verifyBy checks c's signature with the issuer's key and algorithm.
func (c *Cert) verifyBy(issuerAlg string, issuer []byte) error {
	if KeyFingerprint(issuer) != c.Issuer {
		return errors.New("issuer fingerprint does not match the signing key")
	}
	msg, err := c.tbs()
	if err != nil {
		return err
	}
	if !VerifySig(issuerAlg, issuer, msg, c.Signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

// CARoot is a pinned Red-XAI CA root public key.
type CARoot struct {
	Name      string
	Alg       string // "" or ed25519, or p384
	PublicKey []byte // Ed25519 (32 bytes) or P-384 uncompressed point (97 bytes)
	Test      bool   // refused when the policy is Production
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
	// LeafKind is what chain[0] must be: developer (default) for app signatures, update-signer for host
	// update-manifest keys.
	LeafKind string
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
		switch {
		case c.Version == 1 && c.Alg == "":
		case c.Version == 2 && (c.Alg == AlgEd25519 || c.Alg == AlgP384):
		default:
			return nil, chainErr("certificate %d: unsupported version %d / algorithm %q", i, c.Version, c.Alg)
		}
		if !validPublicKey(c.Alg, c.PublicKey) {
			return nil, chainErr("certificate %d: bad public key", i)
		}
		want := CertKindCA
		if i == 0 {
			want = pol.LeafKind
			if want == "" {
				want = CertKindDeveloper
			}
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
		if err := chain[i].verifyBy(chain[i+1].Alg, chain[i+1].PublicKey); err != nil {
			return nil, chainErr("certificate %d: %v", i, err)
		}
	}
	top := &chain[len(chain)-1]
	for _, r := range pol.Roots {
		if pol.Production && r.Test {
			continue
		}
		if top.verifyBy(r.Alg, r.PublicKey) == nil {
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
	Alg   string `json:"alg"` // ed25519 | p384 (must be the developer certificate's algorithm)
	Doc   string `json:"doc"` // base64 canonical FileSigDoc
	Sig   string `json:"sig"` // base64 Ed25519 over fileSigDomain || doc, by chain[0]
	Chain []Cert `json:"chain"`
}

// SignFileDoc signs a document with an Ed25519 developer key (tests; production signing is the uploader's job).
func SignFileDoc(priv ed25519.PrivateKey, chain []Cert, d FileSigDoc) (*FileSignature, error) {
	return SignFileDocWith(Ed25519Signer{priv}, chain, d)
}

// SignFileDocWith signs with any developer key (Ed25519 or P-384).
func SignFileDocWith(k Signer, chain []Cert, d FileSigDoc) (*FileSignature, error) {
	d.V = 1
	b, err := canonJSON(&d)
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(append([]byte(fileSigDomain), b...))
	if err != nil {
		return nil, err
	}
	return &FileSignature{Alg: k.Alg(), Doc: base64.StdEncoding.EncodeToString(b), Sig: base64.StdEncoding.EncodeToString(sig), Chain: chain}, nil
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
	Revocation string       `json:"revocation"`         // fresh | grace | stale | none
	Mismatch   bool         `json:"mismatch,omitempty"` // a verified signature for other bytes: hard refusal
	Test       bool         `json:"test,omitempty"`     // signed under the TEST CA: never valid for production trust or quarantine removal
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
	pol.LeafKind = CertKindDeveloper
	leaf, err := VerifyCertChain(sig.Chain, pol)
	if err != nil {
		return bad(err.Error())
	}
	if sig.Alg != algOf(leaf.Alg) {
		return bad("signature algorithm " + sig.Alg + " does not match the developer certificate (" + algOf(leaf.Alg) + ")")
	}
	r.Test = anyTest(sig.Chain)
	for i := range sig.Chain {
		r.CertFPs = append(r.CertFPs, sig.Chain[i].Fingerprint())
	}
	doc, err := base64.StdEncoding.DecodeString(sig.Doc)
	if err != nil || len(doc) > 64<<10 {
		return bad("signature document is not base64")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) > 200 {
		return bad("signature is malformed")
	}
	if !VerifySig(leaf.Alg, leaf.PublicKey, append([]byte(fileSigDomain), doc...), raw) {
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
		r.Mismatch = true
		return bad("the file's sha256 does not match its Red-XAI signature: it was changed or damaged; nothing will be installed")
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

func anyTest(chain []Cert) bool {
	for _, c := range chain {
		if c.Test {
			return true
		}
	}
	return false
}
