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
)

// Trust model (docs/ROTTENCORE.md §Trust):
//
//   - An app is TRUSTED only when a store attestation verifies under a store public key pinned in this
//     binary AND the attested sha256 and size equal the bytes on disk AND the attested app id equals the
//     manifest's (when there is a manifest). Nothing else makes an app trusted: not `"source": "store"`
//     in a manifest, not a download URL, not a quarantine flag.
//   - Everything else is UNTRUSTED and installs only after the person accepts the warning UntrustedWarning.
//   - Any known checksum (attestation, GitHub SHA256SUMS, sidecar manifest) that does not match the bytes
//     is a hard refusal, accepted or not.

// UntrustedWarning is shown, word for word, before an untrusted install.
const UntrustedWarning = "RottenCore doesn't trust this app: it isn't from the Rotten Apple store."

// attestDomain matches the Rotten Apple store (rarxai/attest.go).
const attestDomain = "ROTTENCORE-ATTEST-v1\x00"

// StoreKeyHex is the production Rotten Apple store (ra-core) public key, the one that signs store
// attestations, review receipts and the revocation status ticket (`ra-core store-keygen`; on the server
// in /etc/ra-core/store.pub.txt, documented in deploy/kamatera-runbook.md). It is public. The private half
// never leaves the server.
const StoreKeyHex = "b596fafa7a639598f371a897b151c9de6018c38e323024fc759b216d4b6ae9d1"

// PinnedStoreKeys are the Rotten Apple store's public keys. Adding or rotating one is a code change and a
// new RottenCore release; it can never come from a file, an environment variable or a manifest.
var PinnedStoreKeys = []ed25519.PublicKey{mustHexKey(StoreKeyHex)}

func mustHexKey(h string) ed25519.PublicKey {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("bad pinned key")
	}
	return b
}

// Signed is the store's envelope (the same as rarxai.Signed in the store).
type Signed struct {
	Doc string `json:"doc"`
	Key string `json:"key"`
	Sig string `json:"sig"`
}

// Attestation is the store's signed statement about one file.
type Attestation struct {
	V        int    `json:"v"`
	AppID    string `json:"appId"`
	Version  string `json:"version"`
	Build    int    `json:"build"`
	Artifact struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"artifact"`
	AgeRating string `json:"ageRating,omitempty"`
	IssuedMs  int64  `json:"issuedMs"`
}

// KeyFingerprint is "sha256:<hex of sha256(public key)>", as the store writes it.
func KeyFingerprint(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(s[:])
}

func canonJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SignAttestation is for tests and for the store's reference: production signing happens in the store.
func SignAttestation(priv ed25519.PrivateKey, a Attestation) (*Signed, error) {
	a.V = 1
	b, err := canonJSON(&a)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, append([]byte(attestDomain), b...))
	return &Signed{Doc: base64.StdEncoding.EncodeToString(b), Key: KeyFingerprint(priv.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyAttestation checks the envelope against pins; the document must be canonical with no unknown fields.
func VerifyAttestation(pins []ed25519.PublicKey, s *Signed) (*Attestation, error) {
	if s == nil || len(s.Doc) > 1<<20 || len(s.Sig) > 200 {
		return nil, errors.New("attestation missing or oversized")
	}
	var key ed25519.PublicKey
	for _, p := range pins {
		if len(p) == ed25519.PublicKeySize && KeyFingerprint(p) == s.Key {
			key = p
		}
	}
	if key == nil {
		return nil, errors.New("attestation is not signed by a store key RottenCore pins")
	}
	b, err := base64.StdEncoding.DecodeString(s.Doc)
	if err != nil {
		return nil, errors.New("attestation document is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("attestation signature is malformed")
	}
	if !ed25519.Verify(key, append([]byte(attestDomain), b...), sig) {
		return nil, errors.New("attestation signature does not verify")
	}
	var a Attestation
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("attestation does not parse: %v", err)
	}
	if again, err := canonJSON(&a); err != nil || !bytes.Equal(again, b) {
		return nil, errors.New("attestation is not canonical")
	}
	if a.V != 1 || !sha256Re.MatchString(a.Artifact.SHA256) || a.Artifact.Bytes <= 0 {
		return nil, errors.New("attestation is malformed")
	}
	return &a, nil
}

// ParseSigned decodes an attestation file.
func ParseSigned(b []byte) (*Signed, error) {
	if len(b) > 1<<20 {
		return nil, errors.New("attestation file too large")
	}
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("attestation file: %w", err)
	}
	return &s, nil
}

// Expected is one checksum source.
type Expected struct {
	From   string `json:"from"` // attestation | github-sha256sums | manifest
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes,omitempty"`
}

// Verdict is the trust and checksum decision for one file.
type Verdict struct {
	SHA256    string     `json:"sha256"`
	Bytes     int64      `json:"bytes"`
	Expected  []Expected `json:"expected"`
	Checksum  string     `json:"checksum"` // match | mismatch | none
	Trusted   bool       `json:"trusted"`
	TrustedBy string     `json:"trustedBy,omitempty"` // "rotten-apple-store"
	Warning   string     `json:"warning,omitempty"`   // UntrustedWarning when not trusted
	Reasons   []string   `json:"reasons"`             // why, in plain words
	Refuse    bool       `json:"refuse"`              // hard refusal (checksum mismatch)
}

// Decide combines everything known about a file. sum/size are the file's own; m may be nil; att may be
// nil; ghSum is the GitHub SHA256SUMS entry ("" when none).
func Decide(pins []ed25519.PublicKey, sum string, size int64, m *Manifest, att *Signed, ghSum string) *Verdict {
	v := &Verdict{SHA256: sum, Bytes: size, Expected: []Expected{}, Reasons: []string{}}
	mismatch := func(from string) {
		v.Refuse = true
		v.Reasons = append(v.Reasons, "the file's sha256 does not match the "+from+": it was changed or damaged; nothing will be installed")
	}
	if att != nil {
		a, err := VerifyAttestation(pins, att)
		switch {
		case err != nil:
			v.Reasons = append(v.Reasons, "store attestation not accepted: "+err.Error())
		default:
			v.Expected = append(v.Expected, Expected{From: "attestation", SHA256: a.Artifact.SHA256, Bytes: a.Artifact.Bytes})
			if a.Artifact.SHA256 != sum || a.Artifact.Bytes != size {
				mismatch("Rotten Apple store's signed attestation")
			} else if m != nil && m.AppID != a.AppID {
				v.Reasons = append(v.Reasons, fmt.Sprintf("store attestation is for %s, the app says it is %s", a.AppID, m.AppID))
			} else {
				v.Trusted, v.TrustedBy = true, "rotten-apple-store"
				v.Reasons = append(v.Reasons, fmt.Sprintf("signed by the Rotten Apple store as %s %s", a.AppID, a.Version))
			}
		}
	}
	if ghSum != "" {
		v.Expected = append(v.Expected, Expected{From: "github-sha256sums", SHA256: ghSum})
		if ghSum != sum {
			mismatch("SHA256SUMS of the GitHub release")
		} else {
			v.Reasons = append(v.Reasons, "matches the SHA256SUMS of the GitHub release")
		}
	}
	if m != nil && m.Artifact != nil && m.Artifact.SHA256 != "" {
		v.Expected = append(v.Expected, Expected{From: "manifest", SHA256: m.Artifact.SHA256})
		if m.Artifact.SHA256 != sum {
			mismatch("sha256 in rottencore.json")
		}
	}
	switch {
	case v.Refuse:
		v.Checksum, v.Trusted, v.TrustedBy = "mismatch", false, ""
	case len(v.Expected) == 0:
		v.Checksum = "none"
		v.Reasons = append(v.Reasons, "no checksum is published for this file, so damage or tampering cannot be ruled out")
	default:
		v.Checksum = "match"
	}
	if !v.Trusted {
		v.Warning = UntrustedWarning
		if m != nil && m.Source == SourceStore {
			v.Reasons = append(v.Reasons, "rottencore.json says it is a store app, but there is no valid store signature, so that claim is ignored")
		}
	}
	return v
}
