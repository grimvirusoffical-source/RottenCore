package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// TypeRottenCoreSigned is the payload type field.
const TypeRottenCoreSigned = "rotten_core_signed"

// Issuer is the lifetime cert's issuer. Accounts is the only issuer RottenCore accepts.
const Issuer = "red-x-accounts-owner"

// CertKind is the Accounts document kind for the owner's lifetime certificate.
const CertKind = "rxa-lifetime-cert"

// OfficialOSNote is shown next to every signature. The overlay does not replace notarization
// or Authenticode; it still verifies when those are present.
const OfficialOSNote = "Official OS signing is still recommended. This overlay works either way."

// Cert is the public half of the lifetime certificate carried inside a signature.
// The private key is never a field here.
type Cert struct {
	ID     string `json:"id"`
	PubKey string `json:"pubkey"`
	Issuer string `json:"issuer"`
}

// Payload is one RottenCore lifetime signature.
//
// The ed25519 signature is over Canonical, which is this JSON with sig omitted.
// Field order is part of the signed bytes: type, sig_id, app_id, version, cert
// (id, pubkey, issuer), hash, nonce, prev_sig_id when present, platforms, launcher_required.
type Payload struct {
	Type             string   `json:"type"`
	SigID            string   `json:"sig_id"`
	AppID            string   `json:"app_id"`
	Version          string   `json:"version"`
	Cert             Cert     `json:"cert"`
	Hash             string   `json:"hash"`
	Nonce            string   `json:"nonce"`
	PrevSigID        string   `json:"prev_sig_id,omitempty"`
	Platforms        []string `json:"platforms"`
	LauncherRequired bool     `json:"launcher_required"`
	Sig              string   `json:"sig,omitempty"`
}

var (
	prefixRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-f]+$`)
)

// Wipe zeroes b and keeps it alive so the compiler cannot drop the write.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func encode(p Payload) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Canonical is the exact byte string ed25519 signs: JSON without the sig field.
func Canonical(p Payload) ([]byte, error) {
	p.Sig = ""
	return encode(p)
}

// Marshal is the carrier JSON, including sig. Seal this; do not write it in the clear.
func Marshal(p Payload) ([]byte, error) {
	if p.Sig == "" {
		return nil, errors.New("signature is missing")
	}
	return encode(p)
}

// Parse decodes a carrier. Trailing junk and unknown fields are refused.
func Parse(b []byte) (Payload, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Payload
	if err := dec.Decode(&p); err != nil {
		return Payload{}, errors.New("signature carrier is not RottenCore JSON")
	}
	if dec.More() {
		return Payload{}, errors.New("signature carrier has trailing data")
	}
	return p, nil
}

func (p Payload) validateBody() error {
	if p.Type != TypeRottenCoreSigned {
		return errors.New("not a RottenCore signature")
	}
	if p.SigID == "" || len(p.SigID) > 80 {
		return errors.New("sig_id is missing")
	}
	if p.AppID == "" || p.Version == "" {
		return errors.New("app id and version are required")
	}
	if p.Cert.ID == "" || p.Cert.Issuer != Issuer {
		return errors.New("lifetime cert issuer is not red-x-accounts-owner")
	}
	pub, err := hex.DecodeString(strings.ToLower(p.Cert.PubKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("lifetime cert public key is malformed")
	}
	sum, err := hex.DecodeString(strings.ToLower(p.Hash))
	if err != nil || len(sum) != 32 {
		return errors.New("hash is not a sha256 digest")
	}
	if p.Nonce == "" || len(p.Nonce) > 128 || !hexRe.MatchString(strings.ToLower(p.Nonce)) {
		return errors.New("nonce is missing")
	}
	if len(p.Platforms) == 0 {
		return errors.New("platforms is empty")
	}
	for _, plat := range p.Platforms {
		if !ValidPlatform(plat) {
			return fmt.Errorf("platform %q is not supported", plat)
		}
	}
	return nil
}

// Sign fills sig with ed25519 over Canonical. priv is not retained.
func Sign(priv ed25519.PrivateKey, p Payload) (Payload, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Payload{}, errors.New("the lifetime cert private key is not an ed25519 key")
	}
	if err := p.validateBody(); err != nil {
		return Payload{}, err
	}
	msg, err := Canonical(p)
	if err != nil {
		return Payload{}, err
	}
	p.Sig = hex.EncodeToString(ed25519.Sign(priv, msg))
	return p, nil
}

// Verify checks sig against the lifetime cert public key and Canonical.
func Verify(p Payload) error {
	if err := p.validateBody(); err != nil {
		return err
	}
	sig, err := hex.DecodeString(strings.ToLower(p.Sig))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is malformed")
	}
	pub, err := hex.DecodeString(strings.ToLower(p.Cert.PubKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("lifetime cert public key is malformed")
	}
	msg, err := Canonical(p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// FreshID is prefix plus fresh random, so each signature gets its own sig_id.
func FreshID(prefix string) (string, error) {
	if prefix == "" {
		prefix = "rxa"
	}
	if !prefixRe.MatchString(prefix) {
		return "", errors.New("sig_id_prefix is malformed")
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

// FreshNonce is 32 random bytes, hex encoded.
func FreshNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ParsePrivateKey accepts the decrypted lifetime key as hex (32-byte seed or 64-byte
// Go private key) and checks it against the certificate's public key. On failure the
// material passed in is wiped. The returned key must be wiped by the caller.
func ParsePrivateKey(plain []byte, pubHex string) (ed25519.PrivateKey, error) {
	pub, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		Wipe(plain)
		return nil, errors.New("lifetime cert public key is malformed")
	}
	raw, decErr := hex.DecodeString(strings.ToLower(strings.TrimSpace(string(plain))))
	if decErr != nil {
		raw = append([]byte(nil), plain...)
	}
	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		priv = append(ed25519.PrivateKey(nil), raw...)
	default:
		Wipe(raw)
		Wipe(plain)
		return nil, errors.New("the decrypted lifetime cert private key is not an ed25519 key")
	}
	Wipe(raw)
	got := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(got, pub) {
		Wipe(priv)
		Wipe(plain)
		return nil, errors.New("the decrypted lifetime cert does not match the published public key")
	}
	return priv, nil
}
