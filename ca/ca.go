package ca

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/seal"
)

// Magnitude (docs/CERTGEN.md §1): key strength and validity by account level. Configurable with a
// JSON file (LoadTiers); these are the defaults Josh chose.
type Tier struct {
	Name         string `json:"name"`
	Alg          string `json:"alg"` // ed25519 | p384
	ValidityDays int    `json:"validityDays"`
	RenewDays    int    `json:"renewBeforeDays"`
}

// Tier names.
const (
	TierStandard = "standard" // developer accounts
	TierMega     = "mega"     // Mega developers (Josh's lifetime Mega first)
	TierOwner    = "owner"    // owners and admins, Red-XAI first-party apps
	TierService  = "service"  // Red-XAI Host update-signer keys
	TierIssuing  = "issuing"  // ra-core issuing CA (intermediate)
	TierRoot     = "root"     // offline root
)

// DefaultTiers: Ed25519 for standard, P-384 for Mega, owner/admin, issuing and root.
func DefaultTiers() map[string]Tier {
	return map[string]Tier{
		TierStandard: {TierStandard, core.AlgEd25519, 365, 30},
		TierMega:     {TierMega, core.AlgP384, 730, 60},
		TierOwner:    {TierOwner, core.AlgP384, 730, 60},
		TierService:  {TierService, core.AlgP384, 365, 30},
		TierIssuing:  {TierIssuing, core.AlgP384, 5 * 365, 365},
		TierRoot:     {TierRoot, core.AlgP384, 20 * 365, 2 * 365},
	}
}

// LoadTiers reads a tiers file over the defaults; unknown algorithms are refused.
func LoadTiers(path string) (map[string]Tier, error) {
	t := DefaultTiers()
	if path == "" {
		return t, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var over map[string]Tier
	if err := json.Unmarshal(b, &over); err != nil {
		return nil, fmt.Errorf("tiers file: %w", err)
	}
	for k, v := range over {
		if v.Alg != core.AlgEd25519 && v.Alg != core.AlgP384 {
			return nil, fmt.Errorf("tier %s: algorithm %q is not ed25519 or p384", k, v.Alg)
		}
		if v.ValidityDays <= 0 || v.ValidityDays > 30*365 {
			return nil, fmt.Errorf("tier %s: validity must be 1..10950 days", k)
		}
		v.Name = k
		t[k] = v
	}
	return t, nil
}

// TierForRole maps a Red-XAI Accounts / store role to a tier. The CA decides the tier from the account,
// never from the request.
func TierForRole(role string, mega bool) string {
	switch role {
	case "owner", "admin":
		return TierOwner
	}
	if mega {
		return TierMega
	}
	return TierStandard
}

// GenerateKey makes a key for alg from the mixer's material (OS CSPRNG + white noise via HKDF-SHA-512).
func GenerateKey(ctx context.Context, m *Mixer, alg, info string) (core.Signer, []Health, error) {
	switch alg {
	case core.AlgEd25519:
		seed, h, err := m.Material(ctx, "ed25519|"+info, ed25519.SeedSize)
		if err != nil {
			return nil, h, err
		}
		return core.Ed25519Signer{Key: ed25519.NewKeyFromSeed(seed)}, h, nil
	case core.AlgP384:
		// Derive the scalar explicitly (newer Go ignores custom randomness in ecdsa.GenerateKey): take 48
		// bytes, reject 0 and >= n (crypto/ecdh enforces the range), retry with a counter.
		for ctr := 0; ctr < 64; ctr++ {
			d, h, err := m.Material(ctx, fmt.Sprintf("p384|%s|%d", info, ctr), 48)
			if err != nil {
				return nil, h, err
			}
			k, err := ecdh.P384().NewPrivateKey(d)
			if err != nil {
				continue
			}
			x, y := elliptic.Unmarshal(elliptic.P384(), k.PublicKey().Bytes()) //nolint:staticcheck // validated point
			priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, D: new(big.Int).SetBytes(d)}
			return core.P384Signer{Key: priv}, h, nil
		}
		return nil, nil, errors.New("could not derive a P-384 key")
	}
	return nil, nil, fmt.Errorf("unknown algorithm %q", alg)
}

// KeyFile is a private key on disk. It goes through the ENCRYPTION-HOOK before writing; today that is a
// no-op, so the file is plain JSON with mode 0600.
type KeyFile struct {
	Alg     string `json:"alg"`
	Private string `json:"private"` // base64: Ed25519 seed (32) or P-384 scalar (48)
	Public  string `json:"public"`  // base64
	Sealer  string `json:"sealer"`  // seal ID used ("none" = not encrypted)
}

func privBytes(k core.Signer) []byte {
	switch s := k.(type) {
	case core.Ed25519Signer:
		return s.Key.Seed()
	case core.P384Signer:
		b := make([]byte, 48)
		s.Key.D.FillBytes(b)
		return b
	}
	return nil
}

// WriteKey writes a private key file (0600, never overwrites).
func WriteKey(path string, k core.Signer) error {
	pb := privBytes(k)
	// ENCRYPTION-HOOK: certgen.private-key — private key bytes before they are written to disk.
	sealed, err := seal.Current().Seal(seal.PrivateKey, pb, []byte("key:"+core.KeyFingerprint(k.Public())))
	if err != nil {
		return err
	}
	kf := KeyFile{Alg: k.Alg(), Private: base64.StdEncoding.EncodeToString(sealed), Public: base64.StdEncoding.EncodeToString(k.Public()), Sealer: seal.Current().ID()}
	b, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// ReadKey loads a key file.
func ReadKey(path string) (core.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(kf.Private)
	if err != nil {
		return nil, errors.New("key file: private key is not base64")
	}
	pub, _ := base64.StdEncoding.DecodeString(kf.Public)
	if kf.Sealer != seal.Current().ID() {
		return nil, fmt.Errorf("key file was sealed with %q but %q is active", kf.Sealer, seal.Current().ID())
	}
	// ENCRYPTION-HOOK: certgen.private-key-open — private key bytes after reading from disk.
	pb, err := seal.Current().Open(seal.PrivateKey, raw, []byte("key:"+core.KeyFingerprint(pub)))
	if err != nil {
		return nil, err
	}
	return signerFromPriv(kf.Alg, pb)
}

// signerFromPriv rebuilds a signer from its algorithm and raw private bytes (Ed25519 seed or P-384 scalar).
func signerFromPriv(alg string, pb []byte) (core.Signer, error) {
	switch alg {
	case core.AlgEd25519:
		if len(pb) != ed25519.SeedSize {
			return nil, errors.New("bad Ed25519 seed")
		}
		return core.Ed25519Signer{Key: ed25519.NewKeyFromSeed(pb)}, nil
	case core.AlgP384:
		k, err := ecdh.P384().NewPrivateKey(pb)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(elliptic.P384(), k.PublicKey().Bytes()) //nolint:staticcheck
		return core.P384Signer{Key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, D: new(big.Int).SetBytes(pb)}}, nil
	}
	return nil, fmt.Errorf("unknown algorithm %q", alg)
}

// CertBundle is a certificate chain plus where its private key is. Written through the cert-bundle hook.
type CertBundle struct {
	Chain   []core.Cert `json:"chain"`
	KeyFile string      `json:"keyFile,omitempty"`
	Tier    string      `json:"tier"`
}

// WriteBundle writes a bundle (0600).
func WriteBundle(path string, b CertBundle) error {
	j, _ := json.MarshalIndent(b, "", "  ")
	// ENCRYPTION-HOOK: certgen.cert-bundle — certificate bundle file (the chain alone stays plain wherever it
	// is published: in .rasig files, /v1/updates/keys and /v1/ca/chain).
	out, err := seal.Current().Seal(seal.CertBundle, j, []byte("bundle:"+b.Chain[0].Fingerprint()))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// ReadBundle reads a bundle.
func ReadBundle(path string) (*CertBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// ENCRYPTION-HOOK: certgen.cert-bundle-open — certificate bundle file after reading.
	plain, err := seal.Current().Open(seal.CertBundle, bytes.TrimSpace(b), nil)
	if err != nil {
		return nil, err
	}
	var cb CertBundle
	if err := json.Unmarshal(plain, &cb); err != nil {
		return nil, err
	}
	return &cb, nil
}

// Authority is a CA: its own chain (issuing cert .. root) and key.
type Authority struct {
	Key   core.Signer
	Chain []core.Cert // [this CA's cert, ..., root cert]; a root's chain is just itself
	Tiers map[string]Tier
	Mixer *Mixer
	Test  bool // TEST CA: everything it issues has test:true (refused by production verifiers)
	Now   func() time.Time
	// Serial makes serial numbers; default: unix nanos.
	Serial func() string
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Authority) serial() string {
	if a.Serial != nil {
		return a.Serial()
	}
	return fmt.Sprintf("%d", a.now().UnixNano())
}

// NewRoot generates a root CA (self-signed; tier root). test marks it as a TEST root.
func NewRoot(ctx context.Context, m *Mixer, tiers map[string]Tier, name string, test bool, now time.Time) (*Authority, []Health, error) {
	t := tiers[TierRoot]
	k, h, err := GenerateKey(ctx, m, t.Alg, "root|"+name)
	if err != nil {
		return nil, h, err
	}
	c := core.Cert{Serial: "root-" + fmt.Sprint(now.Unix()), Kind: core.CertKindCA, Alg: k.Alg(), Subject: core.CertSubject{Name: name}, PublicKey: k.Public(),
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.AddDate(0, 0, t.ValidityDays).Unix(), Test: test}
	if err := core.SignCertWith(&c, k); err != nil {
		return nil, h, err
	}
	return &Authority{Key: k, Chain: []core.Cert{c}, Tiers: tiers, Mixer: m, Test: test}, h, nil
}

// Root returns the root entry verifiers pin (core.CARoot).
func (a *Authority) Root() core.CARoot {
	r := a.Chain[len(a.Chain)-1]
	return core.CARoot{Name: r.Subject.Name, Alg: r.Alg, PublicKey: r.PublicKey, Test: r.Test}
}

// IssueIntermediate makes the ra-core issuing CA under this root.
func (a *Authority) IssueIntermediate(ctx context.Context, name string) (*Authority, []Health, error) {
	t := a.Tiers[TierIssuing]
	k, h, err := GenerateKey(ctx, a.Mixer, t.Alg, "issuing|"+name)
	if err != nil {
		return nil, h, err
	}
	now := a.now()
	c := core.Cert{Serial: a.serial(), Kind: core.CertKindCA, Alg: k.Alg(), Subject: core.CertSubject{Name: name}, PublicKey: k.Public(),
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.AddDate(0, 0, t.ValidityDays).Unix(), Test: a.Test}
	if err := core.SignCertWith(&c, a.Key); err != nil {
		return nil, h, err
	}
	// the chain carried in signatures excludes the root (verifiers pin it); keep it here for Root()
	return &Authority{Key: k, Chain: append([]core.Cert{c}, a.Chain...), Tiers: a.Tiers, Mixer: a.Mixer, Test: a.Test, Now: a.Now, Serial: a.Serial}, h, nil
}

// PublicChain is the chain a leaf carries: leaf, then this CA's certificates without the pinned root.
func (a *Authority) PublicChain(leaf core.Cert) []core.Cert {
	out := []core.Cert{leaf}
	if len(a.Chain) > 1 {
		out = append(out, a.Chain[:len(a.Chain)-1]...)
	} else {
		out = append(out, a.Chain...)
	}
	return out
}

// Request is a certificate signing request. The key holder makes it (the CA never sees developer private
// keys) and proves possession by signing it.
type Request struct {
	V         int              `json:"v"`
	Alg       string           `json:"alg"`
	PublicKey []byte           `json:"publicKey"`
	Subject   core.CertSubject `json:"subject"`
	Kind      string           `json:"kind"` // developer | update-signer
	CreatedMs int64            `json:"createdMs"`
	PoP       []byte           `json:"pop,omitempty"` // signature by the key over "RACORE-CSR-v1\0" || canonical request without pop
}

const csrDomain = "RACORE-CSR-v1\x00"

func (r *Request) tbs() []byte {
	t := *r
	t.PoP = nil
	b, _ := json.Marshal(&t)
	return append([]byte(csrDomain), b...)
}

// NewRequest makes and signs a request with the holder's key.
func NewRequest(k core.Signer, sub core.CertSubject, kind string, now time.Time) (*Request, error) {
	r := &Request{V: 1, Alg: k.Alg(), PublicKey: k.Public(), Subject: sub, Kind: kind, CreatedMs: now.UnixMilli()}
	sig, err := k.Sign(r.tbs())
	if err != nil {
		return nil, err
	}
	r.PoP = sig
	return r, nil
}

// Account is what ra-core knows about the requester (from Red-XAI Accounts + the store), not from the request.
type Account struct {
	DevID  string
	TeamID string
	Name   string
	Role   string // developer | owner | admin
	Mega   bool   // holds a Mega license (Josh: lifetime)
}

// Issue verifies the request's proof of possession, picks the tier from the account (magnitude), and
// issues the certificate. Requests whose key algorithm does not match the tier are refused, so the
// holder must generate the right key type (Rotten Core does this from the tier the store reports).
func (a *Authority) Issue(r *Request, acct Account) (*core.Cert, []core.Cert, error) {
	if r == nil || r.V != 1 {
		return nil, nil, errors.New("bad request")
	}
	if !core.VerifySig(r.Alg, r.PublicKey, r.tbs(), r.PoP) {
		return nil, nil, errors.New("the request is not signed by its own key (proof of possession failed)")
	}
	tierName := TierForRole(acct.Role, acct.Mega)
	if r.Kind == core.CertKindUpdateSigner {
		tierName = TierService
		if acct.Role != "owner" && acct.Role != "admin" {
			return nil, nil, errors.New("only owners and admins can get update-signer certificates")
		}
	} else if r.Kind != core.CertKindDeveloper {
		return nil, nil, fmt.Errorf("cannot issue a %q certificate", r.Kind)
	}
	t := a.Tiers[tierName]
	if r.Alg != t.Alg {
		return nil, nil, fmt.Errorf("the %s tier needs a %s key, the request has %s", tierName, t.Alg, r.Alg)
	}
	now := a.now()
	c := core.Cert{Serial: a.serial(), Kind: r.Kind, Alg: r.Alg, PublicKey: r.PublicKey,
		Subject:   core.CertSubject{Name: firstNonEmpty(acct.Name, r.Subject.Name), TeamID: acct.TeamID, DevID: acct.DevID},
		NotBefore: now.Add(-5 * time.Minute).Unix(), NotAfter: now.AddDate(0, 0, t.ValidityDays).Unix(), Test: a.Test}
	if c.Alg == core.AlgEd25519 && a.Key.Alg() == core.AlgEd25519 {
		c.Alg = "" // v1, byte-identical to rarxai
	}
	if err := core.SignCertWith(&c, a.Key); err != nil {
		return nil, nil, err
	}
	return &c, a.PublicChain(c), nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// IssueUpdateSigner certifies an existing Red-XAI Host update key (the RedX host keeps its private key;
// this only needs its public key, base64 as served at /v1/updates/keys). Owner/admin action.
func (a *Authority) IssueUpdateSigner(alg string, pub []byte, host string, acct Account) (*core.Cert, []core.Cert, error) {
	if acct.Role != "owner" && acct.Role != "admin" {
		return nil, nil, errors.New("only owners and admins can certify a host update key")
	}
	t := a.Tiers[TierService]
	now := a.now()
	c := core.Cert{Serial: a.serial(), Kind: core.CertKindUpdateSigner, Alg: alg, PublicKey: pub,
		Subject:   core.CertSubject{Name: host, TeamID: acct.TeamID, DevID: "host:" + host},
		NotBefore: now.Add(-5 * time.Minute).Unix(), NotAfter: now.AddDate(0, 0, t.ValidityDays).Unix(), Test: a.Test}
	if err := core.SignCertWith(&c, a.Key); err != nil {
		return nil, nil, err
	}
	return &c, a.PublicChain(c), nil
}

// RevocationList is the CA side of revocation: entries become the store's signed status ticket.
type RevocationList struct {
	Certs  []string `json:"certs"`  // certificate fingerprints (Ed25519 and P-384 certs alike)
	Builds []string `json:"builds"` // sha256:<hex>
	Apps   []string `json:"apps"`
	Seq    int64    `json:"seq"`
}

// Revoke adds an entry (cert fingerprint, build hash or app id) and bumps the sequence.
func (l *RevocationList) Revoke(kind, value string) error {
	switch kind {
	case "cert":
		if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
			return errors.New("cert revocations are certificate fingerprints sha256:<64 hex>")
		}
		l.Certs = addSorted(l.Certs, value)
	case "build":
		if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
			return errors.New("build revocations are sha256:<64 hex>")
		}
		l.Builds = addSorted(l.Builds, value)
	case "app":
		l.Apps = addSorted(l.Apps, value)
	default:
		return fmt.Errorf("unknown revocation kind %q", kind)
	}
	l.Seq++
	return nil
}

func addSorted(l []string, v string) []string {
	i := sort.SearchStrings(l, v)
	if i < len(l) && l[i] == v {
		return l
	}
	l = append(l, "")
	copy(l[i+1:], l[i:])
	l[i] = v
	return l
}

// Ticket signs the list as the store's status ticket (store key, Ed25519, 6 h life).
func (l *RevocationList) Ticket(storeKey ed25519.PrivateKey, now time.Time) (*core.Signed, error) {
	return core.SignStatusTicket(storeKey, core.StatusTicket{IssuedMs: now.UnixMilli(), ExpiresMs: now.Add(core.StatusTicketTTL).UnixMilli(),
		RevokedCerts: append([]string{}, l.Certs...), RevokedBuilds: append([]string{}, l.Builds...), RevokedApps: append([]string{}, l.Apps...)})
}

// SignIntermediateRequest signs an ra-core issuing CA certificate from a CSR whose key was generated where
// the intermediate will live (so the issuing private key never travels to the root). The CSR's kind must be
// core.CertKindCA and its proof of possession must verify. Returns the new Authority rooted at this CA (its
// chain is [issuing, ...this chain]); the issuing key is held by the CSR's maker, not here.
func (a *Authority) SignIntermediateRequest(r *Request, name string) (*core.Cert, []core.Cert, error) {
	if r == nil || r.V != 1 || r.Kind != core.CertKindCA {
		return nil, nil, errors.New("not a CA certificate request")
	}
	if !core.VerifySig(r.Alg, r.PublicKey, r.tbs(), r.PoP) {
		return nil, nil, errors.New("the request is not signed by its own key (proof of possession failed)")
	}
	t := a.Tiers[TierIssuing]
	if r.Alg != t.Alg {
		return nil, nil, fmt.Errorf("the issuing tier needs a %s key, the request has %s", t.Alg, r.Alg)
	}
	now := a.now()
	c := core.Cert{Serial: a.serial(), Kind: core.CertKindCA, Alg: r.Alg, PublicKey: r.PublicKey,
		Subject:   core.CertSubject{Name: firstNonEmpty(name, r.Subject.Name)},
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.AddDate(0, 0, t.ValidityDays).Unix(), Test: a.Test}
	if err := core.SignCertWith(&c, a.Key); err != nil {
		return nil, nil, err
	}
	// chain for leaves issued under this new CA: [issuing, this CA's chain without the pinned root is handled
	// by PublicChain]; here we return the CA cert plus this authority's chain for reference.
	return &c, append([]core.Cert{c}, a.Chain...), nil
}
