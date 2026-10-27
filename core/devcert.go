package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// DevCertPublic is the shareable half of a developer certificate.
// The private key is not a field.
type DevCertPublic struct {
	Email  string `json:"email"`
	CertID string `json:"certId"`
	PubKey string `json:"pubkey"`
	Issuer string `json:"issuer"`
}

type devCertFile struct {
	Schema int             `json:"schema"`
	Certs  []DevCertPublic `json:"certs"`
}

func (c *Core) devCertPath() string {
	return filepath.Join(c.State.Dir, "developer-certs.json")
}

func (c *Core) devPrivAccount(email string) string {
	return "dev-priv:" + strings.ToLower(strings.TrimSpace(email))
}

// EnsureDeveloperCert mints a random ed25519 key for this signed-in account when
// one is not already sealed in the keyring. The keyring holds Red-SecretsXAI
// ciphertext only. Accounts has no API to register the public half; it is recorded
// locally so this computer can verify that developer's signatures.
func (c *Core) EnsureDeveloperCert(ctx context.Context, token string, password []byte, sealer sign.Sealer) (*DevCertPublic, error) {
	defer sign.Wipe(password)
	who, err := c.WhoAmI(ctx, token)
	if err != nil {
		return nil, err
	}
	if who.Email == "" {
		return nil, ErrSignInRequired
	}
	if existing, err := c.devCertFor(who.Email); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	if sealer == nil {
		sealer = sign.RedSecretsXAI{}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer sign.Wipe(priv)
	hexKey := []byte(hex.EncodeToString(priv))
	defer sign.Wipe(hexKey)
	ct, err := sealer.Encrypt(ctx, password, hexKey)
	if err != nil {
		return nil, err
	}
	defer sign.Wipe(ct)
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	rec := DevCertPublic{
		Email:  who.Email,
		CertID: "dev_" + hex.EncodeToString(idb[:]),
		PubKey: hex.EncodeToString(pub),
		Issuer: sign.IssuerDeveloper,
	}
	if err := c.secrets().Put(c.devPrivAccount(who.Email), ct); err != nil {
		return nil, err
	}
	if err := c.putDevCert(rec); err != nil {
		_ = c.secrets().Delete(c.devPrivAccount(who.Email))
		return nil, err
	}
	return &rec, nil
}

func (c *Core) devCertFor(email string) (*DevCertPublic, error) {
	all, err := c.readDevCerts()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if strings.EqualFold(all[i].Email, email) {
			return &all[i], nil
		}
	}
	return nil, nil
}

func (c *Core) knownDevPub(pub string) bool {
	all, err := c.readDevCerts()
	if err != nil {
		return false
	}
	for _, rec := range all {
		if strings.EqualFold(rec.PubKey, pub) && rec.Issuer == sign.IssuerDeveloper {
			return true
		}
	}
	return false
}

func (c *Core) readDevCerts() ([]DevCertPublic, error) {
	b, err := os.ReadFile(c.devCertPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f devCertFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, errors.New("developer-certs.json is damaged")
	}
	return f.Certs, nil
}

func (c *Core) putDevCert(rec DevCertPublic) error {
	all, err := c.readDevCerts()
	if err != nil {
		return err
	}
	all = append(all, rec)
	b, err := json.MarshalIndent(devCertFile{Schema: 1, Certs: all}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(c.devCertPath(), append(b, '\n'))
}

func (c *Core) unlockDevKey(ctx context.Context, email string, password []byte, pub string, sealer sign.Sealer) (ed25519.PrivateKey, error) {
	ct, err := c.secrets().Get(c.devPrivAccount(email))
	if err != nil || len(ct) == 0 {
		return nil, errors.New("this account has no developer certificate in the keyring")
	}
	defer sign.Wipe(ct)
	plain, err := sealer.Decrypt(ctx, password, ct)
	if err != nil {
		sign.Wipe(plain)
		return nil, err
	}
	defer sign.Wipe(plain)
	return sign.ParsePrivateKey(plain, pub)
}

// SignDeveloper signs with this account's own certificate. The launcher has to be
// installed and running. The owner lifetime key is not used.
func (c *Core) SignDeveloper(ctx context.Context, token string, password []byte, path, platform string, sealer sign.Sealer) (*SignResult, error) {
	pw := append([]byte(nil), password...)
	defer sign.Wipe(password)
	defer sign.Wipe(pw)
	rec, err := c.EnsureDeveloperCert(ctx, token, append([]byte(nil), pw...), sealer)
	if err != nil {
		return nil, err
	}
	who, err := c.WhoAmI(ctx, token)
	if err != nil {
		return nil, err
	}
	_, installed, running := LauncherStatus()
	if err := sign.Allow(runtime.GOOS, platform, sign.RoleDev, true, installed, running); err != nil {
		return nil, err
	}
	if sealer == nil {
		sealer = sign.RedSecretsXAI{}
	}
	key, err := c.unlockDevKey(ctx, who.Email, pw, rec.PubKey, sealer)
	if err != nil {
		return nil, err
	}
	defer sign.Wipe(key)
	cert := &LifetimeCert{Kind: "rotten-core-developer", CertID: rec.CertID, PubKey: rec.PubKey, SigIDPrefix: "dev"}
	return c.sealSigned(ctx, key, cert, path, platform, true, sealer, pw)
}
