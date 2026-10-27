package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// ErrNotOurs means the file is not a RottenCore signature. It is not installed.
var ErrNotOurs = errors.New("this file is not signed by RottenCore")

func certIssuer(cert *LifetimeCert) string {
	if cert != nil && cert.Kind == "rotten-core-developer" {
		return sign.IssuerDeveloper
	}
	return sign.Issuer
}

func (c *Core) writeRedX(ctx context.Context, sealer sign.Sealer, password, raw []byte, artifact string) error {
	fs, ok := sealer.(sign.FileSealer)
	if !ok {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(artifact), ".rc-sign-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.Write(raw)
	cerr := f.Close()
	defer func() {
		if b, rerr := os.ReadFile(name); rerr == nil {
			sign.Wipe(b)
			_ = os.WriteFile(name, b, 0o600)
		}
		os.Remove(name)
	}()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	produced, err := fs.EncryptFile(ctx, password, name)
	if err != nil {
		return err
	}
	want := artifact + sign.FileExt
	if produced != want {
		if err := os.Rename(produced, want); err != nil {
			return err
		}
	}
	return os.Chmod(want, 0o600)
}

func (c *Core) rememberOwnerPub(cert *LifetimeCert) error {
	if c == nil || c.State == nil || cert == nil || cert.PubKey == "" {
		return nil
	}
	b, err := json.Marshal(map[string]string{
		"certId": cert.CertID,
		"pubkey": strings.ToLower(cert.PubKey),
	})
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(c.State.Dir, "owner-pub.json"), append(b, '\n'))
}

func (c *Core) ownerPub() (string, error) {
	if c == nil || c.State == nil {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Join(c.State.Dir, "owner-pub.json"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var m struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", errors.New("owner-pub.json is damaged")
	}
	return m.PubKey, nil
}

// TrustPayload checks the ed25519 signature and that the key is one RottenCore
// has already seen: the owner lifetime pubkey, or a developer cert minted here.
func (c *Core) TrustPayload(p sign.Payload) error {
	if err := sign.Verify(p); err != nil {
		return err
	}
	switch p.Cert.Issuer {
	case sign.Issuer:
		known, err := c.ownerPub()
		if err != nil {
			return err
		}
		if known == "" || !strings.EqualFold(known, p.Cert.PubKey) {
			return errors.New("owner signature is not from the lifetime certificate on this computer")
		}
	case sign.IssuerDeveloper:
		if !c.knownDevPub(p.Cert.PubKey) {
			return errors.New("developer signature is not from a certificate minted on this computer")
		}
	default:
		return errors.New("unknown signature issuer")
	}
	return nil
}

// OpenSigned detects a red-X carrier or RXAI2 sidecar, decrypts it, verifies it,
// and installs the artifact. Anything that is not ours is refused with ErrNotOurs
// and is not installed. Store trust is unchanged: a non-store app still needs
// AcceptUntrusted.
func (c *Core) OpenSigned(ctx context.Context, path string, password []byte, accept bool, sealer sign.Sealer) (*Entry, error) {
	defer sign.Wipe(password)
	if sealer == nil {
		sealer = sign.RedSecretsXAI{}
	}
	artifact, payload, cleanup, err := c.readCarrier(ctx, path, password, sealer)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}
	if err := c.TrustPayload(payload); err != nil {
		return nil, err
	}
	sum, _, err := FileSHA256(artifact)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(sum, payload.Hash) {
		return nil, errors.New("the signature is not for this file")
	}
	in, err := c.Inspect(ctx, artifact, nil)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	return c.Install(ctx, in, InstallOptions{AcceptUntrusted: accept})
}

func (c *Core) readCarrier(ctx context.Context, path string, password []byte, sealer sign.Sealer) (artifact string, payload sign.Payload, cleanup func(), err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", sign.Payload{}, nil, err
	}
	carrier, artifact := abs, ""
	switch {
	case strings.HasSuffix(abs, sign.FileExt):
		artifact = strings.TrimSuffix(abs, sign.FileExt)
	case strings.HasSuffix(abs, ".rotten_core_signed"):
		artifact = strings.TrimSuffix(abs, ".rotten_core_signed")
	default:
		artifact = abs
		switch {
		case fileExists(abs + sign.FileExt):
			carrier = abs + sign.FileExt
		case fileExists(abs + ".rotten_core_signed"):
			carrier = abs + ".rotten_core_signed"
		default:
			return "", sign.Payload{}, nil, ErrNotOurs
		}
	}
	if _, err := os.Stat(artifact); err != nil {
		return "", sign.Payload{}, nil, ErrNotOurs
	}
	plain, cleanup, err := c.decryptCarrier(ctx, carrier, password, sealer)
	if err != nil {
		return "", sign.Payload{}, cleanup, err
	}
	payload, err = sign.Parse(plain)
	sign.Wipe(plain)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return "", sign.Payload{}, nil, ErrNotOurs
	}
	return artifact, payload, cleanup, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (c *Core) decryptCarrier(ctx context.Context, carrier string, password []byte, sealer sign.Sealer) ([]byte, func(), error) {
	if strings.HasSuffix(carrier, sign.FileExt) {
		fs, ok := sealer.(sign.FileSealer)
		if !ok {
			return nil, nil, errors.New("this Red-SecretsXAI sealer cannot open a .Red_SecretXAI file")
		}
		dir, err := os.MkdirTemp(c.TmpDir, "open-")
		if err != nil {
			if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
				return nil, nil, err
			}
			dir, err = os.MkdirTemp(c.TmpDir, "open-")
			if err != nil {
				return nil, nil, err
			}
		}
		out, err := fs.DecryptFile(ctx, password, carrier, dir)
		if err != nil {
			os.RemoveAll(dir)
			return nil, nil, err
		}
		b, err := os.ReadFile(out)
		if err != nil {
			os.RemoveAll(dir)
			return nil, nil, err
		}
		return b, func() {
			sign.Wipe(b)
			_ = os.WriteFile(out, bytes.Repeat([]byte{0}, len(b)), 0o600)
			os.RemoveAll(dir)
		}, nil
	}
	raw, err := os.ReadFile(carrier)
	if err != nil {
		return nil, nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte(sign.TextPrefix)) {
		return nil, nil, ErrNotOurs
	}
	plain, err := sealer.Decrypt(ctx, password, trimmed)
	if err != nil {
		sign.Wipe(plain)
		return nil, nil, err
	}
	return plain, func() { sign.Wipe(plain) }, nil
}
