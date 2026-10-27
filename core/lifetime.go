package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// RoleOwner is the lifetime-cert owner role. Callers compare Who.Role to this.
const RoleOwner = sign.RoleOwner

// Wipe zeroes secret bytes. Callers outside internal/sign should use this.
func Wipe(b []byte) { sign.Wipe(b) }

// Lifetime signing. The private key is decrypted in memory, used, and wiped.
// It is never written to the support folder, the carrier, or an error string.
// The carrier on disk is Red-SecretsXAI ciphertext of the signed JSON.

const (
	// ErrOwnerSession is returned when a non-owner asks this process to decrypt the lifetime key.
	ErrOwnerSession = errString("only an owner session can use the lifetime cert private key")
	// ErrKeyWithheld is returned when Accounts did not include private_enc.
	ErrKeyWithheld = errString("the lifetime cert private key is readable only by an owner session")
	// ErrAgentDown means a developer (or --via-agent) has no unlocked agent to ask.
	ErrAgentDown = errString("the signing agent is not running; an owner has to unlock it on this Mac")
	// ErrNotOwnerUnlock is returned when a developer tries to start the agent.
	ErrNotOwnerUnlock = errString("only an owner session can unlock the lifetime cert")
)

type errString string

func (e errString) Error() string { return string(e) }

// SignResult is what `rottencore sign --json` prints. It has no key material.
type SignResult struct {
	Type              string   `json:"type"`
	SigID             string   `json:"sigId"`
	AppID             string   `json:"appId"`
	Version           string   `json:"version"`
	Hash              string   `json:"hash"`
	Platforms         []string `json:"platforms"`
	LauncherRequired  bool     `json:"launcherRequired"`
	CertID            string   `json:"certId"`
	Output            string   `json:"output"`
	OfficialOSSigning string   `json:"officialOSSigning"`
	PrevSigID         string   `json:"prevSigId,omitempty"`
}

// Who is the signed-in account as the Sign panel needs it. No token and no private key.
type Who struct {
	Role              string   `json:"role"`
	Email             string   `json:"email"`
	Verified          bool     `json:"verified"`
	IDVerified        bool     `json:"idVerified"`
	IDVerifiedMs      int64    `json:"idVerifiedMs"`
	MFA               bool     `json:"mfa"`
	Platforms         []string `json:"platforms"`
	LauncherInstalled bool     `json:"launcherInstalled"`
	LauncherRunning   bool     `json:"launcherRunning"`
	AgentRunning      bool     `json:"agentRunning"`
	OfficialOSSigning string   `json:"officialOSSigning"`
}

func (c *Core) accounts() (*OIDCAccounts, error) {
	o, ok := c.Accounts.(*OIDCAccounts)
	if !ok || o == nil {
		return nil, ErrAccountsComingSoon
	}
	return o, nil
}

func (c *Core) loadAccount(ctx context.Context, token string) (*Profile, *LifetimeCert, string, error) {
	o, err := c.accounts()
	if err != nil {
		return nil, nil, "", err
	}
	if err := o.UseToken(token); err != nil {
		return nil, nil, "", err
	}
	prof, err := o.Profile(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	cert, cerr := o.LifetimeCert(ctx)
	if cert == nil {
		cert = &LifetimeCert{}
	}
	role := sign.RoleForCert(prof.Email, prof.Verified, prof.IDVerified, prof.MFA, cert.OwnerEmails)
	if cerr != nil && sign.RoleFromProfile(prof.Email, prof.Verified, prof.IDVerified, prof.MFA) == sign.RoleOwner {
		return prof, cert, role, cerr
	}
	return prof, cert, role, nil
}

// WhoAmI describes the access token's account, the platform matrix, and the launcher.
func (c *Core) WhoAmI(ctx context.Context, token string) (*Who, error) {
	prof, _, _, err := c.loadAccount(ctx, token)
	if err != nil {
		return nil, err
	}
	plats, err := sign.HostPlatforms(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	_, installed, running := LauncherStatus()
	return &Who{
		Role:              sign.RoleFromProfile(prof.Email, prof.Verified, prof.IDVerified, prof.MFA),
		Email:             prof.Email,
		Verified:          prof.Verified,
		IDVerified:        prof.IDVerified,
		IDVerifiedMs:      prof.IDVerifiedMs,
		MFA:               prof.MFA,
		Platforms:         plats,
		LauncherInstalled: installed,
		LauncherRunning:   running,
		AgentRunning:      c.AgentRunning(),
		OfficialOSSigning: sign.OfficialOSNote,
	}, nil
}

// SignLifetime signs path with the owner's lifetime certificate.
// password decrypts private_enc and seals the carrier; it is wiped before return.
// A developer token is refused here even if Accounts attached a ciphertext.
func (c *Core) SignLifetime(ctx context.Context, token string, password []byte, path, platform string, withLauncher bool, sealer sign.Sealer) (*SignResult, error) {
	defer sign.Wipe(password)
	_, cert, role, err := c.loadAccount(ctx, token)
	if err != nil {
		return nil, err
	}
	if role != sign.RoleOwner {
		return nil, ErrOwnerSession
	}
	_, installed, running := LauncherStatus()
	if err := sign.Allow(runtime.GOOS, platform, role, withLauncher, installed, running); err != nil {
		return nil, err
	}
	if cert.PrivateEnc == "" || cert.Kind != sign.CertKind {
		return nil, ErrKeyWithheld
	}
	key, err := unlockKey(ctx, sealerOr(sealer), password, cert)
	if err != nil {
		return nil, err
	}
	defer sign.Wipe(key)
	return c.sealSigned(ctx, key, cert, path, platform, withLauncher, sealerOr(sealer), password)
}

func unlockKey(ctx context.Context, sealer sign.Sealer, password []byte, cert *LifetimeCert) (ed25519.PrivateKey, error) {
	enc := []byte(cert.PrivateEnc)
	cert.PrivateEnc = ""
	plain, err := sealer.Decrypt(ctx, password, enc)
	sign.Wipe(enc)
	if err != nil {
		sign.Wipe(plain)
		return nil, err
	}
	defer sign.Wipe(plain)
	return sign.ParsePrivateKey(plain, cert.PubKey)
}

func sealerOr(s sign.Sealer) sign.Sealer {
	if s == nil {
		return sign.RedSecretsXAI{}
	}
	return s
}

func (c *Core) sealSigned(ctx context.Context, key ed25519.PrivateKey, cert *LifetimeCert, path, platform string, withLauncher bool, sealer sign.Sealer, password []byte) (*SignResult, error) {
	appID, version, sum, cleanup, err := c.identity(ctx, path)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}
	unlock, err := c.chainLock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	prev, err := c.prevSig(appID)
	if err != nil {
		return nil, err
	}
	sigID, err := sign.FreshID(cert.SigIDPrefix)
	if err != nil {
		return nil, err
	}
	nonce, err := sign.FreshNonce()
	if err != nil {
		return nil, err
	}
	body := sign.Payload{
		Type:    sign.TypeRottenCoreSigned,
		SigID:   sigID,
		AppID:   appID,
		Version: version,
		Cert: sign.Cert{
			ID:     cert.CertID,
			PubKey: strings.ToLower(cert.PubKey),
			Issuer: certIssuer(cert),
		},
		Hash:             sum,
		Nonce:            nonce,
		PrevSigID:        prev,
		Platforms:        []string{platform},
		LauncherRequired: withLauncher,
	}
	signed, err := sign.Sign(key, body)
	if err != nil {
		return nil, err
	}
	raw, err := sign.Marshal(signed)
	if err != nil {
		return nil, err
	}
	defer sign.Wipe(raw)
	ct, err := sealer.Encrypt(ctx, password, raw)
	if err != nil {
		return nil, err
	}
	out := path + ".rotten_core_signed"
	if err := writePrivate(out, append(append([]byte{}, ct...), '\n')); err != nil {
		return nil, err
	}
	if err := c.writeRedX(ctx, sealer, password, raw, path); err != nil {
		os.Remove(out)
		return nil, err
	}
	if certIssuer(cert) == sign.Issuer {
		if err := c.rememberOwnerPub(cert); err != nil {
			os.Remove(out)
			os.Remove(path + sign.FileExt)
			return nil, err
		}
	}
	if err := c.putSig(appID, sigID); err != nil {
		os.Remove(out)
		os.Remove(path + sign.FileExt)
		return nil, err
	}
	return &SignResult{
		Type:              sign.TypeRottenCoreSigned,
		SigID:             sigID,
		AppID:             appID,
		Version:           version,
		Hash:              sum,
		Platforms:         []string{platform},
		LauncherRequired:  withLauncher,
		CertID:            cert.CertID,
		Output:            out,
		OfficialOSSigning: sign.OfficialOSNote,
		PrevSigID:         prev,
	}, nil
}

func (c *Core) identity(ctx context.Context, path string) (appID, version, sum string, cleanup func(), err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", "", nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", "", "", nil, err
	}
	kind := KindOf(abs)
	if st.IsDir() && kind != KindApp {
		return "", "", "", nil, fmt.Errorf("%s is not an app RottenCore can sign", filepath.Base(abs))
	}
	var mf []byte
	switch kind {
	case KindApp:
		if f := fromDir(abs, "app"); f != nil {
			mf = f.manifest
		}
	case KindZIP:
		if f := fromZip(abs); f != nil {
			mf = f.manifest
		}
	case KindDMG:
		if c.Engine == nil {
			break
		}
		if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
			return "", "", "", nil, err
		}
		mp, detach, merr := c.Engine.Mount(ctx, abs, c.TmpDir)
		if merr == nil {
			cleanup = detach
			if f := fromDir(mp, "dmg"); f != nil {
				mf = f.manifest
			}
			if mf == nil {
				if p, k, ferr := FindPayload(mp, nil); ferr == nil && k == KindApp {
					if f := fromDir(p, "dmg-app"); f != nil {
						mf = f.manifest
					}
				}
			}
		}
	case KindPKG:
		if c.Engine != nil {
			if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
				return "", "", "", nil, err
			}
			if f := fromPkg(ctx, c.Engine.R, abs, c.TmpDir); f != nil {
				mf = f.manifest
			}
		}
	}
	if mf == nil {
		mf = readSmall(abs + "." + strings.TrimSuffix(ManifestName, ".json") + ".json")
	}
	if mf != nil {
		m, perr := ParseManifest(mf)
		if perr != nil {
			return "", "", "", cleanup, perr
		}
		appID, version = m.AppID, m.Version
	} else if kind == KindApp && c.Engine != nil {
		appID, _, version = bundleInfo(ctx, c.Engine.R, abs)
	}
	if appID == "" || version == "" {
		return "", "", "", cleanup, errors.New("this file has no rottencore.json, so RottenCore cannot sign it")
	}
	if st.IsDir() {
		sum, err = hashTree(abs)
	} else {
		sum, _, err = FileSHA256(abs)
	}
	if err != nil {
		return "", "", "", cleanup, err
	}
	return appID, version, sum, cleanup, nil
}

func hashTree(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	var paths []string
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing %s", p)
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return "", err
		}
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		if _, err := io.WriteString(h, filepath.ToSlash(rel)); err != nil {
			f.Close()
			return "", err
		}
		if _, err := h.Write([]byte{0}); err != nil {
			f.Close()
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		if _, err := h.Write([]byte{0}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type sigChainFile struct {
	Schema int               `json:"schema"`
	Apps   map[string]string `json:"apps"`
}

func (c *Core) chainPath() string { return filepath.Join(c.State.Dir, "sig-chain.json") }

func (c *Core) chainLock() (func(), error) {
	if c.State == nil || c.State.Dir == "" {
		return nil, errors.New("RottenCore has no support folder")
	}
	if err := os.MkdirAll(c.State.Dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(c.State.Dir, "sig-chain.lock")
	for i := 0; i < 100; i++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if st, e := os.Stat(p); e == nil && time.Since(st.ModTime()) > 10*time.Minute {
			os.Remove(p)
			continue
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, errors.New("another RottenCore is signing; try again")
}

func (c *Core) readChain() (map[string]string, error) {
	b, err := os.ReadFile(c.chainPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f sigChainFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, errors.New("sig-chain.json is damaged")
	}
	if f.Apps == nil {
		f.Apps = map[string]string{}
	}
	return f.Apps, nil
}

func (c *Core) prevSig(appID string) (string, error) {
	m, err := c.readChain()
	if err != nil {
		return "", err
	}
	return m[appID], nil
}

func (c *Core) putSig(appID, sigID string) error {
	m, err := c.readChain()
	if err != nil {
		return err
	}
	m[appID] = sigID
	b, err := json.MarshalIndent(sigChainFile{Schema: 1, Apps: m}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(c.chainPath(), append(b, '\n'))
}

func writePrivate(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if cerr != nil {
		os.Remove(tmp)
		return cerr
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
