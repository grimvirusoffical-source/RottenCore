//go:build qa

package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// QA attack harness for the installer expand. It does not change product
// behavior: the file is built only with -tags qa. Failure text names the
// class of material that showed up and never prints the bytes.

const qaPassword = "qa-attack-password"

type qaSeal struct {
	password   string
	lifetimeCT []byte
	hits       atomic.Int32
}

func (s *qaSeal) Encrypt(ctx context.Context, password, plaintext []byte) ([]byte, error) {
	return (testSealer{password: s.password}).Encrypt(ctx, password, plaintext)
}

func (s *qaSeal) Decrypt(ctx context.Context, password, ciphertext []byte) ([]byte, error) {
	if len(s.lifetimeCT) > 0 && bytes.Equal(bytes.TrimSpace(ciphertext), bytes.TrimSpace(s.lifetimeCT)) {
		s.hits.Add(1)
	}
	return (testSealer{password: s.password}).Decrypt(ctx, password, ciphertext)
}

type qaAcct struct {
	email            string
	verified         bool
	idVerified       bool
	omitID           bool
	idAsString       string
	idFromAccount    bool
	accountID        bool
	accountEmail     string
	mfa              bool
	amr              []string
	amrOnAccountOnly bool
}

type qaID struct {
	t       *testing.T
	srv     *httptest.Server
	c       *Core
	seal    *qaSeal
	seedHex string
	seedRaw []byte
	pubHex  string
	owners  []string
	accts   map[string]qaAcct
}

func newQA(t *testing.T) *qaID {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sign.Wipe(priv) })
	seedRaw := append([]byte(nil), priv.Seed()...)
	t.Cleanup(func() { sign.Wipe(seedRaw) })
	seedHex := hex.EncodeToString(seedRaw)
	seal := &qaSeal{password: qaPassword}
	enc, err := seal.Encrypt(context.Background(), []byte(qaPassword), []byte(hex.EncodeToString(priv)))
	if err != nil {
		t.Fatal(err)
	}
	seal.lifetimeCT = append([]byte(nil), enc...)
	q := &qaID{
		t: t, seal: seal, seedHex: seedHex, seedRaw: seedRaw,
		pubHex: hex.EncodeToString(pub),
		owners: []string{"support@infected-nation.com", "grimvirusoffical@gmail.com"},
		accts:  map[string]qaAcct{},
	}
	q.srv = httptest.NewServer(http.HandlerFunc(q.serve))
	t.Cleanup(q.srv.Close)
	q.c = testCore(t, newFake(), "", nil)
	q.c.Net.AllowLoopbackHTTP = true
	q.c.Secrets = &MemoryKeyring{}
	q.c.Accounts = &OIDCAccounts{Issuer: q.srv.URL, Net: q.c.Net}
	return q
}

func (q *qaID) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/.well-known/openid-configuration" {
		json.NewEncoder(w).Encode(Discovery{
			Issuer: q.srv.URL, AuthorizationEndpoint: q.srv.URL + "/oauth2/authorize",
			TokenEndpoint: q.srv.URL + "/oauth2/token", UserinfoEndpoint: q.srv.URL + "/oauth2/userinfo",
			JWKSURI: q.srv.URL + "/oauth2/jwks",
		})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	acct, ok := q.accts[tok]
	if tok == "" || !ok {
		http.Error(w, "no", 401)
		return
	}
	switch r.URL.Path {
	case "/oauth2/userinfo":
		body := map[string]interface{}{
			"sub": "qa", "email": acct.email, "email_verified": acct.verified,
		}
		if acct.amrOnAccountOnly {
			body["amr"] = []string{"pwd"}
		} else if len(acct.amr) > 0 {
			body["amr"] = acct.amr
		} else if acct.mfa {
			body["amr"] = []string{"pwd", "otp"}
		} else {
			body["amr"] = []string{"pwd"}
		}
		if !acct.omitID && !acct.idFromAccount {
			if acct.idAsString != "" {
				body["idVerified"] = acct.idAsString
			} else {
				body["idVerified"] = acct.idVerified
			}
		}
		json.NewEncoder(w).Encode(body)
	case "/v1/rxa-account":
		body := map[string]interface{}{}
		if acct.accountEmail != "" {
			body["email"] = acct.accountEmail
		}
		if acct.idFromAccount || acct.accountID {
			body["idVerified"] = true
			body["idVerifiedMs"] = 42
		}
		if acct.amrOnAccountOnly {
			body["amr"] = []string{"pwd", "otp"}
		}
		json.NewEncoder(w).Encode(body)
	case "/v1/rxa-lifetime-cert":
		// Every authenticated token receives ciphertext, including non-owners.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind": "rxa-lifetime-cert", "cert_id": "cert-qa", "pubkey": q.pubHex,
			"private_enc": string(q.seal.lifetimeCT), "issued": "2026-10-27T00:00:00Z",
			"owner_emails": q.owners, "sig_id_prefix": "rxa",
		})
	default:
		http.NotFound(w, r)
	}
}

func (q *qaID) add(token string, a qaAcct) { q.accts[token] = a }

func (q *qaID) zip(version string) string {
	q.t.Helper()
	return zipTool(q.t, q.t.TempDir(), version)
}

func (q *qaID) hits() int { return int(q.seal.hits.Load()) }

func (q *qaID) assertNoMaterial(roots ...string) {
	q.t.Helper()
	needles := [][]byte{[]byte(q.seedHex), q.seedRaw, []byte(qaPassword), []byte("-----BEGIN")}
	for _, root := range roots {
		filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil || !info.Mode().IsRegular() {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, n := range needles {
				if len(n) > 0 && bytes.Contains(b, n) {
					q.t.Errorf("private material present in %s", path)
					return nil
				}
			}
			if bytes.Contains(bytes.ToLower(b), []byte("private_enc")) {
				q.t.Errorf("private_enc field present in %s", path)
			}
			return nil
		})
	}
}

func (q *qaID) noCarrier(path string) {
	q.t.Helper()
	for _, p := range []string{path + ".rotten_core_signed", path + sign.FileExt} {
		if _, err := os.Stat(p); err == nil {
			q.t.Errorf("carrier written for refused sign: %s", filepath.Base(p))
		}
	}
}

func TestQAOwnerUnlockOnly(t *testing.T) {
	q := newQA(t)
	full := func(email string) qaAcct {
		return qaAcct{email: email, verified: true, idVerified: true, mfa: true, amr: []string{"pwd", "otp"}}
	}
	type row struct {
		token string
		acct  qaAcct
		owner bool
	}
	rows := []row{
		{"support", full("support@infected-nation.com"), true},
		{"gmail", full("grimvirusoffical@gmail.com"), true},
		{"casefold", full("Support@Infected-Nation.com"), true},
		{"padded", full("  support@infected-nation.com  "), true},
		{"no-mfa", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: true, amr: []string{"pwd"}}, false},
		{"no-id", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: false, mfa: true}, false},
		{"no-verified", qaAcct{email: "support@infected-nation.com", verified: false, idVerified: true, mfa: true}, false},
		{"attacker", full("attacker@evil.com"), false},
		{"plus", full("support+box@infected-nation.com"), false},
		{"lookalike-domain", full("support@infected-nation.com.evil"), false},
		{"truncated-domain", full("support@infected-nation.co"), false},
		{"string-id", qaAcct{email: "support@infected-nation.com", verified: true, idAsString: "true", mfa: true}, false},
		{"decoy-account-email", qaAcct{email: "attacker@evil.com", verified: true, idFromAccount: true, accountEmail: "support@infected-nation.com", mfa: true, amr: []string{"pwd", "otp"}}, false},
		{"id-false-sticky", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: false, accountID: true, mfa: true}, false},
		{"mfa-only-on-account", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: true, amrOnAccountOnly: true}, false},
		{"dev", full("dev@example.com"), false},
	}
	for _, r := range rows {
		q.add(r.token, r.acct)
	}

	ctx := context.Background()
	for _, r := range rows {
		before := q.hits()
		path := q.zip("1.0." + itoa(len(r.token)))
		res, err := q.c.SignLifetime(ctx, r.token, []byte(qaPassword), path, "linux", false, q.seal)
		if r.owner {
			if err != nil {
				t.Fatalf("%s owner sign: %v", r.token, errClass(err))
			}
			if res.LauncherRequired || res.CertID != "cert-qa" {
				t.Fatalf("%s owner result flags", r.token)
			}
			if q.hits() <= before {
				t.Fatalf("%s owner did not decrypt", r.token)
			}
			q.assertNoMaterial(filepath.Dir(path))
			continue
		}
		if err == nil {
			t.Fatalf("%s non-owner produced a signature", r.token)
		}
		if !errors.Is(err, ErrOwnerSession) && !errors.Is(err, ErrSignInRequired) && !errors.Is(err, ErrNotOwnerUnlock) {
			// Role miss returns ErrOwnerSession. Anything else must still be a refusal.
			if res != nil {
				t.Fatalf("%s returned a result on error", r.token)
			}
		}
		if q.hits() != before {
			t.Fatalf("%s decrypted lifetime ciphertext", r.token)
		}
		q.noCarrier(path)
		if strings.Contains(err.Error(), q.seedHex) || strings.Contains(err.Error(), qaPassword) || strings.Contains(err.Error(), "private_enc") {
			t.Fatalf("%s error exposed private material", r.token)
		}
	}

	// Owner email with every flag set, but the cert does not list them.
	// WhoAmI uses the profile role; the unlock path must still refuse.
	q.owners = nil
	q.add("unlisted", full("support@infected-nation.com"))
	who, err := q.c.WhoAmI(ctx, "unlisted")
	if err != nil {
		t.Fatal(errClass(err))
	}
	if who.Role != sign.RoleOwner {
		t.Fatal("profile role fixture")
	}
	before := q.hits()
	path := q.zip("9.0.0")
	if _, err := q.c.SignLifetime(ctx, "unlisted", []byte(qaPassword), path, "linux", false, q.seal); !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("unlisted owner email unlock: %v", errClass(err))
	}
	if q.hits() != before {
		t.Fatal("unlisted identity decrypted lifetime ciphertext")
	}
	q.noCarrier(path)
	if err := q.c.RunAgent(ctx, "unlisted", []byte(qaPassword), q.seal); !errors.Is(err, ErrNotOwnerUnlock) {
		t.Fatalf("unlisted agent: %v", errClass(err))
	}
	if q.c.AgentRunning() {
		t.Fatal("refused unlock left the agent up")
	}

	// Listed attacker email still is not an owner address.
	q.owners = []string{"attacker@evil.com", "support@infected-nation.com"}
	q.add("listed-attacker", full("attacker@evil.com"))
	before = q.hits()
	path = q.zip("9.1.0")
	if _, err := q.c.SignLifetime(ctx, "listed-attacker", []byte(qaPassword), path, "linux", false, q.seal); !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("listed non-owner: %v", errClass(err))
	}
	if q.hits() != before {
		t.Fatal("listed non-owner decrypted lifetime ciphertext")
	}
	if err := q.c.RunAgent(ctx, "listed-attacker", []byte(qaPassword), q.seal); !errors.Is(err, ErrNotOwnerUnlock) {
		t.Fatalf("listed non-owner agent: %v", errClass(err))
	}

	// Empty ciphertext is withheld, not decrypted.
	q.owners = []string{"support@infected-nation.com", "grimvirusoffical@gmail.com"}
	q.seal.lifetimeCT = []byte("   ")
	// Server still copies q.seal.lifetimeCT. Force an empty document by clearing hits baseline via a token
	// whose cert ciphertext is blank. Re-point the field the handler reads.
	q.add("blank", full("support@infected-nation.com"))
	// The handler uses q.seal.lifetimeCT. Whitespace trims to empty inside unlockKey only after role
	// passes. SignLifetime treats empty PrivateEnc as withheld. Keep a non-empty value that trims empty.
	if _, err := q.c.SignLifetime(ctx, "blank", []byte(qaPassword), q.zip("9.2.0"), "linux", false, q.seal); !errors.Is(err, ErrKeyWithheld) && !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("blank ciphertext: %v", errClass(err))
	}
}

func TestQADeveloperCannotSignWithoutLauncher(t *testing.T) {
	q := newQA(t)
	q.add("owner", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: true, mfa: true, amr: []string{"pwd", "otp"}})
	q.add("dev", qaAcct{email: "dev@example.com", verified: true, idVerified: true, mfa: true, amr: []string{"pwd", "otp"}})
	ctx := context.Background()

	os.Unsetenv("ROTTENCORE_RA_LAUNCHER")
	if _, inst, run := LauncherStatus(); inst || run {
		t.Fatal("launcher fixture was already present")
	}
	path := q.zip("1.0.0")
	before := q.hits()
	if _, err := q.c.SignDeveloper(ctx, "dev", []byte(qaPassword), path, "linux", q.seal); err == nil {
		t.Fatal("developer signed with no launcher")
	} else if !errors.Is(err, sign.ErrLauncherDown) && !strings.Contains(err.Error(), "installed and running") {
		t.Fatalf("developer no-launcher: %v", errClass(err))
	}
	q.noCarrier(path)
	if q.hits() != before {
		t.Fatal("developer path decrypted the lifetime ciphertext")
	}
	if _, err := q.c.SignLifetime(ctx, "dev", []byte(qaPassword), path, "linux", true, q.seal); !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("developer SignLifetime: %v", errClass(err))
	}
	if _, err := q.c.SignLifetime(ctx, "dev", []byte(qaPassword), path, "linux", false, q.seal); !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("developer SignLifetime without launcher: %v", errClass(err))
	}
	if q.hits() != before {
		t.Fatal("developer SignLifetime decrypted lifetime ciphertext")
	}
	q.noCarrier(path)

	// Ceremony: owner unlocks, developer still cannot clear launcher_required,
	// and cannot sign while the launcher is down.
	pw := append([]byte(nil), qaPassword...)
	errCh := make(chan error, 1)
	ctxA, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { errCh <- q.c.RunAgent(ctxA, "owner", pw, q.seal) }()
	waitAgent(t, q.c, errCh)
	sign.Wipe(pw)
	if hits := q.hits(); hits != 1 {
		t.Fatalf("owner unlock decrypt count %d", hits)
	}
	if _, err := q.c.AgentSign(ctx, "dev", path, "linux", false); err == nil || !strings.Contains(err.Error(), sign.ErrDevLauncher.Error()) {
		t.Fatalf("dev agent without launcher: %v", errClass(err))
	}
	q.noCarrier(path)
	if _, err := q.c.AgentSign(ctx, "dev", path, "linux", true); err == nil || !strings.Contains(err.Error(), "installed and running") {
		t.Fatalf("dev agent launcher down: %v", errClass(err))
	}
	q.noCarrier(path)
	if _, err := q.c.AgentSign(ctx, "", path, "linux", false); err == nil {
		t.Fatal("empty token signed")
	}
	if _, err := q.c.AgentSign(ctx, "dev", path, "ios", true); err == nil {
		t.Fatal("linux host signed ios")
	}

	// Direct socket: withLauncher false, and a request that smuggles an extra field.
	sock, err := q.c.agentSocket()
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", st, err)
	}
	dirSt, err := os.Lstat(filepath.Dir(sock))
	if err != nil || dirSt.Mode()&os.ModeSymlink != 0 || dirSt.Mode().Perm()&0o077 != 0 {
		t.Fatalf("socket dir mode %v %v", dirSt, err)
	}
	refuse := func(line string) {
		t.Helper()
		conn, err := dialAgent(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		var env agentEnvelope
		if err := json.NewDecoder(conn).Decode(&env); err != nil {
			t.Fatal(err)
		}
		if env.OK {
			t.Fatal("agent accepted a refused request")
		}
		if strings.Contains(env.Error, "QA-SENTINEL") || strings.Contains(env.Error, q.seedHex) || strings.Contains(env.Error, qaPassword) {
			t.Fatal("agent error exposed material")
		}
	}
	refuse(`{"op":"sign","token":"dev","path":"` + path + `","platform":"linux","withLauncher":false}`)
	refuse(`{"op":"sign","token":"dev","path":"` + path + `","platform":"linux","withLauncher":true,"private_key":"QA-SENTINEL"}`)
	q.noCarrier(path)

	startQALauncher(t)
	res, err := q.c.AgentSign(ctx, "dev", path, "linux", true)
	if err != nil {
		t.Fatalf("dev with launcher: %v", errClass(err))
	}
	if !res.LauncherRequired || res.CertID != "cert-qa" {
		t.Fatal("developer agent signature dropped launcher_required or cert")
	}
	raw, err := os.ReadFile(res.Output)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := q.seal.Decrypt(context.Background(), []byte(qaPassword), raw)
	if err != nil {
		t.Fatal(errClass(err))
	}
	payload, err := sign.Parse(plain)
	sign.Wipe(plain)
	if err != nil || !payload.LauncherRequired || payload.Cert.Issuer != sign.Issuer {
		t.Fatal("developer payload was not an owner signature that requires the launcher")
	}
	// Own-key path is the developer certificate, still launcher-required, and it
	// must not be able to mint launcher_required false.
	own := q.zip("1.2.0")
	devRes, err := q.c.SignDeveloper(ctx, "dev", []byte(qaPassword), own, "linux", q.seal)
	if err != nil {
		t.Fatalf("developer own key: %v", errClass(err))
	}
	if !devRes.LauncherRequired {
		t.Fatal("developer own-key signature cleared launcher_required")
	}
	if kt, err := q.c.secrets().Get(q.c.devPrivAccount("dev@example.com")); err != nil {
		t.Fatal(errClass(err))
	} else if plain, err := q.seal.Decrypt(context.Background(), []byte(qaPassword), kt); err != nil {
		t.Fatal(errClass(err))
	} else {
		carrier, _ := os.ReadFile(devRes.Output)
		if bytes.Contains(carrier, plain) || bytes.Contains(mustRead(t, q.c.devCertPath()), plain) {
			sign.Wipe(plain)
			t.Fatal("developer private key was written into a carrier or the public cert file")
		}
		sign.Wipe(plain)
	}
	if _, err := q.c.SignDeveloper(ctx, "dev", []byte(qaPassword), own, "ios", q.seal); err == nil {
		t.Fatal("developer signed ios from linux")
	}

	// Operator override selects which binary counts as the launcher. It still
	// cannot clear launcher_required for a developer.
	if _, err := q.c.AgentSign(ctx, "dev", path, "linux", false); err == nil {
		t.Fatal("env override let a developer sign without the launcher")
	}

	if err := q.c.ShutdownAgent(ctx); err != nil {
		t.Fatal(errClass(err))
	}
	if _, err := q.c.AgentSign(ctx, "dev", path, "linux", true); !errors.Is(err, ErrAgentDown) {
		t.Fatalf("after shutdown: %v", errClass(err))
	}
	q.assertNoMaterial(filepath.Dir(path), filepath.Dir(own), q.c.State.Dir)
}

func TestQAOpenSealedRefusesUnsigned(t *testing.T) {
	q := newQA(t)
	q.add("dev", qaAcct{email: "dev@example.com", verified: true, idVerified: true, mfa: true})
	startQALauncher(t)
	ctx := context.Background()
	dir := t.TempDir()
	app := makeApp(t, dir, "QATool", "com.qa.sealed", "1.2.0", `{"schema":1,"appId":"com.qa.sealed","name":"QATool","version":"1.2.0","source":"store"}`)
	zip := filepath.Join(dir, "tool.zip")
	zipApp(t, app, zip)
	res, err := q.c.SignDeveloper(ctx, "dev", []byte(qaPassword), zip, "linux", q.seal)
	if err != nil {
		t.Fatal(errClass(err))
	}
	if !res.LauncherRequired {
		t.Fatal("sealed fixture lost launcher_required")
	}
	installed := filepath.Join(q.c.Engine.Applications, "QATool.app")
	if _, err := q.c.OpenSigned(ctx, zip, []byte(qaPassword), false, q.seal); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unaccepted sealed install: %v", errClass(err))
	}
	if _, err := os.Stat(installed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unaccepted open installed")
	}
	ent, err := q.c.OpenSigned(ctx, zip, []byte(qaPassword), true, q.seal)
	if err != nil {
		t.Fatal(errClass(err))
	}
	if ent.AppID != "com.qa.sealed" || ent.Version != "1.2.0" {
		t.Fatal("sealed install identity mismatch")
	}
	if _, err := os.Stat(installed); err != nil {
		t.Fatal("sealed app was not installed")
	}

	unsigned := filepath.Join(dir, "unsigned.zip")
	zipApp(t, makeApp(t, dir, "QANo", "com.qa.unsigned", "1.0.0", `{"schema":1,"appId":"com.qa.unsigned","name":"QANo","version":"1.0.0","source":"store"}`), unsigned)
	if _, err := q.c.OpenSigned(ctx, unsigned, []byte(qaPassword), true, q.seal); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("unsigned: %v", errClass(err))
	}
	if _, err := os.Stat(filepath.Join(q.c.Engine.Applications, "QANo.app")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsigned file was installed")
	}

	plain := filepath.Join(dir, "plain.zip.rotten_core_signed")
	if err := os.WriteFile(plain, []byte(`{"type":"rotten_core_signed","sig":"00"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plainZip := strings.TrimSuffix(plain, ".rotten_core_signed")
	if err := os.WriteFile(plainZip, []byte("not-a-signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.c.OpenSigned(ctx, plain, []byte(qaPassword), true, q.seal); err == nil {
		t.Fatal("unsealed JSON carrier installed")
	}

	png := filepath.Join(dir, "blob.zip"+sign.FileExt)
	if err := os.WriteFile(png, []byte("not-a-png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(png, sign.FileExt), []byte("zip-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.c.OpenSigned(ctx, png, []byte(qaPassword), true, q.seal); err == nil {
		t.Fatal("unsealed file extension installed")
	}

	// Tamper the artifact after a good signature.
	tampered := filepath.Join(dir, "tamper.zip")
	if err := os.WriteFile(tampered, mustRead(t, zip), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered+".rotten_core_signed", mustRead(t, res.Output), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(tampered, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := q.c.OpenSigned(ctx, tampered, []byte(qaPassword), true, q.seal); err == nil {
		t.Fatal("tampered artifact installed")
	}

	// Flip a carrier byte.
	bad := append([]byte(nil), mustRead(t, res.Output)...)
	bad[len(bad)/2] ^= 0x01
	badPath := filepath.Join(dir, "bad.zip")
	if err := os.WriteFile(badPath, mustRead(t, zip), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badPath+".rotten_core_signed", bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.c.OpenSigned(ctx, badPath, []byte(qaPassword), true, q.seal); err == nil {
		t.Fatal("tampered carrier installed")
	}

	// A valid ed25519 payload from a key this computer never minted.
	foreign := q.foreignCarrier(t, dir)
	if _, err := q.c.OpenSigned(ctx, foreign, []byte(qaPassword), true, q.seal); err == nil {
		t.Fatal("unknown key installed")
	}
	if _, err := os.Stat(filepath.Join(q.c.Engine.Applications, "QAForeign.app")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unknown key left an install")
	}
	if _, err := q.c.OpenSigned(ctx, zip, []byte("wrong-password"), true, q.seal); err == nil {
		t.Fatal("wrong password installed")
	}
	q.assertNoMaterial(dir, q.c.State.Dir)
}

func (q *qaID) foreignCarrier(t *testing.T, dir string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sign.Wipe(priv)
	app := makeApp(t, dir, "QAForeign", "com.qa.foreign", "1.0.0", `{"schema":1,"appId":"com.qa.foreign","name":"QAForeign","version":"1.0.0","source":"store"}`)
	zip := filepath.Join(dir, "foreign.zip")
	zipApp(t, app, zip)
	sum, _, err := FileSHA256(zip)
	if err != nil {
		t.Fatal(err)
	}
	body := sign.Payload{
		Type: sign.TypeRottenCoreSigned, SigID: "dev_00112233445566778899aabbccddeeff",
		AppID: "com.qa.foreign", Version: "1.0.0",
		Cert: sign.Cert{ID: "foreign", PubKey: hex.EncodeToString(pub), Issuer: sign.IssuerDeveloper},
		Hash: sum, Nonce: strings.Repeat("ab", 32), Platforms: []string{"linux"}, LauncherRequired: true,
	}
	signed, err := sign.Sign(priv, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sign.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	defer sign.Wipe(raw)
	ct, err := q.seal.Encrypt(context.Background(), []byte(qaPassword), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zip+".rotten_core_signed", append(ct, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return zip
}

func TestQADaemonLoginDevCert(t *testing.T) {
	q := newQA(t)
	q.add("dev", qaAcct{email: "dev@example.com", verified: true, idVerified: false, mfa: false, amr: []string{"pwd"}})
	ctx := context.Background()
	dl := t.TempDir()
	marker := []byte("QA-CARRIER-BODY-MARKER")
	if err := os.WriteFile(filepath.Join(dl, "App.zip.Red_SecretXAI"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dl, "notes.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := q.c.RunDaemon(ctx, DaemonConfig{
		Tick: time.Hour, Stall: time.Hour, MaxUptime: time.Minute, RSSLimit: 1 << 40,
		Downloads: dl, Started: time.Now().Add(-2 * time.Hour),
	})
	if !errors.Is(err, ErrDaemonReset) {
		t.Fatal(errClass(err))
	}
	pending, err := os.ReadFile(filepath.Join(q.c.State.Dir, "pending-imports.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pending, marker) {
		t.Fatal("daemon copied carrier bytes")
	}
	if !bytes.Contains(pending, []byte("App.zip.Red_SecretXAI")) {
		t.Fatal("daemon missed the carrier name")
	}
	if _, err := os.Stat(filepath.Join(q.c.Engine.Applications, "App.app")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("daemon installed")
	}

	// dev-cert: public record only. Lifetime ciphertext stays untouched.
	before := q.hits()
	rec, err := q.c.EnsureDeveloperCert(ctx, "dev", []byte(qaPassword), q.seal)
	if err != nil {
		t.Fatal(errClass(err))
	}
	if q.hits() != before {
		t.Fatal("dev-cert decrypted the lifetime ciphertext")
	}
	jb, _ := json.Marshal(rec)
	if bytes.Contains(jb, []byte(q.seedHex)) || bytes.Contains(bytes.ToLower(jb), []byte("private")) {
		t.Fatal("dev-cert result included private material")
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(jb, &keys) != nil {
		t.Fatal("dev-cert json")
	}
	for _, forbidden := range []string{"private", "private_enc", "seed", "priv"} {
		if _, ok := keys[forbidden]; ok {
			t.Fatal("dev-cert public record has a private field")
		}
	}
	kt, err := q.c.secrets().Get("dev-priv:dev@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(kt, []byte(q.seedHex)) || bytes.Contains(kt, q.seedRaw) {
		t.Fatal("keyring held lifetime key material")
	}
	// The developer private key is sealed. The public file must not contain the
	// ciphertext's plaintext hex. Compare against a freshly decrypted copy only
	// inside the process, then wipe it.
	plain, err := q.seal.Decrypt(context.Background(), []byte(qaPassword), kt)
	if err != nil {
		t.Fatal(errClass(err))
	}
	pubFile, err := os.ReadFile(q.c.devCertPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pubFile, plain) || bytes.Contains(pubFile, []byte("private_enc")) || bytes.Contains(pubFile, []byte("-----BEGIN")) {
		sign.Wipe(plain)
		t.Fatal("developer-certs.json contained private material")
	}
	sign.Wipe(plain)
	st, err := os.Stat(q.c.devCertPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("dev cert mode %v", st)
	}

	// Quick Login does not write tokens when remember_device is false, and a
	// shell metacharacter in the verification URI is not executed.
	markerPath := filepath.Join(t.TempDir(), "rce-marker")
	evil := "$(touch " + markerPath + ")"
	var loginSrv *httptest.Server
	loginSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redxai-connect/start":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code": "d", "user_code": "CODE", "verification_uri": evil,
				"expires_in": 30, "interval": 1, "protocol": QuickLoginProtocol,
			})
		case "/redxai-connect/token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"protocol": QuickLoginProtocol, "token_type": "Bearer",
				"access_token": "qa-access", "refresh_token": "qa-refresh",
				"expires_in": 30, "remember_device": false,
			})
		case "/redxai-connect/userinfo":
			w.WriteHeader(200)
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Discovery{Issuer: loginSrv.URL, AuthorizationEndpoint: loginSrv.URL + "/oauth2/authorize", TokenEndpoint: loginSrv.URL + "/oauth2/token", UserinfoEndpoint: loginSrv.URL + "/oauth2/userinfo", JWKSURI: loginSrv.URL + "/oauth2/jwks"})
		case "/oauth2/userinfo":
			json.NewEncoder(w).Encode(map[string]interface{}{"sub": "a", "email": "dev@example.com", "email_verified": true, "amr": []string{"pwd"}})
		case "/v1/rxa-account":
			json.NewEncoder(w).Encode(map[string]interface{}{"idVerified": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer loginSrv.Close()
	q.c.Accounts = &OIDCAccounts{Issuer: loginSrv.URL, Net: q.c.Net}
	var opened string
	if _, err := q.c.LoginQuick(ctx, func(p LoginPrompt) { opened = p.VerificationURI }); err != nil {
		t.Fatal(errClass(err))
	}
	if opened != evil {
		t.Fatal("verification URI was rewritten")
	}
	if _, err := os.Stat(markerPath); err == nil {
		t.Fatal("verification URI was executed")
	}
	if _, err := q.c.secrets().Get("access-token"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("remember_device false stored a token")
	}
	q.assertNoMaterial(q.c.State.Dir)

	// remember_device true keeps the token in the keyring, not the support folder.
	q.c.Accounts = &OIDCAccounts{Issuer: q.srv.URL, Net: q.c.Net}
	home := t.TempDir()
	path, data, err := AutostartPlan("linux", home, "/usr/local/bin/rottencore")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(q.seedHex)) || bytes.Contains(data, []byte("private_enc")) || bytes.Contains(data, []byte(qaPassword)) {
		t.Fatal("autostart file contained private material")
	}
	if !strings.Contains(path, "rottencore.service") {
		t.Fatal("linux autostart path")
	}
}

func TestQAAgentRejectsLooseSocketDir(t *testing.T) {
	q := newQA(t)
	q.add("owner", qaAcct{email: "support@infected-nation.com", verified: true, idVerified: true, mfa: true, amr: []string{"pwd", "otp"}})
	q.c.State.Dir = filepath.Join(t.TempDir(), strings.Repeat("p", 180))
	sock, err := q.c.agentSocket()
	if err != nil || !strings.HasPrefix(sock, "/tmp/rc-") {
		t.Fatalf("expected a short socket")
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(sock), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(sock)) })
	err = q.c.RunAgent(context.Background(), "owner", []byte(qaPassword), q.seal)
	if err == nil || !strings.Contains(err.Error(), "not private") || q.c.AgentRunning() {
		t.Fatal("agent listened in a world-accessible socket directory")
	}
	if strings.Contains(err.Error(), q.seedHex) || strings.Contains(err.Error(), qaPassword) {
		t.Fatal("loose-directory error exposed private material")
	}
	if _, statErr := os.Stat(sock); statErr == nil {
		st, _ := os.Stat(sock)
		if st.Mode().Perm()&0o077 != 0 {
			t.Fatal("agent left a group-accessible socket")
		}
	}
}

func TestQASchemeAndPathSmoke(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"http://evil.example/x",
		"https://user:pass@red-xai.com",
		"rottenapple://install",
	} {
		if ValidOrigin(raw, false) {
			t.Fatalf("origin accepted %s", raw)
		}
	}
	if !ValidOrigin("https://red-xai.com", false) {
		t.Fatal("https origin rejected")
	}
	n := &Net{AllowLoopbackHTTP: true}
	if _, err := n.GetBytesBearer(context.Background(), "file:///etc/passwd", "tok", 100); err == nil {
		t.Fatal("bearer fetch allowed file")
	}
	if _, err := n.GetBytesBearer(context.Background(), "http://169.254.169.254/latest", "tok", 100); err == nil {
		t.Fatal("bearer fetch allowed link-local http")
	}
	for _, bad := range []string{
		`{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","install":{"bundle":"../../etc/x.app"}}`,
		`{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","install":{"bundle":"foo/bar.app"}}`,
		`{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"store","install":{"pkg":"..\\x.pkg"}}`,
		`{"schema":1,"appId":"com.a.b","name":"A","version":"1","source":"github","github":{"owner":"a","repo":"b","asset":"../x"}}`,
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Fatal("manifest accepted a traversal name")
		}
	}
	dir := t.TempDir()
	for _, iss := range []string{"file:///tmp", "javascript:alert(1)", "http://evil.example"} {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"accountsIssuer":"`+iss+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(dir); err == nil {
			t.Fatalf("config accepted issuer %s", iss)
		}
	}

	// Test-double unzip joins entry names. Production Unzip calls /usr/bin/ditto
	// and is not this function. Record whether the double escapes; do not treat
	// the double as the shipped installer.
	f := newFake()
	c := testCore(t, f, "", nil)
	if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "slip.zip")
	writeSlipZip(t, zipPath)
	out, err := c.Engine.Unzip(context.Background(), zipPath, c.TmpDir)
	escaped := false
	if err == nil {
		outside := filepath.Join(filepath.Dir(out), "qa-slip.txt")
		if _, statErr := os.Stat(outside); statErr == nil {
			escaped = true
			os.Remove(outside)
		}
	}
	if escaped {
		t.Log("test-double unzip joined a .. entry; production engine calls ditto")
	} else if err != nil {
		t.Log("test-double unzip returned an error")
	} else {
		t.Log("test-double unzip kept the entry inside the temp dir")
	}
	if _, err := os.Stat("/usr/bin/ditto"); err == nil {
		t.Log("ditto present")
	} else {
		t.Log("ditto absent on this VM")
	}
}

func TestQARealSealerCarrier(t *testing.T) {
	if exec.Command("python3", "-c", "import redxai").Run() != nil {
		t.Skip("red-xai-encrypt is not installed")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sign.Wipe(priv) })
	seedRaw := append([]byte(nil), priv.Seed()...)
	t.Cleanup(func() { sign.Wipe(seedRaw) })
	seedHex := hex.EncodeToString(seedRaw)
	const pw = "qa-real-sealer-password"
	inner := sign.RedSecretsXAI{}
	enc, err := inner.Encrypt(context.Background(), []byte(pw), []byte(hex.EncodeToString(priv)))
	if err != nil {
		t.Fatal(errClass(err))
	}
	if bytes.Contains(enc, []byte(seedHex)) || bytes.Contains(enc, seedRaw) || bytes.Contains(enc, []byte(pw)) {
		t.Fatal("lifetime ciphertext contained private material")
	}
	seal := &countingReal{inner: inner, ct: enc}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(Discovery{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/oauth2/authorize", TokenEndpoint: srv.URL + "/oauth2/token", UserinfoEndpoint: srv.URL + "/oauth2/userinfo", JWKSURI: srv.URL + "/oauth2/jwks"})
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/oauth2/userinfo":
			email := "dev@example.com"
			idv := false
			amr := []string{"pwd"}
			if tok == "owner" {
				email = "support@infected-nation.com"
				idv = true
				amr = []string{"pwd", "otp"}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"sub": tok, "email": email, "email_verified": true, "idVerified": idv, "amr": amr})
		case "/v1/rxa-lifetime-cert":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"kind": "rxa-lifetime-cert", "cert_id": "cert-real", "pubkey": hex.EncodeToString(pub),
				"private_enc": string(enc), "owner_emails": []string{"support@infected-nation.com"}, "sig_id_prefix": "rxa",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := testCore(t, newFake(), "", nil)
	c.Net.AllowLoopbackHTTP = true
	c.Secrets = &MemoryKeyring{}
	c.Accounts = &OIDCAccounts{Issuer: srv.URL, Net: c.Net}
	ctx := context.Background()
	dir := t.TempDir()
	app := makeApp(t, dir, "QAReal", "com.qa.real", "1.0.0", `{"schema":1,"appId":"com.qa.real","name":"QAReal","version":"1.0.0","source":"store"}`)
	zip := filepath.Join(dir, "real.zip")
	zipApp(t, app, zip)
	if _, err := c.SignLifetime(ctx, "dev", []byte(pw), zip, "linux", true, seal); !errors.Is(err, ErrOwnerSession) {
		t.Fatalf("real sealer dev unlock: %v", errClass(err))
	}
	if seal.hits.Load() != 0 {
		t.Fatal("non-owner decrypted real lifetime ciphertext")
	}
	startQALauncher(t)
	res, err := c.SignDeveloper(ctx, "dev", []byte(pw), zip, "linux", seal)
	if err != nil {
		t.Fatal(errClass(err))
	}
	if !res.LauncherRequired {
		t.Fatal("real developer signature cleared launcher_required")
	}
	if seal.hits.Load() != 0 {
		t.Fatal("developer sign decrypted lifetime ciphertext")
	}
	scanTree(t, dir, seedHex, seedRaw, pw)
	scanTree(t, c.State.Dir, seedHex, seedRaw, pw)
	kt, err := c.secrets().Get("dev-priv:dev@example.com")
	if err != nil || bytes.Contains(kt, []byte(seedHex)) || bytes.Contains(kt, seedRaw) || bytes.Contains(kt, []byte(pw)) {
		t.Fatal("developer keyring held recoverable private material in the clear")
	}
	devPlain, err := inner.Decrypt(context.Background(), []byte(pw), kt)
	if err != nil {
		t.Fatal(errClass(err))
	}
	scanTree(t, dir, string(devPlain), devPlain, pw)
	scanTree(t, c.State.Dir, string(devPlain), devPlain, pw)
	sign.Wipe(devPlain)
	ent, err := c.OpenSigned(ctx, zip, []byte(pw), true, seal)
	if err != nil {
		t.Fatal(errClass(err))
	}
	if ent.AppID != "com.qa.real" {
		t.Fatal("real sealed open did not install")
	}
	if _, err := c.OpenSigned(ctx, filepath.Join(dir, "real-unsigned.txt"), []byte(pw), true, seal); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("real open unsigned: %v", errClass(err))
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".rc-sign-*"))
	if len(matches) != 0 {
		t.Fatal("plaintext sign temp file left behind")
	}
}

func TestQACLIGates(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "rottencore")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = moduleCmd(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	home := t.TempDir()
	run := func(args ...string) (int, string) {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Env = append(os.Environ(), "ROTTENCORE_HOME="+home)
		var buf bytes.Buffer
		c.Stdout = &buf
		c.Stderr = &buf
		err := c.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return code, buf.String()
	}
	code, out := run("sign", "--developer", "--without-launcher", "--platform", "linux", "app.zip")
	if code != 2 {
		t.Fatalf("cli developer without launcher exit %d", code)
	}
	if strings.Contains(out, "private_enc") || strings.Contains(out, "-----BEGIN") {
		t.Fatal("cli usage exposed private material")
	}
	code, _ = run("sign", "--developer", "--with-launcher", "--without-launcher", "--platform", "linux", "app.zip")
	if code != 2 {
		t.Fatalf("cli both launcher flags exit %d", code)
	}

	unsigned := filepath.Join(t.TempDir(), "unsigned.zip")
	if err := os.WriteFile(unsigned, []byte("PK\x03\x04not-ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command(bin, "open", unsigned, "--secrets-stdin", "--accept-untrusted", "--json")
	c.Env = append(os.Environ(), "ROTTENCORE_HOME="+home)
	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	cmdline, _ := os.ReadFile(filepath.Join("/proc", itoa(c.Process.Pid), "cmdline"))
	if bytes.Contains(cmdline, []byte(qaPassword)) {
		t.Fatal("password on process command line")
	}
	if _, err := stdin.Write([]byte(qaPassword + "\n")); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	err = c.Wait()
	if err == nil {
		t.Fatal("cli open installed an unsigned file")
	}
	if !strings.Contains(buf.String(), "not signed") {
		t.Fatalf("cli open exit class %d", exitCode(err))
	}
	if strings.Contains(buf.String(), qaPassword) || strings.Contains(buf.String(), "private_enc") {
		t.Fatal("cli open echoed private material")
	}
}

type countingReal struct {
	inner sign.RedSecretsXAI
	ct    []byte
	hits  atomic.Int32
}

func (s *countingReal) Encrypt(ctx context.Context, password, plaintext []byte) ([]byte, error) {
	return s.inner.Encrypt(ctx, password, plaintext)
}
func (s *countingReal) Decrypt(ctx context.Context, password, ciphertext []byte) ([]byte, error) {
	if bytes.Equal(bytes.TrimSpace(ciphertext), bytes.TrimSpace(s.ct)) {
		s.hits.Add(1)
	}
	return s.inner.Decrypt(ctx, password, ciphertext)
}
func (s *countingReal) EncryptFile(ctx context.Context, password []byte, src string) (string, error) {
	b, _ := os.ReadFile(src)
	if bytes.Contains(b, []byte("-----BEGIN")) {
		return "", errors.New("temp payload class")
	}
	return s.inner.EncryptFile(ctx, password, src)
}
func (s *countingReal) DecryptFile(ctx context.Context, password []byte, src, outDir string) (string, error) {
	return s.inner.DecryptFile(ctx, password, src, outDir)
}

func startQALauncher(t *testing.T) {
	t.Helper()
	launcher := filepath.Join(t.TempDir(), "ra-launcher")
	if err := os.Symlink("/bin/sleep", launcher); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROTTENCORE_RA_LAUNCHER", launcher)
	cmd := exec.Command(launcher, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, inst, run := LauncherStatus(); inst && run {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("launcher process was not visible")
}

func dialAgent(sock string) (net.Conn, error) {
	return net.DialTimeout("unix", sock, time.Second)
}

func scanTree(t *testing.T, root, seedHex string, seedRaw []byte, password string) {
	t.Helper()
	filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if bytes.Contains(b, []byte(seedHex)) || bytes.Contains(b, seedRaw) || bytes.Contains(b, []byte(password)) || bytes.Contains(b, []byte("-----BEGIN")) || bytes.Contains(bytes.ToLower(b), []byte("private_enc")) {
			t.Errorf("private material present in %s", path)
		}
		return nil
	})
}

func writeSlipZip(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../qa-slip.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("slip")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func errClass(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, qaPassword) || strings.Contains(s, "private_enc") || strings.Contains(s, "-----BEGIN") {
		return "error contained private material"
	}
	hexRun := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			hexRun++
			if hexRun >= 32 {
				return "error contained a long hex string"
			}
		default:
			hexRun = 0
		}
	}
	if len(s) > 180 {
		return s[:180]
	}
	return s
}

func exitCode(err error) int {
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func moduleCmd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "cmd", "rottencore")
}
