package core

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

type testSealer struct{ password string }

func (s testSealer) Encrypt(_ context.Context, password, plaintext []byte) ([]byte, error) {
	if string(password) != s.password {
		return nil, errors.New("wrong password")
	}
	return append([]byte("RXAI2."), []byte(base64.StdEncoding.EncodeToString(plaintext))...), nil
}

func (s testSealer) Decrypt(_ context.Context, password, ciphertext []byte) ([]byte, error) {
	if string(password) != s.password {
		return nil, errors.New("wrong password")
	}
	raw := bytesTrim(ciphertext)
	const p = "RXAI2."
	if !strings.HasPrefix(string(raw), p) {
		return nil, errors.New("not sealed")
	}
	return base64.StdEncoding.DecodeString(string(raw[len(p):]))
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func zipTool(t *testing.T, dir, version string) string {
	t.Helper()
	p := filepath.Join(dir, "tool-"+version+".zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("rottencore.json")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(w, `{"schema":1,"appId":"com.acme.tool","name":"Tool","version":"%s","source":"store"}`, version)
	w, err = zw.Create("payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("bytes-" + version)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func lifetimeFixture(t *testing.T) (c *Core, srv *httptest.Server, owner, dev, leaky, password, seedHex string, seal testSealer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sign.Wipe(priv) })
	password = "owner-secret-password"
	seal = testSealer{password: password}
	seedHex = hex.EncodeToString(priv.Seed())
	enc, err := seal.Encrypt(context.Background(), []byte(password), []byte(hex.EncodeToString(priv)))
	if err != nil {
		t.Fatal(err)
	}
	owner, dev, leaky = "owner-token", "dev-token", "leaky-dev"
	pubHex := hex.EncodeToString(pub)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(Discovery{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/oauth2/authorize", TokenEndpoint: srv.URL + "/oauth2/token",
				UserinfoEndpoint: srv.URL + "/oauth2/userinfo", JWKSURI: srv.URL + "/oauth2/jwks"})
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			http.Error(w, "no", 401)
			return
		}
		switch r.URL.Path {
		case "/oauth2/userinfo":
			switch tok {
			case owner:
				json.NewEncoder(w).Encode(map[string]interface{}{
					"sub": "owner", "email": "support@infected-nation.com", "email_verified": true,
					"preferred_username": "owner", "age_band": "18+", "adult_verified": true,
					"idVerified": true, "idVerifiedMs": 1700000000000, "amr": []string{"pwd", "otp"},
				})
			case leaky:
				json.NewEncoder(w).Encode(map[string]interface{}{
					"sub": "dev", "email": "dev@example.com", "email_verified": true, "amr": []string{"pwd"},
				})
			default:
				json.NewEncoder(w).Encode(map[string]interface{}{
					"sub": "dev", "email": "dev@example.com", "email_verified": true,
					"idVerified": false, "amr": []string{"pwd"},
				})
			}
		case "/v1/rxa-lifetime-cert":
			if tok != owner && tok != leaky {
				http.Error(w, "no", 403)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"kind": "rxa-lifetime-cert", "cert_id": "cert-1", "pubkey": pubHex,
				"private_enc": string(enc), "issued": "2026-10-27T00:00:00Z",
				"owner_emails":  []string{"support@infected-nation.com", "grimvirusoffical@gmail.com"},
				"sig_id_prefix": "rxa",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c = testCore(t, newFake(), "", nil)
	c.Accounts = &OIDCAccounts{Issuer: srv.URL, Net: c.Net}
	return c, srv, owner, dev, leaky, password, seedHex, seal
}

func assertNoKey(t *testing.T, seed, password string, blobs ...[]byte) {
	t.Helper()
	for _, b := range blobs {
		if strings.Contains(string(b), seed) || strings.Contains(string(b), password) || strings.Contains(string(b), "private_enc") {
			t.Fatalf("secret landed in output: %.80q", b)
		}
	}
}

func TestLifetimeSignOwnerAndChain(t *testing.T) {
	c, _, owner, _, _, password, seed, seal := lifetimeFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	a := zipTool(t, dir, "1.0.0")
	b := zipTool(t, dir, "1.1.0")
	first, err := c.SignLifetime(ctx, owner, []byte(password), a, "linux", false, seal)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrevSigID != "" || first.CertID != "cert-1" || !strings.HasPrefix(first.SigID, "rxa_") || first.LauncherRequired {
		t.Fatalf("%+v", first)
	}
	if first.OfficialOSSigning != sign.OfficialOSNote {
		t.Fatal(first.OfficialOSSigning)
	}
	sum, _, err := FileSHA256(a)
	if err != nil || first.Hash != sum {
		t.Fatalf("hash %s want %s", first.Hash, sum)
	}
	openCarrier := func(path string) sign.Payload {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := seal.Decrypt(context.Background(), []byte(password), raw)
		if err != nil {
			t.Fatal(err)
		}
		defer sign.Wipe(plain)
		p, err := sign.Parse(plain)
		if err != nil {
			t.Fatal(err)
		}
		if err := sign.Verify(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p1 := openCarrier(first.Output)
	if p1.Cert.Issuer != sign.Issuer || p1.AppID != "com.acme.tool" || p1.Version != "1.0.0" || p1.Platforms[0] != "linux" {
		t.Fatalf("%+v", p1)
	}
	second, err := c.SignLifetime(ctx, owner, []byte(password), b, "macos", false, seal)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevSigID != first.SigID || second.SigID == first.SigID || second.CertID != first.CertID {
		t.Fatalf("chain %+v %+v", first, second)
	}
	p2 := openCarrier(second.Output)
	if p2.PrevSigID != first.SigID || p2.Version != "1.1.0" {
		t.Fatalf("%+v", p2)
	}
	out, _ := os.ReadFile(first.Output)
	chain, _ := os.ReadFile(c.chainPath())
	jb, _ := json.Marshal(first)
	assertNoKey(t, seed, password, out, chain, jb)
	st, err := os.Stat(first.Output)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("carrier mode %v %v", st, err)
	}
	plats, err := sign.HostPlatforms(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	iosOK := false
	for _, p := range plats {
		if p == "ios" {
			iosOK = true
		}
	}
	if !iosOK {
		if _, err := c.SignLifetime(ctx, owner, []byte(password), a, "ios", false, seal); err == nil || !strings.Contains(err.Error(), "cannot sign for ios") {
			t.Fatal(err)
		}
	}
}

func TestDevCannotDecryptEvenIfCiphertextIsReturned(t *testing.T) {
	c, _, _, _, leaky, password, seed, seal := lifetimeFixture(t)
	path := zipTool(t, t.TempDir(), "1.0.0")
	_, err := c.SignLifetime(context.Background(), leaky, []byte(password), path, "linux", true, seal)
	if !errors.Is(err, ErrOwnerSession) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), password) {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(path + ".rotten_core_signed"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("dev sign wrote a carrier")
	}
}

func TestWhoAmIAndAccountDocument(t *testing.T) {
	c, srv, owner, dev, _, _, seed, _ := lifetimeFixture(t)
	_ = srv
	w, err := c.WhoAmI(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if w.Role != sign.RoleOwner || !w.IDVerified || w.IDVerifiedMs != 1700000000000 || !w.MFA || w.Email != "support@infected-nation.com" {
		t.Fatalf("%+v", w)
	}
	if _, installed, _ := LauncherStatus(); w.LauncherInstalled != installed {
		t.Fatal("launcher installed mismatch")
	}
	b, _ := json.Marshal(w)
	if strings.Contains(string(b), seed) || strings.Contains(string(b), "private") {
		t.Fatalf("%s", b)
	}
	dw, err := c.WhoAmI(context.Background(), dev)
	if err != nil || dw.Role != sign.RoleDev {
		t.Fatal(err, dw)
	}
	if _, err := c.WhoAmI(context.Background(), ""); !errors.Is(err, ErrSignInRequired) {
		t.Fatal(err)
	}
}

func TestProfileReadsIDFromAccountDocument(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Discovery{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/oauth2/authorize", TokenEndpoint: srv.URL + "/oauth2/token",
				UserinfoEndpoint: srv.URL + "/oauth2/userinfo", JWKSURI: srv.URL + "/oauth2/jwks"})
		case "/oauth2/userinfo":
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "no", 401)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"sub": "o", "email": "grimvirusoffical@gmail.com", "email_verified": true, "amr": []string{"pwd", "otp"}})
		case "/v1/rxa-account":
			json.NewEncoder(w).Encode(map[string]interface{}{"idVerified": true, "idVerifiedMs": 42})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	o := &OIDCAccounts{Issuer: srv.URL, Net: &Net{AllowLoopbackHTTP: true}}
	if err := o.UseToken("tok"); err != nil {
		t.Fatal(err)
	}
	p, err := o.Profile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !p.IDVerified || p.IDVerifiedMs != 42 || !p.MFA || !p.Verified {
		t.Fatalf("%+v", p)
	}
	if sign.RoleFromProfile(p.Email, p.Verified, p.IDVerified, p.MFA) != sign.RoleOwner {
		t.Fatal("gmail owner")
	}
}

func TestAgentSignsForDevOnlyWithLauncher(t *testing.T) {
	c, _, owner, dev, _, password, seed, seal := lifetimeFixture(t)
	launcher := filepath.Join(t.TempDir(), "ra-launcher")
	if err := os.Symlink("/bin/sleep", launcher); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROTTENCORE_RA_LAUNCHER", launcher)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw := append([]byte(nil), password...)
	errCh := make(chan error, 1)
	go func() { errCh <- c.RunAgent(ctx, owner, pw, seal) }()
	waitAgent(t, c)
	sign.Wipe(pw)
	path := zipTool(t, t.TempDir(), "2.0.0")
	if _, err := c.AgentSign(ctx, dev, path, "linux", false); err == nil || !strings.Contains(err.Error(), sign.ErrDevLauncher.Error()) {
		t.Fatalf("dev without launcher: %v", err)
	}
	if _, err := c.AgentSign(ctx, dev, path, "linux", true); err == nil || !strings.Contains(err.Error(), "installed and running") {
		t.Fatalf("dev launcher down: %v", err)
	}
	cmd := exec.Command(launcher, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, inst, run := LauncherStatus(); inst && run {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, run := LauncherStatus(); !run {
		t.Fatal("launcher process was not visible")
	}
	res, err := c.AgentSign(ctx, dev, path, "android", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.LauncherRequired || res.CertID != "cert-1" || res.Platforms[0] != "android" {
		t.Fatalf("%+v", res)
	}
	raw, _ := os.ReadFile(res.Output)
	jb, _ := json.Marshal(res)
	assertNoKey(t, seed, password, raw, jb)
	plain, err := seal.Decrypt(context.Background(), []byte(password), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer sign.Wipe(plain)
	payload, err := sign.Parse(plain)
	if err != nil || sign.Verify(payload) != nil || !payload.LauncherRequired {
		t.Fatalf("%v %+v", err, payload)
	}
	sconn, err := net.DialTimeout("unix", c.agentSocket(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sconn.Write([]byte("{\"op\":\"sign\",\"private_key\":\"nope\",\"path\":\"x\",\"platform\":\"linux\",\"withLauncher\":true,\"token\":\"dev-token\"}\n")); err != nil {
		t.Fatal(err)
	}
	var env agentEnvelope
	if err := json.NewDecoder(sconn).Decode(&env); err != nil || env.OK || strings.Contains(env.Error, "nope") {
		t.Fatalf("%+v %v", env, err)
	}
	sconn.Close()
	if err := c.ShutdownAgent(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not exit")
	}
	if _, err := c.AgentSign(ctx, dev, path, "linux", true); !errors.Is(err, ErrAgentDown) {
		t.Fatal(err)
	}
}

func TestAgentRejectsDevUnlock(t *testing.T) {
	c, _, _, dev, _, password, seed, seal := lifetimeFixture(t)
	err := c.RunAgent(context.Background(), dev, []byte(password), seal)
	if !errors.Is(err, ErrNotOwnerUnlock) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), seed) || strings.Contains(err.Error(), password) {
		t.Fatal(err)
	}
	if c.AgentRunning() {
		t.Fatal("dev unlock left an agent up")
	}
}

func TestAgentHandshakeFrames(t *testing.T) {
	var buf []byte
	put := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		buf = append(buf, n[:]...)
		buf = append(buf, s...)
	}
	put("ab")
	put("c")
	token, pw, err := ReadAgentHandshake(strings.NewReader(string(buf)))
	if err != nil || token != "ab" || string(pw) != "c" {
		t.Fatalf("%q %q %v", token, pw, err)
	}
	sign.Wipe(pw)
}

func waitAgent(t *testing.T, c *Core) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.AgentRunning() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("signing agent did not start")
}
