package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

type fakeKC struct {
	items   map[string]core.Signer
	secrets map[string]string
	gets    int
}

func (f *fakeKC) Has(l string) bool { _, ok := f.items[l]; return ok }
func (f *fakeKC) Put(l string, k core.Signer) error {
	if f.Has(l) {
		return errors.New("exists")
	}
	f.items[l] = k
	return nil
}
func (f *fakeKC) Get(l string) (core.Signer, error) {
	f.gets++
	k, ok := f.items[l]
	if !ok {
		return nil, errors.New("missing")
	}
	return k, nil
}
func (f *fakeKC) GetSecret(l string) (string, error) {
	s, ok := f.secrets[l]
	if !ok {
		return "", errors.New("missing")
	}
	return s, nil
}

func TestEnsureKeychainKeyGeneratesOnceAndNeverOverwrites(t *testing.T) {
	kc := &fakeKC{items: map[string]core.Signer{}}
	a, err := ensureKeychainKey(context.Background(), kc, "rottencore-device")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ensureKeychainKey(context.Background(), kc, "rottencore-device")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Public()) != string(b.Public()) {
		t.Fatal("second call must reuse the Keychain key, not regenerate")
	}
}

const joshRXA = "rxa_LVWECFKVPN6XMPISHYONVY6WUB"

func joshSubject() json.RawMessage {
	return json.RawMessage(`{"name":"Josh Franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA + `"}`)
}

func TestCheckMegaLeafByteExact(t *testing.T) {
	pub := make([]byte, 32)
	pub[0] = 7
	leaf := &core.Cert{Kind: core.CertKindDeveloper, PublicKey: pub}
	cert := []byte(`{"kind":"developer","subject":` + string(joshSubject()) + `}`)
	if err := checkMegaLeaf(leaf, cert, pub, joshSubject()); err != nil {
		t.Fatalf("exact subject refused: %v", err)
	}
	other := json.RawMessage(strings.Replace(string(joshSubject()), joshRXA+`"}`, joshRXA[:29]+`A"}`, 1))
	if err := checkMegaLeaf(leaf, cert, pub, other); err == nil {
		t.Fatal("subject differing in one byte accepted")
	}
	if err := checkMegaLeaf(leaf, cert, make([]byte, 32), joshSubject()); err == nil {
		t.Fatal("leaf for another key accepted")
	}
	ca := &core.Cert{Kind: core.CertKindCA, PublicKey: pub}
	if err := checkMegaLeaf(ca, cert, pub, joshSubject()); err == nil {
		t.Fatal("ca leaf accepted")
	}
}

// stubTTY feeds input to ttyOpen and records what was written.
type stubTTY struct {
	in  *strings.Reader
	out *strings.Builder
}

func (s stubTTY) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s stubTTY) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s stubTTY) Close() error                { return nil }

func withTTY(t *testing.T, input string) *strings.Builder {
	t.Helper()
	out := &strings.Builder{}
	oldOpen, oldEcho := ttyOpen, ttyEcho
	ttyOpen = func() (io.ReadWriteCloser, error) { return stubTTY{strings.NewReader(input), out}, nil }
	ttyEcho = func(io.ReadWriteCloser, bool) error { return nil }
	t.Cleanup(func() { ttyOpen, ttyEcho = oldOpen, oldEcho })
	return out
}

// TestDevhubPairFlow drives pairing (pending -> approved), challenge and /certs against a fake hub that
// issues a device-bound cert (platforms+device), then checks the chain verifies to the root byte-exactly.
func TestDevhubPairFlow(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	issPub, issPriv, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	iss := core.Cert{Serial: "1", Kind: core.CertKindCA, Subject: core.CertSubject{Name: "Issuing"}, PublicKey: issPub, NotBefore: now - 60, NotAfter: now + 3600}
	if err := core.SignCert(&iss, rootPriv); err != nil {
		t.Fatal(err)
	}
	var polls int32
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(devhub.LauncherHeader) == "" {
			http.Error(w, "launcher", 426)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/devhub/ca/chain" && r.Header.Get(devhub.AccountsKeyHeader) != "rxk_test_accounts_key" {
			http.Error(w, "accounts key", 401)
			return
		}
		switch r.URL.Path {
		case "/v1/devhub/pairings":
			json.NewEncoder(w).Encode(map[string]interface{}{"code": "ABCD1234", "pollSecret": "ps", "expiresMs": time.Now().Add(time.Minute).UnixMilli()})
		case "/v1/devhub/pairings/status":
			st := "pending"
			if atomic.AddInt32(&polls, 1) > 1 {
				st = "approved"
			}
			resp := map[string]interface{}{"state": st, "device": "dev1", "team": joshRXA, "targets": []string{"macos", "ios"}}
			if st == "approved" {
				resp["account"] = map[string]interface{}{"name": "Josh Franklinn", "email": "grimvirusoffical@gmail.com", "subject": joshSubject()}
			}
			json.NewEncoder(w).Encode(resp)
		case "/v1/devhub/challenge":
			gotAuth.Store(r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(map[string]string{"nonce": "n1", "team": "T34", "purpose": "cert"})
		case "/v1/devhub/certs":
			pk, _ := hex.DecodeString(body["publicKey"])
			devPubFP := body["device"]
			var subj core.CertSubject
			_ = json.Unmarshal(joshSubject(), &subj)
			leaf := core.Cert{Serial: "2", Kind: core.CertKindDeveloper, Subject: subj,
				PublicKey: pk, NotBefore: now - 60, NotAfter: now + 3600, Platforms: []string{"ios", "macos"}, Device: devPubFP}
			if err := core.SignCert(&leaf, issPriv); err != nil {
				t.Error(err)
			}
			lb, _ := json.Marshal(leaf)
			ib, _ := json.Marshal(iss)
			json.NewEncoder(w).Encode(map[string]interface{}{"certificate": json.RawMessage(lb), "chain": []json.RawMessage{lb, ib}, "fingerprint": leaf.Fingerprint()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	kc := &fakeKC{items: map[string]core.Signer{}}
	dev, err := ensureKeychainKey(context.Background(), kc, "rottencore-device")
	if err != nil {
		t.Fatal(err)
	}
	mega, err := ensureKeychainKey(context.Background(), kc, "josh-mega")
	if err != nil {
		t.Fatal(err)
	}
	c := &devhub.Client{BaseURL: srv.URL, APIKey: "ra_sk_test", Device: dev, Platform: devhub.PlatformMac,
		AccountsKey: []byte("rxk_test_accounts_key")}
	pairState = filepath.Join(t.TempDir(), "pairing.json")
	pairName = "xlr1-mac"
	st, err := pairAndWait(context.Background(), c, 30*time.Second)
	if err != nil || st.State != "approved" {
		t.Fatalf("pairing: %v %+v", err, st)
	}
	if err := checkServerSubject(st.Account, joshRXA, joshRXA); err != nil {
		t.Fatal(err)
	}
	if err := checkServerSubject(st.Account, joshRXA, "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"); err == nil {
		t.Fatal("team cross-check mismatch accepted")
	}
	shown := withTTY(t, "yes\n")
	if err := confirmAccount(st.Account, "issue"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Josh Franklinn", "grimvirusoffical@gmail.com", joshRXA} {
		if !strings.Contains(shown.String(), want) {
			t.Fatalf("confirmation did not show %q: %s", want, shown.String())
		}
	}
	resp, err := c.IssueCert(context.Background(), mega)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := gotAuth.Load().(string); !strings.HasPrefix(a, "Bearer ") {
		t.Fatal("build key not sent as a Bearer header")
	}
	chain, raw, err := certChainFrom(resp)
	if err != nil || len(chain) != 2 || len(raw) != 2 {
		t.Fatalf("chain: %v %d", err, len(chain))
	}
	if err := checkMegaLeaf(&chain[0], raw[0], mega.Public(), st.Account.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := core.VerifyCertChain(chain, core.ChainPolicy{Roots: []core.CARoot{{Name: "r", PublicKey: rootPub}}, Production: true}); err != nil {
		t.Fatalf("device-bound chain must verify (platforms/device kept in tbs): %v", err)
	}
}

func TestReadBuildKeyFromKeychainNotEnv(t *testing.T) {
	t.Setenv("RA_API_KEY", "from-env-must-not-be-used")
	kc := &fakeKC{secrets: map[string]string{"ra-build-api-key": "ra_sk_kc"}}
	pairKeyStdin, pairAPIKeyLabel = false, ""
	k, err := readBuildKey(kc)
	if err != nil || k != "ra_sk_kc" {
		t.Fatalf("got %q %v", k, err)
	}
}

func TestReadSignList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.tsv")
	writeFileT(t, p, "# c\n/abs/a.dmg\tcom.redx.a\t1.0.0\tmacos\n/abs/b.pkg\tcom.redx.b\t2.0\n")
	j, err := readSignList(p)
	if err != nil || len(j) != 2 || j[0][3] != "macos" || j[1][3] != "" {
		t.Fatalf("%v %v", j, err)
	}
	writeFileT(t, p, "rel/a.dmg\tx\t1\n")
	if _, err := readSignList(p); err == nil {
		t.Fatal("relative path accepted")
	}
}

func writeFileT(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDevhubPairSourceKeepsKeysInProcess is a static check of QA F1: the pair command writes keys only
// through the Keychain store and never to a file, the environment, or stdout.
func TestDevhubPairSourceKeepsKeysInProcess(t *testing.T) {
	b, err := os.ReadFile("devhubpair.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, bad := range []string{"WriteKey(", "os.Setenv(", "ExportKey", ".Key)", "Priv)", "exec.Command(\"security\""} {
		if strings.Contains(src, bad) {
			t.Errorf("devhubpair.go contains %q", bad)
		}
	}
	if !strings.Contains(src, "kc.Put(label, k)") {
		t.Error("generated keys must go straight into the Keychain via Put")
	}
}

func TestConfirmNeedsExactYes(t *testing.T) {
	who := &devhub.AccountIdentity{Name: "Josh Franklinn", Email: "e", Subject: joshSubject()}
	for _, in := range []string{"y\n", "YES\n", "yes please\n", "\n", ""} {
		withTTY(t, in)
		if err := confirmAccount(who, "x"); err == nil {
			t.Errorf("confirmation %q accepted", in)
		}
	}
}

func TestAccountsKeyTTYOnlyAndEnvRefused(t *testing.T) {
	out := withTTY(t, "  rxk_secret_value  \n")
	k, err := readAccountsKey()
	if err != nil || string(k) != "rxk_secret_value" {
		t.Fatalf("got %q %v", k, err)
	}
	if strings.Contains(out.String(), "rxk_secret_value") {
		t.Fatal("key echoed to the terminal")
	}
	zero(k)
	for _, b := range k {
		if b != 0 {
			t.Fatal("zero() left key bytes")
		}
	}
	for _, name := range []string{"REDX_ACCOUNTS_KEY", "REDX_ACCOUNTS_API_KEY", "RA_ACCOUNTS_KEY", "RED_XAI_ACCOUNTS_TOKEN", "ACCOUNTS_API_KEY", "redx_accounts_key", "REDX_FULL_ACCESS_KEY"} {
		if refuseAccountsKeyEnv([]string{name + "=x"}) == nil {
			t.Errorf("%s not refused", name)
		}
		t.Setenv(name, "x")
		withTTY(t, "k\n")
		if _, err := readAccountsKey(); err == nil || strings.Contains(err.Error(), "=x") {
			t.Errorf("%s in env: readAccountsKey must refuse without echoing the value (%v)", name, err)
		}
		os.Unsetenv(name)
	}
	if err := refuseAccountsKeyEnv([]string{"PATH=/bin", "RA_DEVHUB_URL=x", "ROTTEN_DEV_ID=x", "KEYCHAIN_SERVICE=x"}); err != nil {
		t.Errorf("benign env refused: %v", err)
	}
	withTTY(t, "\n")
	if _, err := readAccountsKey(); err == nil {
		t.Error("empty key accepted")
	}
}

func TestAccountsKeySourceNeverStored(t *testing.T) {
	for _, f := range []string{"accountskey.go", "devhubpair.go", "sign.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		bads := []string{"redx-accounts-api-key", "Getenv(\"REDX_ACCOUNTS", "AccountsKey: []byte(os", "WriteFile(\"accounts", "Println(string(akey", "Printf(\"%s\", akey"}
		if f != "sign.go" { // sign.go's build-inbox Setenv is the scoped build key, not the Accounts key
			bads = append(bads, "Setenv(")
		}
		for _, bad := range bads {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

func TestRolloutIDPatternsMatchGo(t *testing.T) {
	b, err := os.ReadFile("../../scripts/rollout/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "ROTTEN_DEV_ID_PATTERN='"+core.DevIDPattern+"'") {
		t.Error("lib.sh ROTTEN_DEV_ID_PATTERN drifted from core.DevIDPattern")
	}
	var pats []string
	for _, p := range core.TeamIDPatterns {
		pats = append(pats, "'"+p.Pattern+"'")
	}
	if !strings.Contains(src, "ROTTEN_TEAM_ID_PATTERNS=("+strings.Join(pats, " ")+")") {
		t.Error("lib.sh ROTTEN_TEAM_ID_PATTERNS drifted from core.TeamIDPatterns")
	}
}

func withTTYSeq(t *testing.T, inputs ...string) {
	t.Helper()
	i := 0
	oldOpen, oldEcho := ttyOpen, ttyEcho
	ttyOpen = func() (io.ReadWriteCloser, error) {
		in := ""
		if i < len(inputs) {
			in = inputs[i]
		}
		i++
		return stubTTY{strings.NewReader(in), &strings.Builder{}}, nil
	}
	ttyEcho = func(io.ReadWriteCloser, bool) error { return nil }
	t.Cleanup(func() { ttyOpen, ttyEcho = oldOpen, oldEcho })
}

// TestSigningIdentityCheck covers the signing-time gate of sign-batch.
func TestSigningIdentityCheck(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	issPub, issPriv, _ := ed25519.GenerateKey(nil)
	megaPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	iss := core.Cert{Serial: "1", Kind: core.CertKindCA, Subject: core.CertSubject{Name: "Issuing"}, PublicKey: issPub, NotBefore: now - 60, NotAfter: now + 3600}
	_ = core.SignCert(&iss, rootPriv)
	var subj core.CertSubject
	_ = json.Unmarshal(joshSubject(), &subj)
	leaf := core.Cert{Serial: "2", Kind: core.CertKindDeveloper, Subject: subj, PublicKey: megaPub, NotBefore: now - 60, NotAfter: now + 3600}
	_ = core.SignCert(&leaf, issPriv)
	lb, _ := json.Marshal(leaf)
	ib, _ := json.Marshal(iss)
	dir := t.TempDir()
	signBundle = filepath.Join(dir, "josh-mega.bundle.json")
	if err := writeJSON0600(signBundle, map[string]interface{}{"chain": []json.RawMessage{lb, ib}, "tier": "developer"}); err != nil {
		t.Fatal(err)
	}
	serverSubject := joshSubject()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != devhub.AccountStatusPath || r.Header.Get(devhub.AccountsKeyHeader) != "rxk_k" {
			http.Error(w, "no", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"account": map[string]interface{}{"name": "Josh Franklinn", "email": "e", "subject": serverSubject}})
	}))
	defer srv.Close()
	t.Setenv("RA_DEVHUB_URL", srv.URL)
	t.Setenv("ROTTEN_DEV_ID", joshRXA)
	t.Setenv("ROTTEN_TEAM_ID", joshRXA)
	trustRootHex = hex.EncodeToString(rootPub)
	defer func() { trustRootHex, signBundle = "", "" }()

	withTTYSeq(t, "rxk_k\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err != nil {
		t.Fatalf("good identity refused: %v", err)
	}
	withTTYSeq(t, "rxk_k\n", "no\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("signing went ahead without yes")
	}
	serverSubject = json.RawMessage(`{"name":"Josh Franklinn","teamId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR","devId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"}`)
	t.Setenv("ROTTEN_DEV_ID", "")
	t.Setenv("ROTTEN_TEAM_ID", "")
	withTTYSeq(t, "rxk_k\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("bundle for another account accepted")
	}
	serverSubject = joshSubject()
	trustRootHex = hex.EncodeToString(issPub) // wrong root
	withTTYSeq(t, "rxk_k\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("chain to a wrong root accepted")
	}
	trustRootHex = ""
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("empty --trust-root accepted")
	}
}
