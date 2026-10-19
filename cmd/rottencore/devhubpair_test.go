package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestCheckMegaLeafExactMatch(t *testing.T) {
	pub := make([]byte, 32)
	pub[0] = 7
	leaf := &core.Cert{Kind: core.CertKindDeveloper, Subject: core.CertSubject{DevID: "A12", TeamID: "T34"}, PublicKey: pub}
	if err := checkMegaLeaf(leaf, pub, "A12", "T34"); err != nil {
		t.Fatalf("exact match refused: %v", err)
	}
	for _, c := range []struct{ dev, team string }{{"A1", "T34"}, {"12", "T34"}, {"A12", "T3"}, {"A12", "34"}, {"A123", "T34"}} {
		if err := checkMegaLeaf(leaf, pub, c.dev, c.team); err == nil {
			t.Fatalf("near-miss dev=%s team=%s accepted (M3 needs exact)", c.dev, c.team)
		}
	}
	other := make([]byte, 32)
	if err := checkMegaLeaf(leaf, other, "A12", "T34"); err == nil {
		t.Fatal("leaf for another key accepted")
	}
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
		switch r.URL.Path {
		case "/v1/devhub/pairings":
			json.NewEncoder(w).Encode(map[string]interface{}{"code": "ABCD1234", "pollSecret": "ps", "expiresMs": time.Now().Add(time.Minute).UnixMilli()})
		case "/v1/devhub/pairings/status":
			st := "pending"
			if atomic.AddInt32(&polls, 1) > 1 {
				st = "approved"
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"state": st, "device": "dev1", "team": "T34", "targets": []string{"macos", "ios"}})
		case "/v1/devhub/challenge":
			gotAuth.Store(r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(map[string]string{"nonce": "n1", "team": "T34", "purpose": "cert"})
		case "/v1/devhub/certs":
			pk, _ := hex.DecodeString(body["publicKey"])
			devPubFP := body["device"]
			leaf := core.Cert{Serial: "2", Kind: core.CertKindDeveloper, Subject: core.CertSubject{Name: "Josh", TeamID: "T34", DevID: "A12"},
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
	c := &devhub.Client{BaseURL: srv.URL, APIKey: "ra_sk_test", Device: dev, Platform: devhub.PlatformMac}
	pairState = filepath.Join(t.TempDir(), "pairing.json")
	pairName = "xlr1-mac"
	st, err := pairAndWait(context.Background(), c, 30*time.Second)
	if err != nil || st.State != "approved" {
		t.Fatalf("pairing: %v %+v", err, st)
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
	if err := checkMegaLeaf(&chain[0], mega.Public(), "A12", "T34"); err != nil {
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
