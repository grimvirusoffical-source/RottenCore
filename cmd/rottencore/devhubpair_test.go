package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/core"
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
