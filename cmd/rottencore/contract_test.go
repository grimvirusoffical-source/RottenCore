package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// Exact ra-core contract (RottenApple rxa-cert-ids @ 711171b, DEV_HUB_API.md §4a).
const (
	testAccountsKey = "ra_sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG" // 43 base62
	testBuildKey    = "ra_sk_live_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210ZYXWVUT"
	joshSubjectStr  = `{"name":"Josh Franklinn","teamId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB","devId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB"}`
)

func init() {
	if len(testAccountsKey) != 54 || len(testBuildKey) != 54 {
		panic("test keys must be ra_sk_live_ + 43")
	}
}

// fakeHub implements the contract with knobs for the failure cases.
type fakeHub struct {
	t             *testing.T
	rootPriv      ed25519.PrivateKey
	issPriv       ed25519.PrivateKey
	iss           core.Cert
	subject       string // cert.subject / account.subject bytes (compact)
	certSubject   string // subject the issued cert actually carries ("" = same as subject)
	nullSubject   bool
	notReady      bool
	contexts      int
	ctxKind       string
	certMismatch  bool // /certs → 403 accounts_key_mismatch
	pairMismatch  bool // /pairings/status → 403 pairing_account_mismatch
	noPollAccount bool // approved without account (pairing started without the header)
	polls         int32
	certCalls     int32
	sawBearer     atomic.Value
	sawAccounts   atomic.Value
	pairingHeader atomic.Value
}

func newFakeHub(t *testing.T) (*fakeHub, ed25519.PublicKey) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	issPub, issPriv, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	iss := core.Cert{Serial: "1", Kind: core.CertKindCA, Subject: core.CertSubject{Name: "Red-XAI Issuing"}, PublicKey: issPub, NotBefore: now - 60, NotAfter: now + 3600}
	if err := core.SignCert(&iss, rootPriv); err != nil {
		t.Fatal(err)
	}
	return &fakeHub{t: t, rootPriv: rootPriv, issPriv: issPriv, iss: iss, subject: joshSubjectStr, contexts: 1, ctxKind: "individual"}, rootPub
}

func (h *fakeHub) account() map[string]interface{} {
	var sub interface{} = json.RawMessage(h.subject)
	if h.nullSubject {
		sub = nil
	}
	return map[string]interface{}{"id": 1, "sub": joshRXA, "name": "GrimVirus", "email": "grimvirusoffical@gmail.com", "rxaLinked": true, "subject": sub}
}

func apiErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(devhub.LauncherHeader) == "" {
		apiErr(w, 426, "launcher_too_old", "")
		return
	}
	ak := r.Header.Get(devhub.AccountsKeyHeader)
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	enc := json.NewEncoder(w) // compact, like ra-core writeJSON
	switch r.URL.Path {
	case "/v1/devhub/pairings":
		h.pairingHeader.Store(ak)
		enc.Encode(map[string]interface{}{"code": "ABCD1234", "pollSecret": "ps", "expiresMs": time.Now().Add(time.Minute).UnixMilli()})
	case "/v1/devhub/pairings/status":
		if h.pairMismatch {
			apiErr(w, 403, "pairing_account_mismatch", "this pairing was started with another account's Red-XAI Accounts key")
			return
		}
		st := "pending"
		if atomic.AddInt32(&h.polls, 1) > 1 {
			st = "approved"
		}
		resp := map[string]interface{}{"state": st, "device": "dev1", "team": "1", "targets": []string{"macos", "ios"}}
		if st == "approved" && !h.noPollAccount {
			resp["account"] = h.account()
		}
		enc.Encode(resp)
	case devhub.AccountStatusPath:
		if ak != testAccountsKey {
			apiErr(w, 401, "accounts_key_required", "")
			return
		}
		if r.Header.Get("Authorization") != "" {
			h.t.Error("account-status must use the Accounts key alone")
		}
		ready := !h.notReady && !h.nullSubject
		cs := ""
		if ready {
			cs = h.subject
		}
		var ctxs []map[string]interface{}
		for i := 0; i < h.contexts; i++ {
			ctxs = append(ctxs, map[string]interface{}{"team": i + 1, "kind": h.ctxKind, "name": "Josh Franklinn", "certTeamId": joshRXA, "role": "owner", "mega": true})
		}
		enc.Encode(map[string]interface{}{"account": h.account(),
			"cert":     map[string]interface{}{"devId": joshRXA, "teamId": joshRXA, "subject": cs, "ready": ready},
			"contexts": ctxs})
	case "/v1/devhub/challenge":
		h.sawBearer.Store(r.Header.Get("Authorization"))
		h.sawAccounts.Store(ak)
		enc.Encode(map[string]string{"nonce": "n1", "team": "1", "purpose": "cert"})
	case "/v1/devhub/certs":
		atomic.AddInt32(&h.certCalls, 1)
		if r.Header.Get("Authorization") != "Bearer "+testBuildKey || ak != testAccountsKey {
			apiErr(w, 401, "build_key_required", "")
			return
		}
		if h.certMismatch {
			apiErr(w, 403, "accounts_key_mismatch", "the Red-XAI Accounts key and the build API key belong to different accounts")
			return
		}
		pk, _ := hex.DecodeString(body["publicKey"])
		subj := h.subject
		if h.certSubject != "" {
			subj = h.certSubject
		}
		var cs core.CertSubject
		_ = json.Unmarshal([]byte(subj), &cs)
		now := time.Now().Unix()
		leaf := core.Cert{Serial: "2", Kind: core.CertKindDeveloper, Subject: cs, PublicKey: pk, NotBefore: now - 60, NotAfter: now + 3600,
			Platforms: []string{"ios", "macos"}, Device: body["device"]}
		if err := core.SignCert(&leaf, h.issPriv); err != nil {
			h.t.Error(err)
		}
		lb, _ := json.Marshal(leaf)
		if h.certSubject != "" { // splice the raw subject bytes in, as a misbehaving server could
			var m map[string]json.RawMessage
			_ = json.Unmarshal(lb, &m)
			lb = []byte(strings.Replace(string(lb), string(m["subject"]), h.certSubject, 1))
		}
		ib, _ := json.Marshal(h.iss)
		if h.certSubject != "" { // write by hand: json.Encoder would compact RawMessage bytes
			fmt.Fprintf(w, `{"certificate":%s,"chain":[%s,%s],"fingerprint":%q}`, lb, lb, ib, leaf.Fingerprint())
			return
		}
		enc.Encode(map[string]interface{}{"certificate": json.RawMessage(lb), "chain": []json.RawMessage{lb, ib}, "fingerprint": leaf.Fingerprint()})
	default:
		http.NotFound(w, r)
	}
}

type pairEnv struct {
	hub     *fakeHub
	srv     *httptest.Server
	c       *devhub.Client
	mega    devhub.DeviceKey
	rootPub ed25519.PublicKey
}

func newPairEnv(t *testing.T, tweak func(*fakeHub)) *pairEnv {
	hub, rootPub := newFakeHub(t)
	if tweak != nil {
		tweak(hub)
	}
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	kc := &fakeKC{items: map[string]core.Signer{}}
	dev, _ := ensureKeychainKey(context.Background(), kc, "rottencore-device")
	mega, _ := ensureKeychainKey(context.Background(), kc, "josh-mega")
	c := &devhub.Client{BaseURL: srv.URL, APIKey: testBuildKey, Device: dev, Platform: devhub.PlatformMac, AccountsKey: []byte(testAccountsKey)}
	pairState = filepath.Join(t.TempDir(), "pairing.json")
	pairName = "xlr1-mac"
	return &pairEnv{hub: hub, srv: srv, c: c, mega: mega, rootPub: rootPub}
}

func (e *pairEnv) run(t *testing.T, yes string, wantDev, wantTeam string) ([]core.Cert, []json.RawMessage, []byte, error) {
	st, err := pairAndWait(context.Background(), e.c, 30*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	withTTY(t, yes)
	chain, raw, subject, _, err := issueMegaCert(context.Background(), e.c, e.mega, st, wantDev, wantTeam)
	return chain, raw, subject, err
}

func TestContractPairHappyPath(t *testing.T) {
	e := newPairEnv(t, nil)
	chain, raw, subject, err := e.run(t, "yes\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(subject) != joshSubjectStr {
		t.Fatalf("subject %s", subject)
	}
	if got, _ := e.hub.pairingHeader.Load().(string); got != testAccountsKey {
		t.Fatal("pairing must be started with the Accounts key header (raw)")
	}
	if b, _ := e.hub.sawBearer.Load().(string); b != "Bearer "+testBuildKey {
		t.Fatal("challenge must carry the build key as Bearer")
	}
	if a, _ := e.hub.sawAccounts.Load().(string); a != testAccountsKey {
		t.Fatal("challenge must carry the Accounts key too")
	}
	if _, err := core.VerifyCertChain(chain, core.ChainPolicy{Roots: []core.CARoot{{Name: "r", PublicKey: e.rootPub}}, Production: true}); err != nil {
		t.Fatalf("chain: %v", err)
	}
	// bundle round trip keeps the exact bytes
	out := filepath.Join(t.TempDir(), "b.json")
	if err := writeBundleExact(out, raw); err != nil {
		t.Fatal(err)
	}
	leaf, _, err := readBundleLeaf(out)
	if err != nil || core.EqualSubjectBytes(leaf, subject) != nil {
		t.Fatalf("bundle lost exact subject bytes: %v", err)
	}
	// optional cross-check: matching passes, mismatching fails closed
	e2 := newPairEnv(t, nil)
	if _, _, _, err := e2.run(t, "yes\n", joshRXA, joshRXA); err != nil {
		t.Fatalf("matching cross-check: %v", err)
	}
	e3 := newPairEnv(t, nil)
	if _, _, _, err := e3.run(t, "yes\n", "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR", ""); err == nil || atomic.LoadInt32(&e3.hub.certCalls) != 0 {
		t.Fatal("cross-check mismatch must stop before /certs")
	}
}

func TestContractPairStops(t *testing.T) {
	cases := []struct {
		name   string
		tweak  func(*fakeHub)
		yes    string
		want   string
		noCert bool
	}{
		{"null subject", func(h *fakeHub) { h.nullSubject = true }, "yes\n", "approved pairing carries no account", true},
		{"cert not ready", func(h *fakeHub) { h.notReady = true }, "yes\n", "cert.ready=false", true},
		{"no contexts", func(h *fakeHub) { h.contexts = 0 }, "yes\n", "exactly one", true},
		{"two contexts", func(h *fakeHub) { h.contexts = 2 }, "yes\n", "exactly one", true},
		{"kind vs team id", func(h *fakeHub) { h.ctxKind = "team" }, "yes\n", "does not fit", true},
		{"no yes", nil, "y\n", "not confirmed", true},
		{"accounts_key_mismatch", func(h *fakeHub) { h.certMismatch = true }, "yes\n", "accounts_key_mismatch", false},
		{"pairing without account", func(h *fakeHub) { h.noPollAccount = true }, "yes\n", "carries no account", true},
		{"issued subject differs", func(h *fakeHub) {
			h.certSubject = `{"name":"Josh Franklinn","teamId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB","devId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"}`
		}, "yes\n", "byte-for-byte", false},
		{"issued subject has whitespace", func(h *fakeHub) {
			h.certSubject = `{"name":"Josh Franklinn", "teamId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB","devId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB"}`
		}, "yes\n", "byte-for-byte", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newPairEnv(t, c.tweak)
			_, _, _, err := e.run(t, c.yes, "", "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
			if c.noCert && atomic.LoadInt32(&e.hub.certCalls) != 0 {
				t.Fatal("must stop before POST /v1/devhub/certs")
			}
			if c.name == "accounts_key_mismatch" && atomic.LoadInt32(&e.hub.certCalls) != 1 {
				t.Fatalf("accounts_key_mismatch must not be retried (%d calls)", e.hub.certCalls)
			}
		})
	}
}

func TestContractPairingAccountMismatch(t *testing.T) {
	e := newPairEnv(t, func(h *fakeHub) { h.pairMismatch = true })
	_, err := pairAndWait(context.Background(), e.c, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "pairing_account_mismatch") || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("got %v", err)
	}
}

func TestContractValidateAccountStatus(t *testing.T) {
	ok := func() *devhub.AccountStatusResponse {
		return &devhub.AccountStatusResponse{
			Account:  devhub.AccountIdentity{ID: 1, Sub: joshRXA, Name: "GrimVirus", Email: "e", RxaLinked: true, Subject: json.RawMessage(joshSubjectStr)},
			Cert:     devhub.CertIDs{DevID: joshRXA, TeamID: joshRXA, Subject: joshSubjectStr, Ready: true},
			Contexts: []devhub.AccountContext{{Team: "1", Kind: "individual", Name: "Josh Franklinn", CertTeamID: joshRXA, Role: "owner", Mega: true}},
		}
	}
	if s, err := validateAccountStatus(ok()); err != nil || string(s) != joshSubjectStr {
		t.Fatalf("good status refused: %v", err)
	}
	rxt := "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"
	teamSub := `{"name":"Red-XAI","teamId":"` + rxt + `","devId":"` + joshRXA + `"}`
	team := ok()
	team.Account.Subject, team.Cert.Subject, team.Cert.TeamID = json.RawMessage(teamSub), teamSub, rxt
	team.Contexts[0] = devhub.AccountContext{Team: "2", Kind: "team", Name: "Red-XAI", CertTeamID: rxt}
	if _, err := validateAccountStatus(team); err != nil {
		t.Fatalf("team context refused: %v", err)
	}
	bad := map[string]func(*devhub.AccountStatusResponse){
		"null subject":           func(s *devhub.AccountStatusResponse) { s.Account.Subject = json.RawMessage("null") },
		"not linked":             func(s *devhub.AccountStatusResponse) { s.Account.RxaLinked = false },
		"not ready":              func(s *devhub.AccountStatusResponse) { s.Cert.Ready = false },
		"zero contexts":          func(s *devhub.AccountStatusResponse) { s.Contexts = nil },
		"two contexts":           func(s *devhub.AccountStatusResponse) { s.Contexts = append(s.Contexts, s.Contexts[0]) },
		"account vs cert bytes":  func(s *devhub.AccountStatusResponse) { s.Cert.Subject = strings.Replace(joshSubjectStr, ",", ", ", 1) },
		"certTeamId disagrees":   func(s *devhub.AccountStatusResponse) { s.Contexts[0].CertTeamID = rxt },
		"cert.devId disagrees":   func(s *devhub.AccountStatusResponse) { s.Cert.DevID = "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR" },
		"sub disagrees":          func(s *devhub.AccountStatusResponse) { s.Account.Sub = "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR" },
		"context name disagrees": func(s *devhub.AccountStatusResponse) { s.Contexts[0].Name = "Josh" },
		"old ids": func(s *devhub.AccountStatusResponse) {
			o := `{"name":"Josh Franklinn","teamId":"T1","devId":"A1"}`
			s.Account.Subject, s.Cert.Subject, s.Cert.DevID, s.Cert.TeamID, s.Account.Sub, s.Contexts[0].CertTeamID = json.RawMessage(o), o, "A1", "T1", "A1", "T1"
		},
		"other rxa as team": func(s *devhub.AccountStatusResponse) {
			o := `{"name":"Josh Franklinn","teamId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR","devId":"` + joshRXA + `"}`
			s.Account.Subject, s.Cert.Subject, s.Cert.TeamID, s.Contexts[0].CertTeamID = json.RawMessage(o), o, "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR", "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"
		},
	}
	for name, f := range bad {
		st := ok()
		f(st)
		if _, err := validateAccountStatus(st); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfirmNeedsExactYes(t *testing.T) {
	st := &devhub.AccountStatusResponse{Account: devhub.AccountIdentity{Name: "GrimVirus", Email: "grimvirusoffical@gmail.com", Sub: joshRXA},
		Cert: devhub.CertIDs{Subject: joshSubjectStr}, Contexts: []devhub.AccountContext{{Kind: "individual", Name: "Josh Franklinn"}}}
	shown := withTTY(t, "yes\n")
	if err := confirmAccount(st, "x"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GrimVirus", "grimvirusoffical@gmail.com", joshSubjectStr, "Josh Franklinn"} {
		if !strings.Contains(shown.String(), want) {
			t.Errorf("confirmation did not show %q", want)
		}
	}
	for _, in := range []string{"y\n", "YES\n", "yes please\n", "\n", ""} {
		withTTY(t, in)
		if err := confirmAccount(st, "x"); err == nil {
			t.Errorf("confirmation %q accepted", in)
		}
	}
}

func TestAccountsKeyTTYOnlyFormatAndEnvRefused(t *testing.T) {
	out := withTTY(t, "  "+testAccountsKey+"  \n")
	k, err := readAccountsKey()
	if err != nil || string(k) != testAccountsKey {
		t.Fatalf("got err %v", err)
	}
	if strings.Contains(out.String(), testAccountsKey) {
		t.Fatal("key echoed to the terminal")
	}
	zero(k)
	for _, b := range k {
		if b != 0 {
			t.Fatal("zero() left key bytes")
		}
	}
	for _, bad := range []string{
		"rxk_secret_value",                            // not the format
		"ra_sk_live_" + testAccountsKey[11:53],        // 42
		testAccountsKey + "A",                         // 44
		"ra_sk_test_" + testAccountsKey[11:],          // wrong env
		"ra_sk_live_" + testAccountsKey[11:52] + "-_", // non-base62
		"RA_SK_LIVE_" + testAccountsKey[11:],          // case
		"Bearer " + testAccountsKey,                   // pasted header
	} {
		withTTY(t, bad+"\n")
		_, err := readAccountsKey()
		if err == nil {
			t.Errorf("bad key accepted (len %d)", len(bad))
			continue
		}
		if strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), testAccountsKey[11:20]) {
			t.Errorf("error echoes the key: %v", err)
		}
	}
	for _, name := range []string{"REDX_ACCOUNTS_KEY", "REDX_ACCOUNTS_API_KEY", "RA_ACCOUNTS_KEY", "RED_XAI_ACCOUNTS_TOKEN", "ACCOUNTS_API_KEY", "redx_accounts_key", "REDX_FULL_ACCESS_KEY"} {
		if refuseAccountsKeyEnv([]string{name + "=x"}) == nil {
			t.Errorf("%s not refused", name)
		}
		t.Setenv(name, testAccountsKey)
		withTTY(t, testAccountsKey+"\n")
		if _, err := readAccountsKey(); err == nil || strings.Contains(err.Error(), testAccountsKey) {
			t.Errorf("%s in env: must refuse without echoing the value (%v)", name, err)
		}
		os.Unsetenv(name)
	}
	if err := refuseAccountsKeyEnv([]string{"PATH=/bin", "RA_DEVHUB_URL=x", "ROTTEN_DEV_ID=x", "KEYCHAIN_SERVICE=x"}); err != nil {
		t.Errorf("benign env refused: %v", err)
	}
}

func TestCrossCheckIDsOptional(t *testing.T) {
	s := []byte(joshSubjectStr)
	if err := crossCheckIDs(s, "", ""); err != nil {
		t.Fatalf("no ids must not be required: %v", err)
	}
	if err := crossCheckIDs(s, joshRXA, joshRXA); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR", ""}, {"", "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"}, {"A7", ""}, {"", "T3"}} {
		if err := crossCheckIDs(s, c[0], c[1]); err == nil {
			t.Errorf("cross-check %v accepted", c)
		}
	}
}

// TestSigningIdentityCheck: the sign-batch gate against the exact account-status contract.
func TestSigningIdentityCheck(t *testing.T) {
	e := newPairEnv(t, nil)
	_, raw, _, err := e.run(t, "yes\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	signBundle = filepath.Join(t.TempDir(), "josh-mega.bundle.json")
	if err := writeBundleExact(signBundle, raw); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RA_DEVHUB_URL", e.srv.URL)
	t.Setenv("ROTTEN_DEV_ID", "")
	t.Setenv("ROTTEN_TEAM_ID", "")
	trustRootHex = hex.EncodeToString(e.rootPub)
	defer func() { trustRootHex, signBundle = "", "" }()

	withTTYSeq(t, testAccountsKey+"\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err != nil {
		t.Fatalf("good identity refused: %v", err)
	}
	withTTYSeq(t, testAccountsKey+"\n", "no\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("signing went ahead without yes")
	}
	for name, tweak := range map[string]func(*fakeHub){
		"null subject": func(h *fakeHub) { h.nullSubject = true },
		"not ready":    func(h *fakeHub) { h.notReady = true },
		"two contexts": func(h *fakeHub) { h.contexts = 2 },
		"other account": func(h *fakeHub) {
			h.subject = `{"name":"Josh Franklinn","teamId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR","devId":"rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"}`
		},
	} {
		h := *e.hub
		tweak(&h)
		srv := httptest.NewServer(&h)
		t.Setenv("RA_DEVHUB_URL", srv.URL)
		withTTYSeq(t, testAccountsKey+"\n", "yes\n")
		if err := signingIdentityCheck(context.Background()); err == nil {
			t.Errorf("%s: signing gate passed", name)
		}
		srv.Close()
	}
	t.Setenv("RA_DEVHUB_URL", e.srv.URL)
	t.Setenv("ROTTEN_DEV_ID", "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR")
	withTTYSeq(t, testAccountsKey+"\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("optional cross-check mismatch passed")
	}
	t.Setenv("ROTTEN_DEV_ID", "")
	trustRootHex = hex.EncodeToString(e.hub.iss.PublicKey) // wrong root
	withTTYSeq(t, testAccountsKey+"\n", "yes\n")
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("wrong root accepted")
	}
	trustRootHex = ""
	if err := signingIdentityCheck(context.Background()); err == nil {
		t.Fatal("empty --trust-root accepted")
	}
}
