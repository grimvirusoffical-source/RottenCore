package devhub

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeStore implements the dev-hub API from docs/DEV_HUB_API.md closely enough to exercise the client,
// including verifying the Ed25519 signatures the client produces.
type fakeStore struct {
	t           *testing.T
	pubByFP     map[string][]byte // device fingerprint -> device public key
	team        string
	nonces      map[string]string // nonce -> purpose
	certIssuer  bool              // false => 501 cert_issuer_not_configured
	sdkFailCode string            // when set, GET apps/{id}/sdks returns 422 with this code
	approved    bool
}

func newFakeStore(t *testing.T) *fakeStore {
	return &fakeStore{t: t, pubByFP: map[string][]byte{}, team: "7", nonces: map[string]string{}, certIssuer: true, approved: true}
}

func (f *fakeStore) needKey(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		writeErrString(w, 401, "build_key_required", "create one in the Rotten Apple store (Developer > API keys)")
		return false
	}
	return true
}

func writeErrString(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func writeErrObj(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": code, "message": msg}})
}

func (f *fakeStore) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/devhub/pairings", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Name, Platform, Kind, PublicKey, Signature string }
		json.NewDecoder(r.Body).Decode(&body)
		pub, err := hex.DecodeString(body.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			writeErrObj(w, 400, "invalid", "bad public key")
			return
		}
		msg := []byte(hubProto + "\npair\n" + body.Platform + "\n" + body.Kind + "\n" + strings.ToLower(body.PublicKey) + "\n" + body.Name)
		sig, _ := base64.StdEncoding.DecodeString(body.Signature)
		if !ed25519.Verify(pub, msg, sig) {
			writeErrObj(w, 400, "invalid", "pair signature does not verify")
			return
		}
		f.pubByFP[Fingerprint(pub)] = pub
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": "K7QM-3XPA", "pollSecret": "sekret", "expiresMs": 600000,
			"approveUrl": "https://store.example/#/dev?tab=devices&pair=K7QM-3XPA",
		})
	})

	mux.HandleFunc("POST /v1/devhub/pairings/status", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Code, PollSecret string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Code != "K7QM-3XPA" || body.PollSecret != "sekret" {
			writeErrObj(w, 404, "not_found", "no such pairing")
			return
		}
		state := "pending"
		if f.approved {
			state = "approved"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"state": state, "device": "11", "team": f.team, "platform": "macos",
			"targets": []string{"ios", "linux", "macos", "web"},
		})
	})

	mux.HandleFunc("GET /v1/devhub/ca/chain", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"chain": []json.RawMessage{json.RawMessage(`{"kind":"ca"}`), json.RawMessage(`{"kind":"root"}`)}})
	})

	mux.HandleFunc("POST /v1/devhub/challenge", func(w http.ResponseWriter, r *http.Request) {
		if !f.needKey(w, r) {
			return
		}
		var body struct{ Purpose string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Purpose != "cert" && body.Purpose != "keycheck" {
			writeErrObj(w, 400, "invalid", "bad purpose")
			return
		}
		nonce := "nonce-" + body.Purpose
		f.nonces[nonce] = body.Purpose
		json.NewEncoder(w).Encode(map[string]interface{}{"nonce": nonce, "expiresMs": 300000, "team": f.team, "purpose": body.Purpose})
	})

	mux.HandleFunc("POST /v1/devhub/certs", func(w http.ResponseWriter, r *http.Request) {
		if !f.needKey(w, r) {
			return
		}
		var body struct{ Device, Nonce, Signature, PublicKey, KeySignature string }
		json.NewDecoder(r.Body).Decode(&body)
		if f.nonces[body.Nonce] != "cert" {
			writeErrObj(w, 400, "invalid", "unknown or wrong-purpose nonce")
			return
		}
		pub := f.pubByFP[body.Device]
		if pub == nil {
			writeErrObj(w, 403, "device_not_yours", "device not registered")
			return
		}
		msg := []byte(hubProto + "\ncert\n" + body.Nonce + "\n" + f.team + "\n" + body.Device + "\n" + body.PublicKey)
		sig, _ := base64.StdEncoding.DecodeString(body.Signature)
		if !ed25519.Verify(pub, msg, sig) {
			writeErrObj(w, 400, "invalid", "device signature does not verify")
			return
		}
		newPub, _ := hex.DecodeString(body.PublicKey)
		ksig, _ := base64.StdEncoding.DecodeString(body.KeySignature)
		if len(newPub) != ed25519.PublicKeySize || !ed25519.Verify(newPub, msg, ksig) {
			writeErrObj(w, 400, "invalid", "new key signature does not verify")
			return
		}
		if !f.certIssuer {
			writeErrObj(w, 501, "cert_issuer_not_configured", "the issuing CA key is not set")
			return
		}
		delete(f.nonces, body.Nonce)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"certificate": json.RawMessage(`{"alg":"ed25519"}`),
			"chain":       []json.RawMessage{json.RawMessage(`{"kind":"ca"}`)},
			"fingerprint": "sha256:leaf", "platforms": []string{"ios", "linux", "macos", "web"}, "expiresMs": 123,
		})
	})

	mux.HandleFunc("POST /v1/devhub/keys/check", func(w http.ResponseWriter, r *http.Request) {
		if !f.needKey(w, r) {
			return
		}
		var body struct{ Device, Nonce, Signature string }
		json.NewDecoder(r.Body).Decode(&body)
		if f.nonces[body.Nonce] != "keycheck" {
			writeErrObj(w, 400, "invalid", "unknown or wrong-purpose nonce")
			return
		}
		pub := f.pubByFP[body.Device]
		msg := []byte(hubProto + "\nkeycheck\n" + body.Nonce + "\n" + f.team + "\n" + body.Device)
		sig, _ := base64.StdEncoding.DecodeString(body.Signature)
		if pub == nil || !ed25519.Verify(pub, msg, sig) {
			writeErrObj(w, 403, "device_not_yours", "device proof failed")
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true, "key": json.RawMessage(`{"id":"k1"}`), "device": json.RawMessage(`{"id":"11"}`),
			"targets": []string{"ios", "macos"}, "context": json.RawMessage(`{"team":7}`),
		})
	})

	mux.HandleFunc("GET /v1/devhub/context", func(w http.ResponseWriter, r *http.Request) {
		if !f.needKey(w, r) {
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"team": 7, "teamName": "Red-XAI", "teamKind": "team", "role": "developer", "level": 1, "mega": true,
			"sdks": []map[string]interface{}{
				{"id": "redx", "name": "RedX", "kind": "inapp", "level": 1, "unlocked": true},
				{"id": "ads", "name": "Ads", "kind": "inapp", "level": 4, "unlocked": false},
			},
			"apps": []string{"com.redxai.redx"},
		})
	})

	mux.HandleFunc("GET /v1/devhub/apps/{appId}/sdks", func(w http.ResponseWriter, r *http.Request) {
		if !f.needKey(w, r) {
			return
		}
		if f.sdkFailCode != "" {
			writeErrString(w, 422, f.sdkFailCode, "sdk problem")
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"selected": []string{"redx", "analytics"},
			"services": []string{"redx", "analytics"},
			"manifest": map[string]interface{}{"sdks": []string{"redx", "analytics"}},
			"sdks": []map[string]interface{}{
				{"id": "redx", "unlocked": true}, {"id": "analytics", "unlocked": true},
			},
			"level": 1,
		})
	})

	return mux
}

func newTestClient(t *testing.T, srv *httptest.Server, dev DeviceKey, key string) *Client {
	return &Client{BaseURL: srv.URL, AllowLoopbackHTTP: true, HTTP: srv.Client(), APIKey: key, Device: dev, Platform: PlatformMac}
}

func genEd(t *testing.T) EdKey {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return EdKey{Priv: priv}
}

func TestPairingAndPoll(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dev := genEd(t)
	c := newTestClient(t, srv, dev, "ra_sk_live_x")

	p, err := c.StartPairing("Josh's MacBook")
	if err != nil || p.Code != "K7QM-3XPA" || p.PollSecret == "" || p.ApproveURL == "" {
		t.Fatalf("pairing: %+v %v", p, err)
	}
	st, err := c.PollPairing(context.Background(), p.Code, p.PollSecret)
	if err != nil || st.State != "approved" || st.Team != "7" || len(st.Targets) != 4 {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestPairingSignatureIsRequired(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	// a client whose device key signs with the wrong key: forge by signing a different message.
	dev := genEd(t)
	c := newTestClient(t, srv, badSigner{dev}, "k")
	if _, err := c.StartPairing("x"); err == nil {
		t.Fatal("a bad pair signature was accepted")
	}
}

type badSigner struct{ EdKey }

func (b badSigner) Sign(msg []byte) ([]byte, error) { return b.EdKey.Sign([]byte("not the message")) }

func TestBuildKeyRequired(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := newTestClient(t, srv, genEd(t), "") // no API key
	_, err := c.Context()
	if !IsBuildKeyRequired(err) {
		t.Fatalf("want build_key_required, got %v", err)
	}
	// the challenge route is also key-gated
	if _, err := c.CheckKey(context.Background()); !IsBuildKeyRequired(err) {
		t.Fatalf("checkKey want build_key_required, got %v", err)
	}
}

func TestIssueCertVerifiesBothSignatures(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dev := genEd(t)
	c := newTestClient(t, srv, dev, "ra_sk_live_x")
	// register the device so the server knows its public key
	if _, err := c.StartPairing("mac"); err != nil {
		t.Fatal(err)
	}
	newKey := genEd(t)
	cr, err := c.IssueCert(context.Background(), newKey)
	if err != nil || cr.Fingerprint == "" || len(cr.Platforms) != 4 {
		t.Fatalf("issue cert: %+v %v", cr, err)
	}
}

func TestCertIssuerNotConfigured(t *testing.T) {
	f := newFakeStore(t)
	f.certIssuer = false
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dev := genEd(t)
	c := newTestClient(t, srv, dev, "ra_sk_live_x")
	c.StartPairing("mac")
	_, err := c.IssueCert(context.Background(), genEd(t))
	if !IsCertIssuerNotConfigured(err) {
		t.Fatalf("want cert_issuer_not_configured, got %v", err)
	}
}

func TestCheckKeyProof(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dev := genEd(t)
	c := newTestClient(t, srv, dev, "ra_sk_live_x")
	c.StartPairing("mac")
	kc, err := c.CheckKey(context.Background())
	if err != nil || !kc.OK || len(kc.Targets) == 0 {
		t.Fatalf("check key: %+v %v", kc, err)
	}
}

func TestContextMapping(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := newTestClient(t, srv, genEd(t), "ra_sk_live_x")
	bc, err := c.Context()
	if err != nil {
		t.Fatal(err)
	}
	if bc.TeamID != "7" || bc.Individual || bc.Role != "developer" || bc.BuildKey != "ra_sk_live_x" {
		t.Fatalf("context: %+v", bc)
	}
	if !has(bc.SDKs.Unlocked, "redx") || has(bc.SDKs.Unlocked, "ads") {
		t.Fatalf("unlocked sdks: %+v", bc.SDKs)
	}
}

func TestAppSDKsAndFailures(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := newTestClient(t, srv, genEd(t), "ra_sk_live_x")
	a, err := c.AppSDKs(context.Background(), "com.redxai.redx")
	if err != nil || len(a.Manifest.SDKs) != 2 {
		t.Fatalf("appSDKs: %+v %v", a, err)
	}
	sel := a.SelectionFor([]string{"redx"})
	if !has(sel.Selected, "analytics") || !has(sel.Unlocked, "analytics") {
		t.Fatalf("selection: %+v", sel)
	}
	for _, code := range []string{"sdk_locked", "sdk_not_selected", "sdk_manifest_missing"} {
		f.sdkFailCode = code
		_, err := c.AppSDKs(context.Background(), "com.redxai.redx")
		switch code {
		case "sdk_locked":
			if !IsSDKLocked(err) {
				t.Fatalf("%s: %v", code, err)
			}
		case "sdk_not_selected":
			if !IsSDKNotSelected(err) {
				t.Fatalf("%s: %v", code, err)
			}
		case "sdk_manifest_missing":
			if !IsSDKManifestMissing(err) {
				t.Fatalf("%s: %v", code, err)
			}
		}
	}
}

func TestWrongPlatformParse(t *testing.T) {
	// wrong_platform surfaces from the upload path; here we assert the client parses the 422 code either shape.
	if !IsWrongPlatform(parseAPIError(422, []byte(`{"error":"wrong_platform","message":"sign it on a Windows PC"}`))) {
		t.Fatal("string shape")
	}
	if !IsWrongPlatform(parseAPIError(422, []byte(`{"error":{"code":"wrong_platform","message":"x"}}`))) {
		t.Fatal("object shape")
	}
}

func TestCAChain(t *testing.T) {
	f := newFakeStore(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := newTestClient(t, srv, genEd(t), "")
	chain, err := c.CAChain(context.Background())
	if err != nil || len(chain) != 2 {
		t.Fatalf("ca chain: %v %v", chain, err)
	}
}

func TestHTTPDeviceServiceFlow(t *testing.T) {
	f := newFakeStore(t)
	f.approved = false
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dev := genEd(t)
	c := newTestClient(t, srv, dev, "ra_sk_live_x")
	cache := &LocalDeviceService{Path: t.TempDir() + "/device.json"}
	svc := &HTTPDeviceService{Client: c, Cache: cache, Name: "mac"}

	d, err := svc.StartRegistration(PlatformMac, dev.Public())
	if err != nil || d.PairingCode == "" {
		t.Fatalf("start: %+v %v", d, err)
	}
	// still pending
	if _, err := svc.Approve(d.ID, "", false); err == nil {
		t.Fatal("pending approve should error")
	}
	if _, err := svc.Current(); err != ErrNoDevice {
		t.Fatal("pending device is current")
	}
	// dashboard approves
	f.approved = true
	cur, err := svc.Approve(d.ID, "", false)
	if err != nil || !cur.Approved || cur.TeamID != "7" || len(cur.Targets) == 0 {
		t.Fatalf("approve: %+v %v", cur, err)
	}
	got, err := svc.Current()
	if err != nil || !got.Approved {
		t.Fatalf("current: %+v %v", got, err)
	}
}

func TestLauncherHeaderSent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(LauncherHeader)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"chain":[],"issuing":false,"production":true}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, AllowLoopbackHTTP: true, HTTP: srv.Client()}
	if _, err := c.CAChainInfo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got != LauncherVersion {
		t.Fatalf("X-RA-Launcher %q, want %q", got, LauncherVersion)
	}
	if compareHub(got, "0.2.0") < 0 {
		t.Fatalf("%q older than HubMinLauncher 0.2.0", got)
	}
}

// compareHub is a tiny dotted-int compare for the test (same idea as ra-core validVersion).
func compareHub(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &ai)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bi)
		}
		if ai != bi {
			return ai - bi
		}
	}
	return 0
}
