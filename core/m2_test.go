package core

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// p384PKI: P-384 root and intermediate (magnitude tiers), developer leaf in the given algorithm.
func p384PKI(t *testing.T, now time.Time, leafP384 bool) (Signer, []Cert, ChainPolicy) {
	t.Helper()
	root, _ := NewP384Signer()
	inter, _ := NewP384Signer()
	ic := Cert{Serial: "i", Kind: CertKindCA, Alg: AlgP384, PublicKey: inter.Public(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(), Test: true}
	if err := SignCertWith(&ic, root); err != nil {
		t.Fatal(err)
	}
	var dev Signer
	if leafP384 {
		dev, _ = NewP384Signer()
	} else {
		_, k, _ := ed25519.GenerateKey(nil)
		dev = Ed25519Signer{k}
	}
	dc := Cert{Serial: "d", Kind: CertKindDeveloper, Alg: dev.Alg(), Subject: CertSubject{Name: "Mega Dev", TeamID: "T-mega"}, PublicKey: dev.Public(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(), Test: true}
	if err := SignCertWith(&dc, inter); err != nil {
		t.Fatal(err)
	}
	return dev, []Cert{dc, ic}, ChainPolicy{Roots: []CARoot{{Name: "r", Alg: AlgP384, PublicKey: root.Public(), Test: true}}, Now: now}
}

func TestP384ChainsAndSignatures(t *testing.T) {
	now := time.Now()
	_, store, _ := ed25519.GenerateKey(nil)
	clean := ticket(t, store, now, StatusTicket{})
	for _, leafP384 := range []bool{true, false} {
		dev, chain, pol := p384PKI(t, now, leafP384)
		if chain[0].Version != 2 || chain[1].Version != 2 {
			t.Fatal("P-384-signed certificates must be v2")
		}
		d := FileSigDoc{AppID: "com.redx.app", Version: "1.0.0"}
		d.Artifact.Name, d.Artifact.Kind, d.Artifact.SHA256, d.Artifact.Bytes = "x.dmg", "dmg", sumA, 10
		sig, err := SignFileDocWith(dev, chain, d)
		if err != nil {
			t.Fatal(err)
		}
		if r := VerifyFileSignature(sig, sumA, 10, pol, clean); r.Status != SigValid || !r.Test {
			t.Fatalf("p384 leaf=%v: %+v", leafP384, r)
		}
		// algorithm confusion: claim the other algorithm
		bad := *sig
		if bad.Alg == AlgP384 {
			bad.Alg = AlgEd25519
		} else {
			bad.Alg = AlgP384
		}
		if r := VerifyFileSignature(&bad, sumA, 10, pol, clean); r.Status != SigInvalid {
			t.Fatal("algorithm confusion accepted")
		}
		// revoking the P-384 intermediate revokes the chain
		if r := VerifyFileSignature(sig, sumA, 10, pol, ticket(t, store, now, StatusTicket{RevokedCerts: []string{chain[1].Fingerprint()}})); r.Status != SigRevoked {
			t.Fatal("revoked P-384 intermediate accepted")
		}
		// tampered certificate
		tc := append([]Cert{}, chain...)
		tc[0].Subject.TeamID = "T-evil"
		if _, err := VerifyCertChain(tc, pol); err == nil {
			t.Fatal("tampered P-384-signed cert accepted")
		}
	}
	if validPublicKey(AlgP384, make([]byte, 97)) {
		t.Fatal("point not on the curve accepted")
	}
}

// signedDMG makes a dmg (fake runner) plus its .rasig from the given developer key and chain.
func signedDMG(t *testing.T, f *fakeRunner, dev Signer, chain []Cert, appID string, tamper bool) string {
	dir := t.TempDir()
	contents := filepath.Join(dir, "contents")
	makeApp(t, contents, "Notes", appID, "2.0.0", "")
	dmg := filepath.Join(dir, "Notes.dmg")
	b := []byte("signed dmg bytes " + dir)
	os.WriteFile(dmg, b, 0o644)
	f.dmgs[dmg] = contents
	d := FileSigDoc{AppID: appID, Version: "2.0.0"}
	d.Artifact.Name, d.Artifact.Kind, d.Artifact.SHA256, d.Artifact.Bytes = "Notes.dmg", "dmg", sumOf(b), int64(len(b))
	if tamper {
		d.Artifact.SHA256 = sumA
	}
	sig, err := SignFileDocWith(dev, chain, d)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(sig)
	os.WriteFile(dmg+SignatureSidecar, j, 0o644)
	return dmg
}

func TestInstallSignedByOurCertsAndQuarantine(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	p := newPKI(t, now)
	_, store, _ := ed25519.GenerateKey(nil)
	setup := func(t *testing.T, st StatusTicket) (*Core, *fakeRunner) {
		f := newFake()
		c := testCore(t, f, "", nil)
		c.Roots, c.Production, c.Now = p.pol.Roots, false, func() time.Time { return now }
		c.Rev = &RevocationCache{Path: filepath.Join(t.TempDir(), "st.json"), Pins: []ed25519.PublicKey{store.Public().(ed25519.PublicKey)}}
		s, _ := SignStatusTicket(store, StatusTicket{IssuedMs: now.UnixMilli(), ExpiresMs: now.Add(time.Hour).UnixMilli(), RevokedCerts: st.RevokedCerts, RevokedApps: st.RevokedApps})
		if _, err := c.Rev.Store(s); err != nil {
			t.Fatal(err)
		}
		return c, f
	}
	dev := Ed25519Signer{p.dev}

	// valid (test CA): trusted by its signature, installs with no warning; TEST chain -> quarantine kept, logged
	c, f := setup(t, StatusTicket{})
	in, err := c.Inspect(ctx, signedDMG(t, f, dev, p.chain, "com.rotten.notes", false), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if !in.Verdict.Trusted || in.Verdict.TrustedBy != TrustedByDeveloperTest || in.Verdict.Warning != "" || in.Signature.Signer.TeamID != "T-josh" {
		t.Fatalf("signed dmg: %+v %+v", in.Verdict, in.Signature)
	}
	e, err := c.Install(ctx, in, InstallOptions{})
	if err != nil || e.QuarantineRemoved || len(e.CertFPs) != 2 {
		t.Fatalf("install: %+v %v", e, err)
	}
	logb, _ := os.ReadFile(filepath.Join(c.State.Dir, QuarantineLogName))
	if !strings.Contains(string(logb), "skipped: signed under the TEST CA") {
		t.Fatalf("log: %s", logb)
	}

	// production-like (root not marked test, chain certs not test): quarantine removed and logged
	c, f = setup(t, StatusTicket{})
	prodRoot, prodInter, prodDev := ed25519.NewKeyFromSeed(make([]byte, 32)), p.inter, p.dev
	_ = prodInter
	ic := Cert{Serial: "pi", Kind: CertKindCA, PublicKey: p.inter.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()}
	SignCert(&ic, prodRoot)
	dc := Cert{Serial: "pd", Kind: CertKindDeveloper, Subject: CertSubject{Name: "Josh", TeamID: "T-josh"}, PublicKey: prodDev.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()}
	SignCert(&dc, p.inter)
	c.Roots, c.Production = []CARoot{{Name: "prod", PublicKey: prodRoot.Public().(ed25519.PublicKey)}}, true
	in, _ = c.Inspect(ctx, signedDMG(t, f, dev, []Cert{dc, ic}, "com.rotten.notes", false), nil)
	defer in.Close()
	if in.Verdict.TrustedBy != TrustedByDeveloper {
		t.Fatalf("%+v", in.Verdict)
	}
	e, err = c.Install(ctx, in, InstallOptions{})
	if err != nil || !e.QuarantineRemoved {
		t.Fatalf("quarantine not removed: %+v %v", e, err)
	}
	removed := false
	for _, call := range f.calls {
		if strings.HasPrefix(call, "xattr -dr com.apple.quarantine "+e.Paths[0]) {
			removed = true
		}
	}
	logb, _ = os.ReadFile(filepath.Join(c.State.Dir, QuarantineLogName))
	if !removed || !strings.Contains(string(logb), `"result":"removed"`) || !strings.Contains(string(logb), `"team":"T-josh"`) {
		t.Fatalf("calls %v log %s", f.calls, logb)
	}
	// later the store revokes the app: the installed list marks it
	s2, _ := SignStatusTicket(store, StatusTicket{IssuedMs: now.Add(time.Minute).UnixMilli(), ExpiresMs: now.Add(time.Hour).UnixMilli(), RevokedCerts: []string{dc.Fingerprint()}})
	c.Rev.Store(s2)
	c.revState = nil
	list, state, err := c.CheckInstalledRevocations(ctx)
	if err != nil || state != "fresh" || len(list) != 1 || !strings.Contains(list[0].Revoked, "revoked the developer certificate") {
		t.Fatalf("revocation mark: %+v %s %v", list, state, err)
	}

	// revoked: hard refusal, never installs, quarantine never touched
	c, f = setup(t, StatusTicket{RevokedApps: []string{"com.rotten.notes"}})
	in, _ = c.Inspect(ctx, signedDMG(t, f, dev, p.chain, "com.rotten.notes", false), nil)
	defer in.Close()
	if !in.Verdict.Refuse {
		t.Fatalf("revoked not refused: %+v", in.Verdict)
	}
	if _, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true}); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	// verified signature for other bytes: hard refusal
	c, f = setup(t, StatusTicket{})
	in, _ = c.Inspect(ctx, signedDMG(t, f, dev, p.chain, "com.rotten.notes", true), nil)
	defer in.Close()
	if !in.Verdict.Refuse {
		t.Fatalf("mismatch not refused: %+v", in.Verdict)
	}
	// unknown root: untrusted, warning, quarantine skipped after an accepted install
	c, f = setup(t, StatusTicket{})
	c.Roots = newPKI(t, now).pol.Roots
	in, _ = c.Inspect(ctx, signedDMG(t, f, dev, p.chain, "com.rotten.notes", false), nil)
	defer in.Close()
	if in.Verdict.Trusted || in.Verdict.Warning != UntrustedWarning {
		t.Fatalf("foreign root trusted: %+v", in.Verdict)
	}
	if e, err := c.Install(ctx, in, InstallOptions{AcceptUntrusted: true}); err != nil || e.QuarantineRemoved {
		t.Fatalf("%+v %v", e, err)
	}
}

// fakeHost is a minimal RedX host update API as built in PR #10.
func fakeHost(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var log []string
	mux := http.NewServeMux()
	need := func(w http.ResponseWriter, r *http.Request, op string) bool {
		mu.Lock()
		log = append(log, r.Method+" "+r.URL.Path+" confirm="+r.Header.Get("X-RedX-Confirm")+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		if op != "" && r.Header.Get("X-RedX-Confirm") != op {
			w.WriteHeader(428)
			w.Write([]byte(`{"error":{"code":"confirm_required","message":"send X-RedX-Confirm: ` + op + `"}}`))
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/updates/apps", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, "")
		w.Write([]byte(`{"apps":[{"app":"redx","hosted":true,"source_pref":"both","latest":{"host":{"version":"0.4.5","sequence":42}},"available":[{"version":"0.4.5","channel":"stable","outcome":{"tags":["+perf"],"summary":"s","risk":{"score":0.1,"level":"low","reasons":[]},"changelog_md":""},"sources":["github","host"]}]},{"app":"notes","hosted":false,"available":[]}]}`))
	})
	mux.HandleFunc("POST /v1/updates/apps/{app}/apply", func(w http.ResponseWriter, r *http.Request) {
		if need(w, r, OpUpdateApply) {
			w.WriteHeader(202)
			w.Write([]byte(`{"rollout_id":"ro_1","snapshot_id":"snap_1"}`))
		}
	})
	mux.HandleFunc("GET /v1/updates/rollouts/{id}", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, "")
		w.Write([]byte(`{"rollout_id":"ro_1","app":"redx","version":"0.4.5","source":"host","strategy":"direct","state":"done","snapshot_id":"snap_1","progress":{"updated":1,"total":1,"percent":100},"health":{"error_rate":0}}`))
	})
	mux.HandleFunc("POST /v1/updates/rollouts/{id}/promote", func(w http.ResponseWriter, r *http.Request) { need(w, r, OpUpdatePromote) })
	mux.HandleFunc("POST /v1/updates/rollouts/{id}/rollback", func(w http.ResponseWriter, r *http.Request) { need(w, r, OpUpdateRolloutRollback) })
	mux.HandleFunc("POST /v1/updates/apps/{app}/rollback", func(w http.ResponseWriter, r *http.Request) {
		if need(w, r, OpUpdateAppRollback) {
			w.Write([]byte(`{"ok":true,"snapshot_id":"snap_1","app":"redx"}`))
		}
	})
	mux.HandleFunc("POST /v1/updates/apps/{app}/publish", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, OpUpdatePublish)
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"owner only"}`)) // owner-gate shape
	})
	mux.HandleFunc("PUT /v1/updates/apps/{app}/source", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, "")
		w.WriteHeader(400)
		w.Write([]byte(`{"error":{"code":"invalid","message":"bad source"}}`))
	})
	mux.HandleFunc("GET /v1/updates/apps/{app}/snapshots", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, "")
		w.Write([]byte(`{"snapshots":[{"id":"snap_1","app":"redx","version":"0.4.4","created_at":"2026-10-19T18:00:00Z","size":10,"sha256":"` + sumA + `"}]}`))
	})
	mux.HandleFunc("GET /v1/updates/events", func(w http.ResponseWriter, r *http.Request) {
		need(w, r, "")
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(400)
			return
		}
		hj, _ := w.(http.Hijacker)
		conn, brw, _ := hj.Hijack()
		defer conn.Close()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		frame := func(op byte, p []byte) { brw.Write(append([]byte{0x80 | op, byte(len(p))}, p...)) }
		frame(0x9, []byte("hi")) // ping: the client must pong
		frame(0x1, []byte(`{"type":"rollout.state","app":"redx","version":"0.4.5","source":"host","rollout_id":"ro_1","state":"canary"}`))
		frame(0x1, []byte(`{"type":"rollback.done","app":"redx","version":"0.4.5","source":"host","rollout_id":"ro_1"}`))
		brw.Flush()
		// read the pong (masked)
		br := bufio.NewReader(brw)
		_, op, payload, err := readWSFrame(br)
		if err != nil || op != 0xA || string(payload) != "hi" {
			t.Errorf("pong: op %x %q %v", op, payload, err)
		}
		frame(0x8, nil)
		brw.Flush()
	})
	return httptest.NewServer(mux), &log
}

func TestHostClientMatchesPR10(t *testing.T) {
	ctx := context.Background()
	srv, log := fakeHost(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "tok", AllowLoopbackHTTP: true}
	apps, err := h.Apps(ctx)
	if err != nil || len(apps) != 2 || !apps[0].Hosted || len(apps[1].SourceOptions()) != 1 || len(apps[0].SourceOptions()) != 3 {
		t.Fatalf("apps %+v %v", apps, err)
	}
	ro, snap, err := h.Apply(ctx, "redx", ApplyRequest{Version: "0.4.5", Source: "host", Strategy: "canary"})
	if err != nil || ro != "ro_1" || snap != "snap_1" {
		t.Fatal(err)
	}
	r, err := h.Rollout(ctx, ro)
	if err != nil || r.Strategy != "direct" || !r.Terminal() || r.Progress.Percent != 100 || r.App != "redx" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, f := range []func() error{
		func() error { return h.Promote(ctx, ro) },
		func() error { return h.RollbackRollout(ctx, ro, "health") },
		func() error { return h.RestoreSnapshot(ctx, "redx", "snap_1") },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = h.Publish(ctx, "redx", map[string]string{"version": "0.4.5"})
	var he *HostError
	if !errors.As(err, &he) || !he.OwnerGate || he.Status != 403 || he.Message != "owner only" {
		t.Fatalf("owner gate: %#v", err)
	}
	if err := h.SetSource(ctx, "redx", "github", true); !errors.As(err, &he) || he.Code != "invalid" || he.Status != 400 {
		t.Fatalf("invalid: %#v", err)
	}
	if err := h.SetSource(ctx, "notes", "host", false); code(err) != "not_hosted" {
		t.Fatal("host source allowed for a non-hosted app")
	}
	snaps, err := h.Snapshots(ctx, "redx")
	if err != nil || len(snaps) != 1 || snaps[0].ID != "snap_1" {
		t.Fatal(err)
	}
	var evs []HostEvent
	if err := h.Events(ctx, func(e HostEvent) { evs = append(evs, e) }); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Type != "rollout.state" || evs[1].Type != "rollback.done" {
		t.Fatalf("events %+v", evs)
	}
	confirms := map[string]string{"/apply": OpUpdateApply, "/promote": OpUpdatePromote, "rollouts/ro_1/rollback": OpUpdateRolloutRollback, "apps/redx/rollback": OpUpdateAppRollback, "/publish": OpUpdatePublish}
	for suffix, op := range confirms {
		found := false
		for _, l := range *log {
			if strings.Contains(l, suffix+" ") && strings.Contains(l, "confirm="+op+" ") && strings.Contains(l, "auth=Bearer tok") {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s did not send X-RedX-Confirm: %s (%v)", suffix, op, *log)
		}
	}
	if e := ParseHostError(404, []byte(`{"error":"database not found"}`)); !e.OwnerGate || e.Code != "not_found" {
		t.Fatalf("%+v", e)
	}
	if e := ParseHostError(401, []byte(`{"error":{"code":"forbidden","message":"unauthorized"}}`)); e.Code != "forbidden" || e.OwnerGate {
		t.Fatalf("%+v", e)
	}
}
