package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// devUpdateHost models the RedX host update API at PR #10 head 76c380e: host-admin auth on every read
// except GET /v1/updates/keys, the two-step confirm token, 409 sequence_regression on downgrades, owner-only
// publish of hosted apps with exact allowlisted asset URLs, 404 on an extra path segment, per-app rollback,
// and health that can be unknown (null rates).
type devUpdateHost struct {
	mu         sync.Mutex
	planned    map[string]string // "apiKey|op|app" -> version (single-use plan record)
	installed  map[string]int64  // app -> installed sequence
	rolledBack map[string]bool   // app -> did a rollback touch it
	ownerTok   string
	adminTok   string
	health     *RolloutHealth
}

func newDevHost() *devUpdateHost {
	return &devUpdateHost{planned: map[string]string{}, installed: map[string]int64{"redx": 42, "notes": 7},
		rolledBack: map[string]bool{}, ownerTok: "owner", adminTok: "admin"}
}

func (d *devUpdateHost) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	// a public key endpoint (no auth)
	mux.HandleFunc("GET /v1/updates/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	admin := func(w http.ResponseWriter, r *http.Request) bool {
		a := r.Header.Get("Authorization")
		if a != "Bearer "+d.adminTok && a != "Bearer "+d.ownerTok {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"code":"forbidden","message":"host-admin key required"}}`))
			return false
		}
		return true
	}
	apiKey := func(r *http.Request) string { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") }
	// plan implements the fbc2098 two-step: a plan/dry_run records the API key that planned op|app; the real
	// call must send X-RedX-Confirm: <op> and X-RedX-Update-Confirm set to that SAME API key. Single use.
	plan := func(w http.ResponseWriter, r *http.Request, op, app, ver string) bool {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		key := apiKey(r)
		if body["plan"] == true || body["dry_run"] == true {
			d.mu.Lock()
			d.planned[key+"|"+op+"|"+app] = ver
			d.mu.Unlock()
			w.Write([]byte(`{"plan":true}`))
			return false
		}
		if r.Header.Get("X-RedX-Confirm") != op {
			w.WriteHeader(428)
			w.Write([]byte(`{"error":{"code":"confirm_required","message":"confirm"}}`))
			return false
		}
		if r.Header.Get("X-RedX-Update-Confirm") != key || key == "" {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"forbidden","message":"X-RedX-Update-Confirm must be the API key that planned this update"}}`))
			return false
		}
		d.mu.Lock()
		_, ok := d.planned[key+"|"+op+"|"+app]
		delete(d.planned, key+"|"+op+"|"+app)
		d.mu.Unlock()
		if !ok {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"forbidden","message":"no plan on record for this key (missing or reused)"}}`))
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/updates/apps/{app}", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		app := r.PathValue("app")
		seq := d.installed[app]
		// status NEVER offers a version older than installed
		w.Write([]byte(`{"app":"` + app + `","hosted":true,"installed":{"version":"x","sequence":` + itoa(seq) +
			`},"available":[{"version":"newer","channel":"stable","outcome":{"summary":"","risk":{"level":"low"}},"sources":["host"]}]}`))
	})
	mux.HandleFunc("POST /v1/updates/apps/{app}/apply", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		app := r.PathValue("app")
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		var req map[string]interface{}
		json.Unmarshal(raw, &req)
		// a downgrade (version "old") or failed min_from -> 409 sequence_regression, even on the plan step
		if req["version"] == "old" {
			w.WriteHeader(409)
			w.Write([]byte(`{"error":{"code":"sequence_regression","message":"refusing to install an older or equal version"}}`))
			return
		}
		if plan(w, r, OpUpdateApply, app, "newer") {
			w.WriteHeader(202)
			w.Write([]byte(`{"rollout_id":"ro_` + app + `","snapshot_id":"snap_` + app + `"}`))
		}
	})
	mux.HandleFunc("GET /v1/updates/rollouts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		d.mu.Lock()
		h := d.health
		d.mu.Unlock()
		hb := "null"
		if h != nil {
			b, _ := json.Marshal(h)
			hb = string(b)
		}
		w.Write([]byte(`{"rollout_id":"` + r.PathValue("id") + `","app":"redx","version":"newer","source":"host","strategy":"canary","state":"canary","progress":{"updated":1,"total":2,"percent":50},"health":` + hb + `}`))
	})
	mux.HandleFunc("POST /v1/updates/apps/{app}/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		app := r.PathValue("app")
		if plan(w, r, OpUpdateAppRollback, app, "") {
			d.mu.Lock()
			d.rolledBack[app] = true // only THIS app
			d.mu.Unlock()
			w.Write([]byte(`{"ok":true,"app":"` + app + `","snapshot_id":"snap_` + app + `"}`))
		}
	})
	mux.HandleFunc("POST /v1/updates/apps/{app}/publish", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+d.ownerTok {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"owner only"}`))
			return
		}
		if plan(w, r, OpUpdatePublish, r.PathValue("app"), "newer") {
			w.Write([]byte(`{"published":true}`))
		}
	})
	mux.HandleFunc("PUT /v1/updates/apps/{app}/source", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+d.ownerTok {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"owner only while accounts are enabled"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	return httptest.NewServer(mux)
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func hcode(err error) string {
	var e *HostError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestUpdateReadsNeedAdminKeyExceptKeys(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	anon := &HostClient{Base: srv.URL, AllowLoopbackHTTP: true}
	if _, err := anon.App(ctx, "redx"); !IsForbidden(err) {
		t.Fatalf("read without an admin key was allowed: %v", err)
	}
	// the key endpoint is public
	if _, err := anon.Keys(ctx); err != nil {
		t.Fatalf("GET /v1/updates/keys should be public: %v", err)
	}
	admin := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	if _, err := admin.App(ctx, "redx"); err != nil {
		t.Fatalf("admin read failed: %v", err)
	}
}

func TestTwoStepConfirmTokenSingleUse(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	// a normal two-step apply works
	ro, snap, err := h.Apply(ctx, "redx", ApplyRequest{Version: "newer", Source: "host", Strategy: "canary"})
	if err != nil || ro == "" || snap == "" {
		t.Fatalf("apply: %v", err)
	}
	// a real call with no confirm value (skipping the plan step) is 403
	var out struct {
		RolloutID string `json:"rollout_id"`
	}
	_, _, err = h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil,
		map[string]interface{}{"version": "newer"}, OpUpdateApply, "", &out)
	if !IsForbidden(err) {
		t.Fatalf("missing confirm was accepted: %v", err)
	}
	// confirming with the API key but without a prior plan for it is 403
	if _, _, err := h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil, map[string]interface{}{"version": "newer"}, OpUpdateApply, h.Token, &out); !IsForbidden(err) {
		t.Fatalf("confirm without a plan was accepted: %v", err)
	}
	// plan, then confirm with the SAME API key; the confirm value is that key; a reuse (no re-plan) is 403
	tok, err := h.planConfirm(ctx, "POST", "/v1/updates/apps/redx/apply", map[string]interface{}{"version": "newer"})
	if err != nil {
		t.Fatal(err)
	}
	if tok != h.Token {
		t.Fatalf("confirm value should be the API key, got %q", tok)
	}
	if _, _, err := h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil, map[string]interface{}{"version": "newer"}, OpUpdateApply, tok, &out); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if _, _, err := h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil, map[string]interface{}{"version": "newer"}, OpUpdateApply, tok, &out); !IsForbidden(err) {
		t.Fatalf("reused plan was accepted: %v", err)
	}
}

func TestSetSourceOwnerOnlyWhileAccountsOn(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	admin := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	if err := admin.SetSource(ctx, "redx", "both", true); !IsForbidden(err) {
		t.Fatalf("a non-owner key set the source: %v", err)
	}
	owner := &HostClient{Base: srv.URL, Token: "owner", AllowLoopbackHTTP: true}
	if err := owner.SetSource(ctx, "redx", "both", true); err != nil {
		t.Fatalf("owner set source failed: %v", err)
	}
}

func TestHealthUnknownUntil20Samples(t *testing.T) {
	zero, one := 0.0, 1.0
	few := &RolloutHealth{SuccessRate: &one, ErrorRate: &zero, CrashRate: &zero, Samples: 19}
	if few.Known() {
		t.Fatal("health known with only 19 samples")
	}
	enough := &RolloutHealth{SuccessRate: &one, ErrorRate: &zero, CrashRate: &zero, Samples: 20}
	if !enough.Known() {
		t.Fatal("health should be known at 20 samples")
	}
	r := &HostRollout{State: "canary", Health: few}
	if !r.AwaitingHealthData() || r.AutoPromoteEligible() {
		t.Fatal("under 20 samples must await health and not auto-promote")
	}
}

func TestPrereleaseVersionsSortBySemver(t *testing.T) {
	app := &HostApp{
		App: "redx", Hosted: true, Installed: &HostVerRef{Version: "1.0.0"},
		Available: []HostAvailable{
			{Version: "1.0.0"},
			{Version: "2.0.0-rc.2"},
			{Version: "2.0.0-rc.10"},
			{Version: "2.0.0"},
			{Version: "2.0.0-alpha"},
		},
	}
	got := app.OfferableVersions()
	want := []string{"2.0.0", "2.0.0-rc.10", "2.0.0-rc.2", "2.0.0-alpha"}
	if len(got) != len(want) {
		t.Fatalf("offerable count: %v", got)
	}
	for i := range want {
		if got[i].Version != want[i] {
			t.Fatalf("order %d: got %q want %q (%v)", i, got[i].Version, want[i], got)
		}
	}
	if n := app.Newest(); n == nil || n.Version != "2.0.0" {
		t.Fatalf("newest: %+v", n)
	}
}

func TestReleaseAssetURLsArePlainGithubNoQuery(t *testing.T) {
	okURL := "https://github.com/o/r/releases/download/v1/a.dmg"
	if err := ValidateReleaseAssetURL("o", "r", okURL); err != nil {
		t.Fatalf("plain URL rejected: %v", err)
	}
	for _, bad := range []string{
		okURL + "?token=abc",
		okURL + "#frag",
		"http://github.com/o/r/releases/download/v1/a.dmg",
		"https://codeload.github.com/o/r/releases/download/v1/a.dmg",
	} {
		if err := ValidateReleaseAssetURL("o", "r", bad); err == nil {
			t.Fatalf("accepted non-plain URL %q", bad)
		}
	}
}

func TestDowngradeIsSequenceRegression(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	_, _, err := h.Apply(ctx, "redx", ApplyRequest{Version: "old", Source: "host"})
	if !IsSequenceRegression(err) {
		t.Fatalf("downgrade not a 409 sequence_regression: %v", err)
	}
	// status never offers an older version than installed
	app, err := h.App(ctx, "redx")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range app.Available {
		if a.Version == "old" {
			t.Fatal("status offered an older version")
		}
	}
}

func TestPublishOwnerHostedAndAssetURLs(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	good := ReleaseAsset{Name: "a.dmg", URL: "https://github.com/grimvirusoffical-source/quick-launch/releases/download/v1.0.0/a.dmg"}
	// non-hosted app: refused client-side, nothing sent
	admin := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	if _, err := admin.Publish(ctx, "redx", false, "grimvirusoffical-source", "quick-launch", PublishRequest{Assets: []ReleaseAsset{good}}); hcode(err) != "not_hosted" {
		t.Fatalf("non-hosted publish allowed: %v", err)
	}
	// a non-allowlisted repo / non-exact URL is refused client-side
	bad := ReleaseAsset{Name: "a.dmg", URL: "https://evil.example/releases/download/v1/a.dmg"}
	if _, err := admin.Publish(ctx, "redx", true, "grimvirusoffical-source", "quick-launch", PublishRequest{Assets: []ReleaseAsset{bad}}); hcode(err) != "invalid" {
		t.Fatalf("bad asset URL allowed: %v", err)
	}
	wrongRepo := ReleaseAsset{URL: "https://github.com/someoneelse/repo/releases/download/v1/a.dmg"}
	if _, err := admin.Publish(ctx, "redx", true, "grimvirusoffical-source", "quick-launch", PublishRequest{Assets: []ReleaseAsset{wrongRepo}}); hcode(err) != "invalid" {
		t.Fatalf("wrong-repo asset URL allowed: %v", err)
	}
	// an admin (not owner) is refused by the host owner gate
	if _, err := admin.Publish(ctx, "redx", true, "grimvirusoffical-source", "quick-launch", PublishRequest{Version: "newer", Tag: "v1.0.0", Assets: []ReleaseAsset{good}}); !IsForbidden(err) {
		t.Fatalf("admin publish was not owner-gated: %v", err)
	}
	// the owner can publish a hosted app with exact allowlisted URLs
	owner := &HostClient{Base: srv.URL, Token: "owner", AllowLoopbackHTTP: true}
	if _, err := owner.Publish(ctx, "redx", true, "grimvirusoffical-source", "quick-launch", PublishRequest{Version: "newer", Tag: "v1.0.0", Assets: []ReleaseAsset{good}}); err != nil {
		t.Fatalf("owner publish failed: %v", err)
	}
}

func TestExtraPathSegmentIsNotFound(t *testing.T) {
	ctx := context.Background()
	srv := newDevHost().server(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	_, _, err := h.do(ctx, "GET", "/v1/updates/apps/redx/extra/segment", nil, nil, "", "", nil)
	if !IsNotFound(err) {
		t.Fatalf("extra path segment was not 404: %v", err)
	}
}

func TestHealthUnknownBlocksAutoPromote(t *testing.T) {
	ctx := context.Background()
	d := newDevHost()
	srv := d.server(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	// health null -> awaiting health data, never auto-promote
	r, err := h.Rollout(ctx, "ro_redx")
	if err != nil {
		t.Fatal(err)
	}
	if !r.AwaitingHealthData() || r.HealthSummary() != "awaiting health data" || r.AutoPromoteEligible() {
		t.Fatalf("unknown health: awaiting=%v summary=%q auto=%v", r.AwaitingHealthData(), r.HealthSummary(), r.AutoPromoteEligible())
	}
	// known, clean health on a canary -> eligible
	zero := 0.0
	one := 1.0
	d.mu.Lock()
	d.health = &RolloutHealth{SuccessRate: &one, ErrorRate: &zero, CrashRate: &zero, Samples: 500}
	d.mu.Unlock()
	r, _ = h.Rollout(ctx, "ro_redx")
	if r.AwaitingHealthData() || !r.AutoPromoteEligible() || r.HealthSummary() != "healthy" {
		t.Fatalf("healthy: %+v", r.Health)
	}
	// errors present -> degraded, not eligible
	bad := 0.2
	d.mu.Lock()
	d.health = &RolloutHealth{SuccessRate: &zero, ErrorRate: &bad, Samples: 500}
	d.mu.Unlock()
	r, _ = h.Rollout(ctx, "ro_redx")
	if r.AutoPromoteEligible() || r.HealthSummary() != "degraded" {
		t.Fatalf("degraded: %+v", r.Health)
	}
}

func TestAppRollbackRestoresOnlyThatApp(t *testing.T) {
	ctx := context.Background()
	d := newDevHost()
	srv := d.server(t)
	defer srv.Close()
	h := &HostClient{Base: srv.URL, Token: "admin", AllowLoopbackHTTP: true}
	if err := h.RestoreSnapshot(ctx, "redx", "snap_redx"); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.rolledBack["redx"] || d.rolledBack["notes"] {
		t.Fatalf("rollback touched the wrong apps: %+v", d.rolledBack)
	}
}
