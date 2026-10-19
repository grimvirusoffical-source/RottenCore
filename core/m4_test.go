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
	tokens     map[string]string // token -> "op|app|version"
	installed  map[string]int64  // app -> installed sequence
	rolledBack map[string]bool   // app -> did a rollback touch it
	ownerTok   string
	adminTok   string
	health     *RolloutHealth
}

func newDevHost() *devUpdateHost {
	return &devUpdateHost{tokens: map[string]string{}, installed: map[string]int64{"redx": 42, "notes": 7},
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
	plan := func(w http.ResponseWriter, r *http.Request, op, app, ver string) bool {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		if body["plan"] == true || body["dry_run"] == true {
			tok := "ct_" + op + "_" + app
			d.mu.Lock()
			d.tokens[tok] = op + "|" + app + "|" + ver
			d.mu.Unlock()
			w.Header().Set("X-RedX-Update-Confirm", tok)
			w.Write([]byte(`{"plan":true}`))
			return false
		}
		if r.Header.Get("X-RedX-Confirm") != op {
			w.WriteHeader(428)
			w.Write([]byte(`{"error":{"code":"confirm_required","message":"confirm"}}`))
			return false
		}
		tok := r.Header.Get("X-RedX-Update-Confirm")
		d.mu.Lock()
		want, ok := d.tokens[tok]
		delete(d.tokens, tok)
		d.mu.Unlock()
		if !ok || !strings.HasPrefix(want, op+"|"+app+"|") {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"forbidden","message":"missing or reused update-confirm token"}}`))
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
	// a real call with no token (skipping the plan step) is 403
	var out struct {
		RolloutID string `json:"rollout_id"`
	}
	_, _, err = h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil,
		map[string]interface{}{"version": "newer"}, OpUpdateApply, "", &out)
	if !IsForbidden(err) {
		t.Fatalf("missing token was accepted: %v", err)
	}
	// a reused token is 403
	tok, err := h.planToken(ctx, "POST", "/v1/updates/apps/redx/apply", map[string]interface{}{"version": "newer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil, map[string]interface{}{"version": "newer"}, OpUpdateApply, tok, &out); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if _, _, err := h.do(ctx, "POST", "/v1/updates/apps/redx/apply", nil, map[string]interface{}{"version": "newer"}, OpUpdateApply, tok, &out); !IsForbidden(err) {
		t.Fatalf("reused token was accepted: %v", err)
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
