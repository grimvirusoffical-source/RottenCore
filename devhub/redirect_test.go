package devhub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// QA D3: a hub that answers 307/302 must not make the client re-send X-RedX-Accounts-Key (or the build key)
// anywhere, neither to a second host nor to another path on the same host.
func TestDevhubNeverFollowsRedirects(t *testing.T) {
	const akey = "ra_sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
	var otherHits, sameHits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		if r.Header.Get(AccountsKeyHeader) != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("second host received a secret header on %s", r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer other.Close()
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1) // a different host name

	for _, tc := range []struct {
		name   string
		status int
		cross  bool
	}{{"307 cross-host", 307, true}, {"302 cross-host", 302, true}, {"301 cross-host", 301, true}, {"308 cross-host", 308, true},
		{"307 same-host", 307, false}, {"302 same-host", 302, false}} {
		t.Run(tc.name, func(t *testing.T) {
			atomic.StoreInt32(&otherHits, 0)
			atomic.StoreInt32(&sameHits, 0)
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/moved") {
					atomic.AddInt32(&sameHits, 1)
					w.Write([]byte(`{}`))
					return
				}
				target := "/moved" + r.URL.Path + "?sig=SECRETQUERY"
				if tc.cross {
					target = otherURL + r.URL.Path + "?sig=SECRETQUERY"
				}
				http.Redirect(w, r, target, tc.status)
			}))
			defer hub.Close()
			c := &Client{BaseURL: hub.URL, AllowLoopbackHTTP: true, APIKey: "ra_sk_live_build", AccountsKey: []byte(akey)}
			calls := map[string]func() error{
				"account-status": func() error { _, err := c.AccountStatus(context.Background()); return err },
				"pairings": func() error {
					return c.do(context.Background(), "POST", "/v1/devhub/pairings", map[string]string{}, false, nil)
				},
				"challenge": func() error {
					return c.do(context.Background(), "POST", "/v1/devhub/challenge", map[string]string{}, true, nil)
				},
				"certs": func() error {
					return c.do(context.Background(), "POST", "/v1/devhub/certs", map[string]string{}, true, nil)
				},
				"context": func() error { _, err := c.Context(); return err },
			}
			for name, call := range calls {
				err := call()
				var re *core.RedirectError
				if !errors.As(err, &re) || re.Status != tc.status {
					t.Fatalf("%s: want a hard RedirectError %d, got %v", name, tc.status, err)
				}
				msg := err.Error()
				if strings.Contains(msg, "SECRETQUERY") || strings.Contains(msg, akey) || strings.Contains(msg, "/v1/") {
					t.Fatalf("%s: error must name only status and host: %s", name, msg)
				}
				wantHost := strings.TrimPrefix(hub.URL, "http://")
				if tc.cross {
					wantHost = strings.TrimPrefix(otherURL, "http://")
				}
				if re.Host != wantHost {
					t.Fatalf("%s: host %q, want %q", name, re.Host, wantHost)
				}
			}
			if n := atomic.LoadInt32(&otherHits); n != 0 {
				t.Fatalf("second host received %d requests", n)
			}
			if n := atomic.LoadInt32(&sameHits); n != 0 {
				t.Fatalf("same-host redirect target received %d requests", n)
			}
		})
	}
	// a caller-supplied http.Client with a permissive CheckRedirect is overridden too
	hub := httptest.NewServer(http.RedirectHandler(otherURL+"/x", 307))
	defer hub.Close()
	c := &Client{BaseURL: hub.URL, AllowLoopbackHTTP: true, HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}, AccountsKey: []byte(akey)}
	if _, err := c.AccountStatus(context.Background()); err == nil || atomic.LoadInt32(&otherHits) != 0 {
		t.Fatalf("custom client followed the redirect: %v", err)
	}
}

func TestDevhubRefusesNonHTTPSBase(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	for _, tc := range []struct {
		base     string
		loopback bool
	}{
		{srv.URL, false}, // loopback http without the test-only switch
		{"http://api.rottenapplestore.org", false},
		{"http://api.rottenapplestore.org", true}, // the switch is loopback-only
		{"http://10.0.0.5:8080", true},
		{"ftp://api.rottenapplestore.org", true},
		{"api.rottenapplestore.org", true},
		{"https://user:pw@api.rottenapplestore.org", false},
	} {
		c := &Client{BaseURL: tc.base, AllowLoopbackHTTP: tc.loopback, AccountsKey: []byte("ra_sk_live_x")}
		if _, err := c.AccountStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("%s (loopback=%v): want an https refusal, got %v", tc.base, tc.loopback, err)
		}
	}
	if hits != 0 {
		t.Fatalf("refused base URLs still reached the server (%d)", hits)
	}
}
