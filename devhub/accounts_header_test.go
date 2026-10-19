package devhub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The Accounts key goes raw in X-RedX-Accounts-Key, only on the routes the contract (711171b) reads it:
// pairings, challenge, certs and account-status. Never on pairings/status (ignored there), context,
// uploads or anything else, never as a Bearer token, never in the URL.
func TestAccountsKeyHeaderOnlyOnContractRoutes(t *testing.T) {
	const key = "ra_sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get(AccountsKeyHeader)
		mu.Unlock()
		if strings.Contains(r.Header.Get("Authorization"), key) || strings.Contains(r.URL.String(), key) {
			t.Errorf("%s: Accounts key outside its header", r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, AllowLoopbackHTTP: true, APIKey: "build", AccountsKey: []byte(key)}
	ctx := context.Background()
	for _, p := range []string{"/v1/devhub/pairings", "/v1/devhub/pairings/status", "/v1/devhub/challenge", "/v1/devhub/certs", AccountStatusPath, "/v1/devhub/context", "/v1/devhub/apps/x/sdks", "/v1/devhub/ca/chain"} {
		_ = c.do(ctx, "POST", p, map[string]string{}, false, nil)
	}
	want := map[string]bool{"/v1/devhub/pairings": true, "/v1/devhub/challenge": true, "/v1/devhub/certs": true, AccountStatusPath: true}
	for p, v := range seen {
		if want[p] && v != key {
			t.Errorf("%s: header %q, want the raw key", p, v)
		}
		if !want[p] && v != "" {
			t.Errorf("%s: Accounts key sent where the contract does not read it", p)
		}
	}
	if len(seen) != 8 {
		t.Fatalf("saw %d routes", len(seen))
	}
}
