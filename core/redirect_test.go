package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// QA D3 for the other clients that carry credentials: HostClient (host key + confirm headers), Net with
// a GitHub token, and the OIDC token exchange never follow a redirect.
func TestSecretClientsNeverFollowRedirects(t *testing.T) {
	var otherHits int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-RedX-Confirm") != "" {
			t.Error("second host received a secret header")
		}
	}))
	defer other.Close()
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	for _, status := range []int{307, 302} {
		for _, same := range []bool{false, true} {
			var sameHits int32
			hub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/moved") {
					atomic.AddInt32(&sameHits, 1)
					return
				}
				to := otherURL + "/moved?sig=Q"
				if same {
					to = "/moved?sig=Q"
				}
				http.Redirect(w, r, to, status)
			}))
			n := &Net{HTTP: hub.Client(), GitHubAPI: hub.URL, GitHubToken: "ghp_secret"}
			hc := &HostClient{Base: hub.URL, Token: "host_secret", Net: n}
			checks := map[string]error{}
			_, _, checks["host"] = hc.do(context.Background(), "POST", "/v1/apps", nil, map[string]string{}, "op-1", "tok", nil)
			checks["net+token"] = n.GetJSON(context.Background(), hub.URL+"/repos/x/releases", &struct{}{})
			for name, err := range checks {
				var re *RedirectError
				if !errors.As(err, &re) || re.Status != status || strings.Contains(err.Error(), "sig=Q") {
					t.Errorf("%d same=%v %s: want RedirectError naming status+host, got %v", status, same, name, err)
				}
			}
			if atomic.LoadInt32(&otherHits) != 0 || atomic.LoadInt32(&sameHits) != 0 {
				t.Fatalf("%d same=%v: a redirect was followed (other=%d same=%d)", status, same, otherHits, sameHits)
			}
			hub.Close()
		}
	}
}

func TestNoRedirectsKeepsTimeoutAndRefusesAny3xx(t *testing.T) {
	c := NoRedirects(&http.Client{Timeout: 7})
	if c.Timeout != 7 || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("NoRedirects must keep the timeout and stop at the first 3xx")
	}
	for _, s := range []int{300, 301, 302, 303, 304, 307, 308, 399} {
		if RefuseRedirect(&http.Response{StatusCode: s, Header: http.Header{}}) == nil {
			t.Errorf("%d not refused", s)
		}
	}
	for _, s := range []int{200, 204, 400, 403, 500} {
		if RefuseRedirect(&http.Response{StatusCode: s}) != nil {
			t.Errorf("%d refused", s)
		}
	}
}
