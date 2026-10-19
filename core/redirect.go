package core

import (
	"fmt"
	"net/http"
)

// QA D3: net/http drops Authorization and Cookie on a cross-host redirect but forwards custom headers
// (X-RedX-Accounts-Key, X-RedX-Confirm, …). Every client that sends a key or credential therefore never
// follows a redirect: the 3xx comes back as the response and RefuseRedirect turns it into a hard error.

// NoRedirects returns a copy of base (nil = a default client) that never follows a redirect.
func NoRedirects(base *http.Client) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// RedirectError is a 3xx answer to a request that carried a secret. It names only the status and the
// target host (never the full Location, which may carry a signed query).
type RedirectError struct {
	Status int
	Host   string
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("refusing HTTP %d redirect to host %s: requests that carry keys never follow redirects (check the configured base URL)", e.Status, e.Host)
}

// RefuseRedirect returns a *RedirectError for any 3xx response, nil otherwise.
func RefuseRedirect(resp *http.Response) error {
	if resp == nil || resp.StatusCode < 300 || resp.StatusCode > 399 {
		return nil
	}
	host := "(no Location)"
	if u, err := resp.Location(); err == nil && u.Host != "" {
		host = u.Host
	}
	return &RedirectError{Status: resp.StatusCode, Host: host}
}
