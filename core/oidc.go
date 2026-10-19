package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Red-XAI Accounts v1 is an OIDC provider (red-xai-accounts docs/API.md, contract ce61961):
// discovery at /.well-known/openid-configuration, authorization code + PKCE S256 (required), tokens at
// /oauth2/token, userinfo with profile claims preferred_username, age_band, adult_verified. RottenCore is a
// public client (no secret). The issuer and client id are configurable; neither is live yet, so the app
// shows sign-in as "coming soon" until accountsIssuer is set and the "rottencore" client is registered.

// Discovery is the part of the OIDC discovery document RottenCore uses.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint,omitempty"`
	JWKSURI               string   `json:"jwks_uri"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported,omitempty"`
}

// OIDCAccounts implements the Accounts hook against Red-XAI Accounts.
type OIDCAccounts struct {
	Issuer   string
	ClientID string // default "rottencore"
	Net      *Net
	disc     *Discovery
	session  *Session
}

func (o *OIDCAccounts) clientID() string {
	if o.ClientID == "" {
		return "rottencore"
	}
	return o.ClientID
}

// Discover fetches and checks the discovery document (issuer must match exactly; endpoints on the issuer's origin).
func (o *OIDCAccounts) Discover(ctx context.Context) (*Discovery, error) {
	if o.Issuer == "" {
		return nil, ErrAccountsComingSoon
	}
	if !ValidOrigin(o.Issuer, o.Net.AllowLoopbackHTTP) {
		return nil, fmt.Errorf("accounts issuer %q is not an https origin", o.Issuer)
	}
	var d Discovery
	if err := o.Net.GetJSON(ctx, strings.TrimRight(o.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(o.Issuer, "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match %q", d.Issuer, o.Issuer)
	}
	iss, _ := url.Parse(o.Issuer)
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.UserinfoEndpoint} {
		u, err := url.Parse(e)
		if err != nil || u.Host != iss.Host || u.Scheme != iss.Scheme {
			return nil, fmt.Errorf("discovery endpoint %q is not on the issuer", e)
		}
	}
	o.disc = &d
	return &d, nil
}

// PKCE is one authorization attempt's secrets.
type PKCE struct {
	Verifier, Challenge, State, Nonce string
}

func rnd() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewPKCE makes a verifier (S256 challenge), state and nonce.
func NewPKCE() PKCE {
	v := rnd()
	s := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(s[:]), State: rnd(), Nonce: rnd()}
}

// AuthorizeURL is where the browser goes. redirect is a loopback URL (http://127.0.0.1:<port>/callback).
func (o *OIDCAccounts) AuthorizeURL(p PKCE, redirect string) (string, error) {
	if o.disc == nil {
		return "", errors.New("discover first")
	}
	q := url.Values{"response_type": {"code"}, "client_id": {o.clientID()}, "redirect_uri": {redirect}, "scope": {"openid profile email"},
		"state": {p.State}, "nonce": {p.Nonce}, "code_challenge": {p.Challenge}, "code_challenge_method": {"S256"}}
	return o.disc.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Tokens is the token endpoint's answer.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// Exchange trades the code for tokens. The caller has already checked the returned state.
func (o *OIDCAccounts) Exchange(ctx context.Context, p PKCE, code, redirect string) (*Tokens, error) {
	if o.disc == nil {
		return nil, errors.New("discover first")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {o.clientID()}, "code_verifier": {p.Verifier}}
	req, err := http.NewRequestWithContext(ctx, "POST", o.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := NoRedirects(o.Net.client()).Do(req) // the code + verifier never follow a redirect
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := RefuseRedirect(resp); err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var t Tokens
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" || !strings.EqualFold(t.TokenType, "bearer") {
		return nil, errors.New("token endpoint sent no bearer access token")
	}
	return &t, nil
}

// SignIn: the browser round trip (loopback listener) is not wired in v0.1.0; Red-XAI Accounts is not live
// and RottenCore's client is not registered. The pieces above are tested against a fake provider.
func (o *OIDCAccounts) SignIn(ctx context.Context) (*Session, error) {
	if _, err := o.Discover(ctx); err != nil {
		return nil, err
	}
	return nil, ErrAccountsComingSoon
}

func (o *OIDCAccounts) SignOut(context.Context) error { o.session = nil; return nil }
func (o *OIDCAccounts) Current() *Session             { return o.session }
