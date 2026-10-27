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
	resp, err := o.Net.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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

// UseToken keeps an access token in memory for this process. It is not written to disk.
func (o *OIDCAccounts) UseToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return ErrSignInRequired
	}
	if o.session == nil {
		o.session = &Session{}
	}
	o.session.Token = token
	return nil
}

// Profile reads userinfo and, when idVerified is absent there, GET {issuer}/v1/rxa-account.
func (o *OIDCAccounts) Profile(ctx context.Context) (*Profile, error) {
	if o.Net == nil || o.session == nil || strings.TrimSpace(o.session.Token) == "" {
		return nil, ErrSignInRequired
	}
	if o.disc == nil {
		if _, err := o.Discover(ctx); err != nil {
			return nil, err
		}
	}
	b, err := o.Net.GetBytesBearer(ctx, o.disc.UserinfoEndpoint, o.session.Token, 1<<20)
	if err != nil {
		return nil, errors.New("Accounts refused this session")
	}
	p, err := parseProfile(b)
	if err != nil {
		return nil, err
	}
	if !p.sawID && o.Issuer != "" {
		ab, err := o.Net.GetBytesBearer(ctx, strings.TrimRight(o.Issuer, "/")+"/v1/rxa-account", o.session.Token, 1<<20)
		if err == nil {
			if extra, eerr := parseProfile(ab); eerr == nil && extra.sawID {
				p.IDVerified = extra.IDVerified
				p.IDVerifiedMs = extra.IDVerifiedMs
				p.sawID = true
			}
		}
	}
	return p, nil
}

// LifetimeCert reads GET {issuer}/v1/rxa-lifetime-cert. A non-200 is a refusal with no body echoed.
func (o *OIDCAccounts) LifetimeCert(ctx context.Context) (*LifetimeCert, error) {
	if o.Net == nil || o.Issuer == "" || o.session == nil || strings.TrimSpace(o.session.Token) == "" {
		return nil, ErrSignInRequired
	}
	b, err := o.Net.GetBytesBearer(ctx, strings.TrimRight(o.Issuer, "/")+"/v1/rxa-lifetime-cert", o.session.Token, 1<<20)
	if err != nil {
		return nil, errors.New("Accounts refused the lifetime cert")
	}
	var cert LifetimeCert
	if err := json.Unmarshal(b, &cert); err != nil {
		return nil, errors.New("Accounts sent a lifetime cert RottenCore could not read")
	}
	if cert.Kind != CertKindLifetime {
		return nil, errors.New("Accounts did not return an rxa-lifetime-cert")
	}
	cert.PubKey = strings.ToLower(strings.TrimSpace(cert.PubKey))
	cert.PrivateEnc = strings.TrimSpace(cert.PrivateEnc)
	return &cert, nil
}

// CertKindLifetime is the Accounts kind RottenCore asks for. It matches sign.CertKind.
const CertKindLifetime = "rxa-lifetime-cert"

func parseProfile(b []byte) (*Profile, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, errors.New("Accounts sent a profile RottenCore could not read")
	}
	p := &Profile{
		Sub:               jsonString(raw, "sub"),
		Email:             jsonString(raw, "email"),
		PreferredUsername: jsonString(raw, "preferred_username"),
		AgeBand:           firstString(raw, "age_band", "ageBand"),
	}
	p.Verified = jsonBool(raw, "email_verified") || jsonBool(raw, "emailVerified") || jsonBool(raw, "verified")
	p.AdultVerified = jsonBool(raw, "adult_verified") || jsonBool(raw, "adultVerified")
	if _, ok := raw["idVerified"]; ok {
		p.IDVerified = jsonBool(raw, "idVerified")
		p.sawID = true
	} else if _, ok := raw["id_verified"]; ok {
		p.IDVerified = jsonBool(raw, "id_verified")
		p.sawID = true
	}
	p.IDVerifiedMs = firstInt(raw, "idVerifiedMs", "id_verified_ms")
	p.MFA = jsonBool(raw, "mfa") || jsonBool(raw, "two_factor") || jsonBool(raw, "twoFactor")
	p.AMR = jsonStrings(raw, "amr")
	if !p.MFA && secondFactor(p.AMR) {
		p.MFA = true
	}
	return p, nil
}

func jsonString(raw map[string]json.RawMessage, key string) string {
	b, ok := raw[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ""
	}
	return s
}

func firstString(raw map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := jsonString(raw, k); s != "" {
			return s
		}
	}
	return ""
}

func jsonBool(raw map[string]json.RawMessage, key string) bool {
	b, ok := raw[key]
	if !ok {
		return false
	}
	var v bool
	if err := json.Unmarshal(b, &v); err != nil {
		return false
	}
	return v
}

func firstInt(raw map[string]json.RawMessage, keys ...string) int64 {
	for _, k := range keys {
		b, ok := raw[k]
		if !ok {
			continue
		}
		var n int64
		if err := json.Unmarshal(b, &n); err == nil {
			return n
		}
	}
	return 0
}

func jsonStrings(raw map[string]json.RawMessage, key string) []string {
	b, ok := raw[key]
	if !ok {
		return nil
	}
	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil
	}
	return s
}

func secondFactor(amr []string) bool {
	for _, a := range amr {
		switch strings.ToLower(strings.TrimSpace(a)) {
		case "otp", "totp", "mfa", "hwk", "sms", "swk", "pop":
			return true
		}
	}
	return false
}
