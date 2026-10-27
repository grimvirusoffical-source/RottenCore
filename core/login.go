package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Quick Login is the public Red-XAI device flow documented in
// grimvirusoffical-source/red-xai-quick-login-docs (protocol redx-site-session-v1).
// The docs say the public authorization endpoint is not deployed yet.
// RottenCore is a public client: client id "rottencore", PKCE, no API key.
//
// Accounts endpoints used after a token exists:
//   - GET {origin}/redxai-connect/userinfo
//   - GET {origin}/v1/rxa-account (idVerified / idVerifiedMs), via the OIDC profile path
//
// There is no published endpoint to register a developer public key.
// Those keys stay in the local developer-certs.json registry.

const (
	QuickLoginProtocol = "redx-site-session-v1"
	DefaultQuickOrigin = "https://red-xai.com"
)

// QuickOrigin is the Quick Login origin. An explicit Accounts issuer wins so tests
// and a future combined host can serve both OIDC and /redxai-connect.
func (c *Core) QuickOrigin() string {
	if o, ok := c.Accounts.(*OIDCAccounts); ok && o != nil && strings.TrimSpace(o.Issuer) != "" {
		return strings.TrimRight(o.Issuer, "/")
	}
	return DefaultQuickOrigin
}

type quickStart struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Protocol        string `json:"protocol"`
}

type quickToken struct {
	Protocol     string `json:"protocol"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Remember     bool   `json:"remember_device"`
	User         struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
}

// LoginPrompt is what the user has to do in the browser. It has no tokens.
type LoginPrompt struct {
	UserCode        string `json:"userCode"`
	VerificationURI string `json:"verificationUri"`
}

// LoginQuick runs the device flow. open is called with the server-supplied
// verification URI before polling (the URI is not rebuilt). remember_device
// false keeps the access token in this process only: it is not written to the keyring.
func (c *Core) LoginQuick(ctx context.Context, open func(LoginPrompt)) (*Who, error) {
	origin := c.QuickOrigin()
	if c.Net == nil || !ValidOrigin(origin, c.Net.AllowLoopbackHTTP) {
		return nil, fmt.Errorf("quick login origin %q is not an https origin", origin)
	}
	pkce := NewPKCE()
	body, _ := json.Marshal(map[string]string{
		"client_id":             "rottencore",
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": "S256",
	})
	var start quickStart
	if err := c.postQuick(ctx, origin+"/redxai-connect/start", body, &start); err != nil {
		return nil, err
	}
	if start.Protocol != QuickLoginProtocol || start.DeviceCode == "" || start.VerificationURI == "" || start.UserCode == "" {
		return nil, errors.New("quick login returned an incomplete device code")
	}
	prompt := LoginPrompt{UserCode: start.UserCode, VerificationURI: start.VerificationURI}
	if open != nil {
		open(prompt)
	}
	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(5 * time.Minute)
	}
	var tok quickToken
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("quick login expired")
		}
		reqBody, _ := json.Marshal(map[string]string{
			"client_id":     "rottencore",
			"device_code":   start.DeviceCode,
			"code_verifier": pkce.Verifier,
		})
		status, err := c.postQuickStatus(ctx, origin+"/redxai-connect/token", reqBody, &tok)
		if err != nil {
			return nil, err
		}
		if status == 200 {
			break
		}
		if status == 428 || status == 429 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		return nil, fmt.Errorf("quick login answered %d", status)
	}
	if tok.Protocol != QuickLoginProtocol || tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
		return nil, errors.New("quick login did not return a bearer token")
	}
	if err := c.storeSession(tok.AccessToken, tok.RefreshToken, tok.Remember); err != nil {
		return nil, err
	}
	if err := c.quickUserinfo(ctx, origin, tok.AccessToken); err != nil {
		return nil, err
	}
	return c.WhoAmI(ctx, tok.AccessToken)
}

func (c *Core) storeSession(access, refresh string, remember bool) error {
	if !remember {
		_ = c.secrets().Delete("access-token")
		_ = c.secrets().Delete("refresh-token")
		return nil
	}
	if err := c.secrets().Put("access-token", []byte(access)); err != nil {
		return err
	}
	if refresh == "" {
		return nil
	}
	return c.secrets().Put("refresh-token", []byte(refresh))
}

// Logout drops keyring tokens and the in-memory OIDC session. It does not revoke
// other Red-XAI apps. Revocation is POST /redxai-connect/revoke when a refresh token exists.
func (c *Core) Logout(ctx context.Context) error {
	if b, err := c.secrets().Get("refresh-token"); err == nil && len(b) > 0 {
		origin := c.QuickOrigin()
		body, _ := json.Marshal(map[string]string{"token": string(b)})
		_ = c.postQuick(ctx, origin+"/redxai-connect/revoke", body, nil)
	}
	_ = c.secrets().Delete("access-token")
	_ = c.secrets().Delete("refresh-token")
	if o, ok := c.Accounts.(*OIDCAccounts); ok && o != nil {
		_ = o.SignOut(ctx)
	}
	return nil
}

func (c *Core) quickUserinfo(ctx context.Context, origin, access string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", origin+"/redxai-connect/userinfo", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Cache-Control", "no-store")
	resp, err := c.Net.client().Do(req)
	if err != nil {
		return errors.New("quick login userinfo failed")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("quick login userinfo answered %d", resp.StatusCode)
	}
	return nil
}

func (c *Core) postQuick(ctx context.Context, url string, body []byte, dest interface{}) error {
	status, err := c.postQuickStatus(ctx, url, body, dest)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("quick login answered %d", status)
	}
	return nil
}

func (c *Core) postQuickStatus(ctx context.Context, raw string, body []byte, dest interface{}) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", raw, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := c.Net.client().Do(req)
	if err != nil {
		return 0, errors.New("quick login request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	if dest == nil {
		return 200, nil
	}
	if err := json.Unmarshal(b, dest); err != nil {
		return 0, errors.New("quick login returned unreadable JSON")
	}
	return 200, nil
}
