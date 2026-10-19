package devhub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file wires Rotten Core's dev-account client to the real store API (RottenApple branch dev-hub,
// docs/DEV_HUB_API.md). The local file-backed services stay as the fallback behind the DeviceService and
// ContextProvider interfaces; Client is the primary when a store URL and build API key are configured.

// hubProto is the domain prefix for every signed dev-hub message.
const hubProto = "rottenapple-devhub-v1"

// LauncherHeader is required by ra-core HubMinLauncher (DEV_HUB_API.md §B6 / N1).
const LauncherHeader = "X-RA-Launcher"

// LauncherVersion is what Rotten Core sends as X-RA-Launcher. Must be >= HubMinLauncher (0.2.0).
// Kept separate from core.Version so the hub gate tracks the Poison Apple launcher floor.
const LauncherVersion = "0.2.0"

// AccountsKeyHeader carries Josh's Red-XAI Accounts full-access key on the pairing and cert requests
// (and the signing-time account-status check). ra-core resolves the sub and team coverage server-side.
// PENDING (Grok Bot): header name and API shape are placeholders until ra-core's commit lands.
const AccountsKeyHeader = "X-RedX-Accounts-Key"

// AccountStatusPath is the signing-time identity check. PENDING: placeholder path.
const AccountStatusPath = "/v1/devhub/account-status"

// DeviceKey is a device or signing key held on this machine. Only the public bytes ever leave it; signing
// happens here. Software keys are Ed25519 (spec §2); a Secure Enclave key would implement the same shape.
type DeviceKey interface {
	Public() []byte
	Sign(msg []byte) ([]byte, error)
}

// EdKey is an Ed25519 DeviceKey.
type EdKey struct{ Priv ed25519.PrivateKey }

func (k EdKey) Public() []byte { return append([]byte(nil), k.Priv.Public().(ed25519.PublicKey)...) }
func (k EdKey) Sign(msg []byte) ([]byte, error) {
	if len(k.Priv) != ed25519.PrivateKeySize {
		return nil, errors.New("device key is not an Ed25519 private key")
	}
	return ed25519.Sign(k.Priv, msg), nil
}

// Fingerprint is the device identifier the store and the signed messages use: sha256 of the public key.
func Fingerprint(pub []byte) string {
	s := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(s[:])
}

// APIError is a non-2xx answer from the dev-hub API, over both error shapes the store uses:
// {"error":"code","message":"…"} and {"error":{"code":"…","message":"…"}}.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("dev hub %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("dev hub %d %s", e.Status, e.Code)
}

func codeIs(err error, code string) bool {
	var a *APIError
	return errors.As(err, &a) && a.Code == code
}

// The named failures the spec calls out, as predicates so callers (and the UI) can react.
func IsBuildKeyRequired(err error) bool     { return codeIs(err, "build_key_required") }
func IsWrongPlatform(err error) bool        { return codeIs(err, "wrong_platform") }
func IsSDKLocked(err error) bool            { return codeIs(err, "sdk_locked") }
func IsSDKNotSelected(err error) bool       { return codeIs(err, "sdk_not_selected") }
func IsSDKManifestMissing(err error) bool   { return codeIs(err, "sdk_manifest_missing") }
func IsSDKSelectionRequired(err error) bool { return codeIs(err, "sdk_selection_required") }
func IsDeviceCertRequired(err error) bool   { return codeIs(err, "device_cert_required") }

// IsCertIssuerNotConfigured reports the 501 the store returns until the production issuing CA is loaded
// (the root ceremony is still Josh's decision). Rotten Core shows "the production CA isn't loaded yet".
func IsCertIssuerNotConfigured(err error) bool {
	var a *APIError
	return errors.As(err, &a) && (a.Code == "cert_issuer_not_configured" || a.Status == http.StatusNotImplemented)
}

// CertIssuerNotConfiguredMessage is shown verbatim when IsCertIssuerNotConfigured.
const CertIssuerNotConfiguredMessage = "the production signing CA isn't loaded in the store yet; certificates can't be issued until the root ceremony is done"

func parseAPIError(status int, b []byte) *APIError {
	e := &APIError{Status: status}
	var env struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(b, &env) == nil {
		e.Message = env.Message
		var s string
		var o struct{ Code, Message string }
		switch {
		case len(env.Error) > 0 && json.Unmarshal(env.Error, &s) == nil:
			e.Code = s
		case len(env.Error) > 0 && json.Unmarshal(env.Error, &o) == nil:
			e.Code = o.Code
			if e.Message == "" {
				e.Message = o.Message
			}
		}
	}
	if e.Code == "" {
		e.Code = map[int]string{400: "invalid", 401: "build_key_required", 403: "forbidden", 404: "not_found",
			422: "unprocessable", 501: "cert_issuer_not_configured"}[status]
		if e.Code == "" {
			e.Code = "error"
		}
	}
	return e
}

// Client talks to the dev-hub API. BaseURL is the store origin; APIKey is the build API key (empty → the
// key routes answer build_key_required); Device is this machine's device key, used to sign proofs.
type Client struct {
	BaseURL  string
	HTTP     *http.Client
	APIKey   string
	Device   DeviceKey
	Platform Platform
	Now      func() time.Time
	// AccountsKey is the Red-XAI Accounts full-access key typed at the tty prompt. It is sent only in
	// AccountsKeyHeader and the caller zeroes it after use (net/http needs a string copy per request).
	AccountsKey []byte
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// do sends one JSON request. withKey adds the build API key as a Bearer token.
func (c *Client) do(ctx context.Context, method, path string, body interface{}, withKey bool, out interface{}) error {
	if strings.TrimRight(c.BaseURL, "/") == "" {
		return errors.New("no dev-hub base URL configured")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	// HubMinLauncher gate: ra-core refuses hub packages / some routes without a new-enough launcher.
	req.Header.Set(LauncherHeader, LauncherVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withKey {
		if c.APIKey == "" {
			return &APIError{Status: http.StatusUnauthorized, Code: "build_key_required",
				Message: ErrNoBuildKey.Error()}
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if len(c.AccountsKey) > 0 && accountsKeyPath(path) {
		req.Header.Set(AccountsKeyHeader, string(c.AccountsKey))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, b)
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- Pairing (spec §2) ----

// Pairing is the answer to POST /v1/devhub/pairings.
type Pairing struct {
	Code       string `json:"code"`
	PollSecret string `json:"pollSecret"`
	ExpiresMs  int64  `json:"expiresMs"`
	ApproveURL string `json:"approveUrl"`
}

// PairMessage is what the device key signs to open a pairing.
func PairMessage(platform Platform, kind, pubHex, name string) []byte {
	return []byte(hubProto + "\npair\n" + storePlatform(platform) + "\n" + kind + "\n" + strings.ToLower(pubHex) + "\n" + name)
}

// storePlatform maps the client Platform ("mac"/"windows") to the store's "macos"/"windows".
func storePlatform(p Platform) string {
	if p == PlatformMac {
		return "macos"
	}
	return "windows"
}

// StartPairing generates a pairing: signs PairMessage with the device key and posts it (no sign-in).
func (c *Client) StartPairing(name string) (*Pairing, error) {
	if c.Device == nil {
		return nil, errors.New("no device key")
	}
	pubHex := hex.EncodeToString(c.Device.Public())
	kind := "software-ed25519"
	sig, err := c.Device.Sign(PairMessage(c.Platform, kind, pubHex, name))
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"name": name, "platform": storePlatform(c.Platform), "kind": kind,
		"publicKey": pubHex, "signature": base64.StdEncoding.EncodeToString(sig),
	}
	var p Pairing
	if err := c.do(context.Background(), "POST", "/v1/devhub/pairings", body, false, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// accountsKeyPath limits the Accounts key to the routes that need it (pairing, cert issue, account status).
func accountsKeyPath(p string) bool {
	switch p {
	case "/v1/devhub/pairings", "/v1/devhub/pairings/status", "/v1/devhub/challenge", "/v1/devhub/certs", AccountStatusPath:
		return true
	}
	return false
}

// AccountIdentity is who ra-core resolved the Accounts key to. Subject is kept as the server's exact
// bytes: the Mega cert's subject must equal it byte for byte. PENDING: field names and placement.
type AccountIdentity struct {
	Name    string          `json:"name"`
	Email   string          `json:"email"`
	Subject json.RawMessage `json:"subject"`
}

// PairingStatus is the answer to POST /v1/devhub/pairings/status.
type PairingStatus struct {
	State    string           `json:"state"` // pending | approved | denied
	Device   string           `json:"device"`
	Team     string           `json:"team"`
	Platform string           `json:"platform"`
	Targets  []string         `json:"targets"`
	Account  *AccountIdentity `json:"account,omitempty"` // PENDING: returned once approved
}

// AccountStatus asks ra-core who the Accounts key belongs to (signing-time check). PENDING shape.
func (c *Client) AccountStatus(ctx context.Context) (*AccountIdentity, error) {
	if len(c.AccountsKey) == 0 {
		return nil, errors.New("no Red-XAI Accounts key")
	}
	var r struct {
		Account *AccountIdentity `json:"account"`
	}
	if err := c.do(ctx, "POST", AccountStatusPath, map[string]string{}, false, &r); err != nil {
		return nil, err
	}
	if r.Account == nil || len(r.Account.Subject) == 0 {
		return nil, errors.New("ra-core returned no account subject")
	}
	return r.Account, nil
}

// PollPairing polls the pairing with the poll secret.
func (c *Client) PollPairing(ctx context.Context, code, pollSecret string) (*PairingStatus, error) {
	var s PairingStatus
	err := c.do(ctx, "POST", "/v1/devhub/pairings/status", map[string]string{"code": code, "pollSecret": pollSecret}, false, &s)
	return &s, err
}

// ---- CA chain (spec §4) ----

// CAChainInfo is the public GET /v1/devhub/ca/chain answer.
type CAChainInfo struct {
	Chain      []json.RawMessage `json:"chain"`
	Issuing    bool              `json:"issuing"`
	Production bool              `json:"production"`
}

// CAChain returns the issuing chain (public GET /v1/devhub/ca/chain), as the raw cert JSON objects.
func (c *Client) CAChain(ctx context.Context) ([]json.RawMessage, error) {
	info, err := c.CAChainInfo(ctx)
	if err != nil {
		return nil, err
	}
	return info.Chain, nil
}

// CAChainInfo returns the full public CA status (chain + whether an issuer is loaded).
func (c *Client) CAChainInfo(ctx context.Context) (*CAChainInfo, error) {
	var out CAChainInfo
	if err := c.do(ctx, "GET", "/v1/devhub/ca/chain", nil, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Device proofs (spec §3) ----

type challengeResp struct {
	Nonce     string `json:"nonce"`
	ExpiresMs int64  `json:"expiresMs"`
	Team      string `json:"team"`
	Purpose   string `json:"purpose"`
}

// challenge asks for a single-use challenge for one purpose ("cert" or "keycheck"); it needs the build key.
func (c *Client) challenge(ctx context.Context, purpose string) (*challengeResp, error) {
	var r challengeResp
	err := c.do(ctx, "POST", "/v1/devhub/challenge", map[string]string{"purpose": purpose}, true, &r)
	return &r, err
}

// HubDeviceMessage is what the device key signs for a proof. extra is purpose-specific (for a cert, the new
// public key hex).
func HubDeviceMessage(purpose, nonce, team, fingerprint string, extra ...string) []byte {
	parts := []string{hubProto, purpose, nonce, team, fingerprint}
	parts = append(parts, extra...)
	return []byte(strings.Join(parts, "\n"))
}

func (c *Client) deviceProof(purpose string, ch *challengeResp, extra ...string) (map[string]string, []byte, error) {
	fp := Fingerprint(c.Device.Public())
	msg := HubDeviceMessage(purpose, ch.Nonce, ch.Team, fp, extra...)
	sig, err := c.Device.Sign(msg)
	if err != nil {
		return nil, nil, err
	}
	return map[string]string{"device": fp, "nonce": ch.Nonce, "signature": base64.StdEncoding.EncodeToString(sig)}, msg, nil
}

// ---- Device-bound certificates (spec §4) ----

// CertResponse is the answer to POST /v1/devhub/certs.
type CertResponse struct {
	Certificate json.RawMessage   `json:"certificate"`
	Chain       []json.RawMessage `json:"chain"`
	Fingerprint string            `json:"fingerprint"`
	Platforms   []string          `json:"platforms"`
	ExpiresMs   int64             `json:"expiresMs"`
}

// IssueCert asks the store to issue a device-bound developer certificate for newKey, a signing key made on
// this device. It takes a cert-purpose challenge, has the device prove possession, and has the new key sign
// the same message. Returns IsCertIssuerNotConfigured(err) when the production CA isn't loaded yet.
func (c *Client) IssueCert(ctx context.Context, newKey DeviceKey) (*CertResponse, error) {
	if c.Device == nil || newKey == nil {
		return nil, errors.New("device key and new signing key are required")
	}
	ch, err := c.challenge(ctx, "cert")
	if err != nil {
		return nil, err
	}
	newPubHex := hex.EncodeToString(newKey.Public())
	proof, msg, err := c.deviceProof("cert", ch, newPubHex)
	if err != nil {
		return nil, err
	}
	keySig, err := newKey.Sign(msg)
	if err != nil {
		return nil, err
	}
	proof["publicKey"] = newPubHex
	proof["keySignature"] = base64.StdEncoding.EncodeToString(keySig)
	var out CertResponse
	if err := c.do(ctx, "POST", "/v1/devhub/certs", proof, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Build API key check (spec §5) ----

// KeyCheck is the answer to POST /v1/devhub/keys/check.
type KeyCheck struct {
	OK      bool            `json:"ok"`
	Key     json.RawMessage `json:"key"`
	Device  json.RawMessage `json:"device"`
	Targets []string        `json:"targets"`
	Context json.RawMessage `json:"context"`
}

// CheckKey confirms the build API key works together with this registered device, before a build.
func (c *Client) CheckKey(ctx context.Context) (*KeyCheck, error) {
	ch, err := c.challenge(ctx, "keycheck")
	if err != nil {
		return nil, err
	}
	proof, _, err := c.deviceProof("keycheck", ch)
	if err != nil {
		return nil, err
	}
	var out KeyCheck
	if err := c.do(ctx, "POST", "/v1/devhub/keys/check", proof, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Team context (spec §6) ----

type hubContext struct {
	Team     json.Number     `json:"team"`
	TeamName string          `json:"teamName"`
	TeamKind string          `json:"teamKind"`
	Role     string          `json:"role"`
	Level    int             `json:"level"`
	Mega     bool            `json:"mega"`
	Staff    bool            `json:"staff"`
	SDKs     []hubSDK        `json:"sdks"`
	Apps     []string        `json:"apps"`
	Key      json.RawMessage `json:"key"`
}

type hubSDK struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Level    int    `json:"level"`
	Unlocked bool   `json:"unlocked"`
}

// Context fetches the team/individual build context with the build API key (implements ContextProvider).
func (c *Client) Context() (*BuildContext, error) {
	var hc hubContext
	if err := c.do(context.Background(), "GET", "/v1/devhub/context", nil, true, &hc); err != nil {
		return nil, err
	}
	bc := &BuildContext{
		TeamID:     hc.Team.String(),
		Individual: hc.TeamKind == "individual",
		Role:       hc.Role,
		BuildKey:   c.APIKey,
	}
	for _, s := range hc.SDKs {
		if s.Unlocked {
			bc.SDKs.Unlocked = append(bc.SDKs.Unlocked, s.ID)
		}
	}
	return bc, nil
}

// ---- Per-app SDK selection (spec §7) ----

// AppSDKs is the answer to GET /v1/devhub/apps/{appId}/sdks: what the builder writes into the manifest.
type AppSDKs struct {
	Selected []string `json:"selected"`
	Services []string `json:"services"`
	Manifest struct {
		SDKs []string `json:"sdks"`
	} `json:"manifest"`
	SDKs  []hubSDK `json:"sdks"`
	Level int      `json:"level"`
}

// AppSDKs fetches the per-app SDK selection by bundle id (build API key). A locked or unselected SDK on the
// upload is where the 422 sdk_* failures surface; this read returns the current selection and status.
func (c *Client) AppSDKs(ctx context.Context, appID string) (*AppSDKs, error) {
	var out AppSDKs
	if err := c.do(ctx, "GET", "/v1/devhub/apps/"+url.PathEscape(appID)+"/sdks", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SelectionFor returns the SDKSelection for a BuildContext from the per-app read, merged with the context's
// account-level unlocked list.
func (a *AppSDKs) SelectionFor(unlocked []string) SDKSelection {
	sel := SDKSelection{Selected: append([]string(nil), a.Manifest.SDKs...), Unlocked: append([]string(nil), unlocked...)}
	for _, s := range a.SDKs {
		if s.Unlocked && !has(sel.Unlocked, s.ID) {
			sel.Unlocked = append(sel.Unlocked, s.ID)
		}
	}
	if len(sel.Selected) == 0 {
		sel.Selected = append([]string(nil), a.Selected...)
	}
	return sel
}
