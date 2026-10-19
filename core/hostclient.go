package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HostClient is RottenCore's client for a Red-XAI Host's update API (specs/redx-host-update-contract.md
// as built in RedX PR #10, head 47a5278). Differences from the written contract it follows:
//   - POST apply / promote / rollback / publish send X-RedX-Confirm: <operation id> (428 confirm_required
//     without it): updateApply, updatePromote, updateRolloutRollback, updateAppRollback, updatePublish.
//   - GET /v1/updates/apps lists every app.
//   - Owner-gate denials are {"error":"<string>"} with 403 or 404; other errors are
//     {"error":{"code","message"}} (validation = invalid/400, missing login = forbidden/401).
//   - Rollout JSON carries rollout_id, app, version, source and the effective strategy (direct when the
//     cluster has fewer than two nodes); progress.percent is a number.
//   - Live events: WebSocket GET /v1/updates/events (/v1/apps/events is a JSON poll, not used here).
//   - Phase 1: heuristic risk, certificate null, live_patch []. Auto-apply is skipped on hosts with
//     Accounts enabled.
//
// The token (RedX key or Red-XAI Accounts session) is sent only to the host origin and never logged.
type HostClient struct {
	Base  string // https origin of the host, e.g. https://redx.example
	Token string
	Net   *Net
	// AllowLoopbackHTTP is for tests only.
	AllowLoopbackHTTP bool
}

// Confirm operation ids (RedX host/danger.go).
const (
	OpUpdateApply           = "updateApply"
	OpUpdatePromote         = "updatePromote"
	OpUpdateRolloutRollback = "updateRolloutRollback"
	OpUpdateAppRollback     = "updateAppRollback"
	OpUpdatePublish         = "updatePublish"
)

// HostError is any non-2xx answer, normalised over both error shapes.
type HostError struct {
	Status    int
	Code      string // not_hosted | bad_signature | sequence_regression | snapshot_failed | rollout_conflict | not_found | forbidden | invalid | confirm_required | owner_only
	Message   string
	OwnerGate bool // {"error":"<string>"} from the shared owner gate
}

func (e *HostError) Error() string {
	return fmt.Sprintf("host answered %d %s: %s", e.Status, e.Code, e.Message)
}

// ParseHostError reads either error shape.
func ParseHostError(status int, b []byte) *HostError {
	e := &HostError{Status: status}
	var structured struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(b, &structured) == nil && len(structured.Error) > 0 {
		var s string
		var o struct{ Code, Message string }
		switch {
		case json.Unmarshal(structured.Error, &s) == nil:
			e.Message, e.OwnerGate = s, true
			e.Code = "owner_only"
			if status == http.StatusNotFound {
				e.Code = "not_found"
			}
		case json.Unmarshal(structured.Error, &o) == nil:
			e.Code, e.Message = o.Code, o.Message
		}
	}
	if e.Code == "" {
		e.Code = map[int]string{400: "invalid", 401: "forbidden", 403: "forbidden", 404: "not_found", 409: "rollout_conflict", 428: "confirm_required"}[status]
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(b))
		}
	}
	return e
}

func (h *HostClient) url(p string, q url.Values) (string, error) {
	if !ValidOrigin(strings.TrimRight(h.Base, "/"), h.AllowLoopbackHTTP) {
		return "", fmt.Errorf("host %q is not an https origin", h.Base)
	}
	u := strings.TrimRight(h.Base, "/") + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u, nil
}

func (h *HostClient) http() *http.Client {
	n := h.Net
	if n == nil {
		n = &Net{AllowLoopbackHTTP: h.AllowLoopbackHTTP}
	}
	c := *n.client()
	if c.Timeout == 0 || c.Timeout > time.Minute {
		c.Timeout = time.Minute
	}
	return &c
}

// do sends one request; confirm is the operation id for dangerous calls.
func (h *HostClient) do(ctx context.Context, method, p string, q url.Values, body interface{}, confirm string, out interface{}) (http.Header, []byte, error) {
	u, err := h.url(p, q)
	if err != nil {
		return nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "RottenCore/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	if confirm != "" {
		req.Header.Set("X-RedX-Confirm", confirm)
	}
	resp, err := h.http().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, b, ParseHostError(resp.StatusCode, b)
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.Header, b, fmt.Errorf("host answer does not parse: %w", err)
		}
	}
	return resp.Header, b, nil
}

// HostAvailable is one version offered for an app.
type HostAvailable struct {
	Version string        `json:"version"`
	Channel string        `json:"channel"`
	Outcome UpdateOutcome `json:"outcome"`
	Sources []string      `json:"sources"`
}

// HostVerRef is {version, sequence}.
type HostVerRef struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
}

// HostApp is GET /v1/updates/apps/{app} (and one element of GET /v1/updates/apps).
type HostApp struct {
	App        string      `json:"app"`
	Hosted     bool        `json:"hosted"`
	SourcePref string      `json:"source_pref"`
	Installed  *HostVerRef `json:"installed"`
	Latest     struct {
		Host   *HostVerRef `json:"host"`
		GitHub *HostVerRef `json:"github"`
	} `json:"latest"`
	Available []HostAvailable `json:"available"`
}

// SourceOptions is what the picker may offer for this app.
func (a *HostApp) SourceOptions() []string { return UpdateSourceOptions(a.Hosted) }

// HostRollout is GET /v1/updates/rollouts/{id}.
type HostRollout struct {
	RolloutID  string `json:"rollout_id"`
	App        string `json:"app"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Strategy   string `json:"strategy"` // effective: canary | blue_green | direct (direct when < 2 nodes)
	State      string `json:"state"`    // scheduled | snapshotting | canary | promoting | done | rolled_back | failed
	SnapshotID string `json:"snapshot_id"`
	Progress   struct {
		Updated int     `json:"updated"`
		Total   int     `json:"total"`
		Percent float64 `json:"percent"`
	} `json:"progress"`
	Health map[string]interface{} `json:"health"`
}

// Terminal reports whether the rollout has finished one way or another.
func (r *HostRollout) Terminal() bool {
	return r.State == "done" || r.State == "rolled_back" || r.State == "failed"
}

// HostSnapshot is one immutable snapshot.
type HostSnapshot struct {
	ID        string    `json:"id"`
	App       string    `json:"app"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
}

// ApplyRequest is POST /v1/updates/apps/{app}/apply.
type ApplyRequest struct {
	Version  string `json:"version"`
	Source   string `json:"source"`
	Strategy string `json:"strategy,omitempty"` // canary | blue_green | direct
	Canary   *struct {
		Percent    int `json:"percent"`
		MinMinutes int `json:"min_minutes"`
	} `json:"canary,omitempty"`
	ScheduleAt *time.Time `json:"schedule_at,omitempty"`
	DryRun     bool       `json:"dry_run"`
}

// Apps lists every app (GET /v1/updates/apps).
func (h *HostClient) Apps(ctx context.Context) ([]HostApp, error) {
	var out struct {
		Apps []HostApp `json:"apps"`
	}
	_, _, err := h.do(ctx, "GET", "/v1/updates/apps", nil, nil, "", &out)
	return out.Apps, err
}

// App is one app's update status.
func (h *HostClient) App(ctx context.Context, app string) (*HostApp, error) {
	var out HostApp
	_, _, err := h.do(ctx, "GET", "/v1/updates/apps/"+url.PathEscape(app), nil, nil, "", &out)
	return &out, err
}

// Keys is GET /v1/updates/keys (no auth).
func (h *HostClient) Keys(ctx context.Context) ([]UpdateKey, error) {
	var out []UpdateKey
	_, _, err := h.do(ctx, "GET", "/v1/updates/keys", nil, nil, "", &out)
	return out, err
}

// Manifest fetches the exact manifest bytes plus X-RedX-Signature and X-RedX-Key-Id.
func (h *HostClient) Manifest(ctx context.Context, app, version, source string) (body []byte, sig, kid string, err error) {
	q := url.Values{}
	if source != "" {
		q.Set("source", source)
	}
	hdr, b, err := h.do(ctx, "GET", "/v1/updates/apps/"+url.PathEscape(app)+"/manifests/"+url.PathEscape(version), q, nil, "", nil)
	if err != nil {
		return nil, "", "", err
	}
	return b, hdr.Get("X-RedX-Signature"), hdr.Get("X-RedX-Key-Id"), nil
}

// VerifiedManifest fetches the keys and the manifest and verifies both: the host key's ra-core chain and
// revocation, then the manifest signature, schema and sequence (> lastSeq).
func (h *HostClient) VerifiedManifest(ctx context.Context, app, version, source string, pol ChainPolicy, rev *RevocationState, lastSeq int64) (*UpdateManifest, error) {
	keys, err := h.Keys(ctx)
	if err != nil {
		return nil, err
	}
	trusted, why := TrustedUpdateKeys(keys, pol, rev)
	if len(trusted) == 0 {
		return nil, umErr("bad_signature", "no host update key has a valid, unrevoked Red-XAI certificate (%s)", strings.Join(why, "; "))
	}
	body, sig, kid, err := h.Manifest(ctx, app, version, source)
	if err != nil {
		return nil, err
	}
	m, err := VerifyUpdateManifest(body, sig, kid, trusted, lastSeq)
	if err != nil {
		return nil, err
	}
	if m.App != app || m.Version != version {
		return nil, umErr("bad_manifest", "asked for %s %s, got %s %s", app, version, m.App, m.Version)
	}
	return m, nil
}

// SetSource stores the per-app source preference (409 not_hosted for host/both on a non-hosted app).
func (h *HostClient) SetSource(ctx context.Context, app, source string, hosted bool) error {
	if err := ValidUpdateSource(source, hosted); err != nil {
		return err
	}
	_, _, err := h.do(ctx, "PUT", "/v1/updates/apps/"+url.PathEscape(app)+"/source", nil, map[string]string{"source": source}, "", nil)
	return err
}

// Apply starts a rollout; the host snapshots first and refuses if the snapshot fails.
func (h *HostClient) Apply(ctx context.Context, app string, req ApplyRequest) (rolloutID, snapshotID string, err error) {
	var out struct {
		RolloutID  string `json:"rollout_id"`
		SnapshotID string `json:"snapshot_id"`
	}
	_, _, err = h.do(ctx, "POST", "/v1/updates/apps/"+url.PathEscape(app)+"/apply", nil, req, OpUpdateApply, &out)
	return out.RolloutID, out.SnapshotID, err
}

// Rollout reads one rollout.
func (h *HostClient) Rollout(ctx context.Context, id string) (*HostRollout, error) {
	var out HostRollout
	_, _, err := h.do(ctx, "GET", "/v1/updates/rollouts/"+url.PathEscape(id), nil, nil, "", &out)
	return &out, err
}

// Promote moves a canary to 100%.
func (h *HostClient) Promote(ctx context.Context, id string) error {
	_, _, err := h.do(ctx, "POST", "/v1/updates/rollouts/"+url.PathEscape(id)+"/promote", nil, map[string]string{}, OpUpdatePromote, nil)
	return err
}

// RollbackRollout rolls a rollout back (also mid-rollout).
func (h *HostClient) RollbackRollout(ctx context.Context, id, reason string) error {
	_, _, err := h.do(ctx, "POST", "/v1/updates/rollouts/"+url.PathEscape(id)+"/rollback", nil, map[string]string{"reason": reason}, OpUpdateRolloutRollback, nil)
	return err
}

// RestoreSnapshot restores an app to a snapshot.
func (h *HostClient) RestoreSnapshot(ctx context.Context, app, snapshotID string) error {
	_, _, err := h.do(ctx, "POST", "/v1/updates/apps/"+url.PathEscape(app)+"/rollback", nil, map[string]string{"snapshot_id": snapshotID}, OpUpdateAppRollback, nil)
	return err
}

// Snapshots lists an app's snapshots.
func (h *HostClient) Snapshots(ctx context.Context, app string) ([]HostSnapshot, error) {
	var raw json.RawMessage
	if _, _, err := h.do(ctx, "GET", "/v1/updates/apps/"+url.PathEscape(app)+"/snapshots", nil, nil, "", &raw); err != nil {
		return nil, err
	}
	var list []HostSnapshot
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	var wrapped struct {
		Snapshots []HostSnapshot `json:"snapshots"`
	}
	err := json.Unmarshal(raw, &wrapped)
	return wrapped.Snapshots, err
}

// Publish keeps GitHub and the host in sync. RottenCore's uploader calls it only after QA sign-off.
func (h *HostClient) Publish(ctx context.Context, app string, req interface{}) (json.RawMessage, error) {
	var out json.RawMessage
	_, _, err := h.do(ctx, "POST", "/v1/updates/apps/"+url.PathEscape(app)+"/publish", nil, req, OpUpdatePublish, &out)
	return out, err
}

// HostEvent is one message on GET /v1/updates/events.
type HostEvent struct {
	Type      string `json:"type"` // update.available | update.analysed | rollout.state | rollout.health | rollback.done
	App       string `json:"app"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	RolloutID string `json:"rollout_id,omitempty"`
	State     string `json:"state,omitempty"`
}

// Events opens the WebSocket at /v1/updates/events and calls fn for every event until ctx ends or the
// connection closes. Minimal RFC 6455 client: text frames in, pings answered, nothing else sent.
func (h *HostClient) Events(ctx context.Context, fn func(HostEvent)) error {
	u, err := h.url("/v1/updates/events", nil)
	if err != nil {
		return err
	}
	pu, _ := url.Parse(u)
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), map[string]string{"https": "443", "http": "80"}[pu.Scheme])
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	if pu.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: pu.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tc
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req := "GET " + pu.RequestURI() + " HTTP/1.1\r\nHost: " + pu.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: RottenCore/" + Version + "\r\n"
	if h.Token != "" {
		req += "Authorization: Bearer " + h.Token + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ParseHostError(resp.StatusCode, b)
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return errors.New("events: bad WebSocket handshake")
	}
	var msg []byte
	for {
		fin, op, payload, err := readWSFrame(br)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		switch op {
		case 0x8: // close
			return nil
		case 0x9: // ping -> pong (masked, as a client must)
			if err := writeWSFrame(conn, 0xA, payload); err != nil {
				return err
			}
			continue
		case 0xA:
			continue
		case 0x1, 0x0:
			msg = append(msg, payload...)
			if len(msg) > 1<<20 {
				return errors.New("events: message too large")
			}
		default:
			continue
		}
		if fin {
			var ev HostEvent
			if json.Unmarshal(msg, &ev) == nil && ev.Type != "" {
				fn(ev)
			}
			msg = msg[:0]
		}
	}
}

func readWSFrame(r *bufio.Reader) (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	fin, op = h[0]&0x80 != 0, h[0]&0x0F
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 {
		return false, 0, nil, errors.New("events: frame too large")
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

func writeWSFrame(w io.Writer, op byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	b := []byte{0x80 | op, 0x80 | byte(len(payload))}
	b = append(b, mask[:]...)
	for i, c := range payload {
		b = append(b, c^mask[i%4])
	}
	_, err := w.Write(b)
	return err
}
