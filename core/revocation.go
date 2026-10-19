package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Revocation (docs/SIGNING.md §4). ra-core publishes a short-lived signed status ticket at GET /v1/status
// (6 h life) that lists revoked certificate fingerprints, builds ("sha256:<hex>") and app ids. It is signed
// with the store key under "RARXAI-STATUS-v1\0" and is the same document the Poison Apple launcher uses.
//
//   fresh  ticket not expired                      -> revocation checked
//   grace  expired less than 7 days ago (offline)  -> still accepted, the UI says it is offline
//   stale  older than that, or none ever fetched   -> signatures are "unverifiable", never "valid"
//
// A revoked certificate, build or app is a hard refusal whatever the person accepts. RottenCore caches the
// last good ticket on disk (status-ticket.json, 0600) and only replaces it with a newer, valid one, so a
// replayed older ticket cannot un-revoke anything.

const (
	statusDomain       = "RARXAI-STATUS-v1\x00"
	StatusTicketTTL    = 6 * time.Hour
	StatusOfflineGrace = 7 * 24 * time.Hour
	// StatusRefresh is how often RottenCore refreshes the ticket while running.
	StatusRefresh = 1 * time.Hour
)

// StatusTicket is rarxai.StatusTicket (same fields, order and tags; the document must re-encode exactly).
type StatusTicket struct {
	V             int                 `json:"v"`
	IssuedMs      int64               `json:"issuedMs"`
	ExpiresMs     int64               `json:"expiresMs"`
	RevokedCerts  []string            `json:"revokedCerts"`
	RevokedBuilds []string            `json:"revokedBuilds"`
	RevokedApps   []string            `json:"revokedApps"`
	MegaApps      []string            `json:"megaApps,omitempty"`
	Ratings       map[string]string   `json:"ratings,omitempty"`
	Suspended     map[string][]string `json:"suspended,omitempty"`
	PaidApps      []string            `json:"paidApps,omitempty"`
}

// SignStatusTicket is for tests (ra-core signs production tickets).
func SignStatusTicket(priv ed25519.PrivateKey, t StatusTicket) (*Signed, error) {
	t.V = 1
	for _, l := range []*[]string{&t.RevokedCerts, &t.RevokedBuilds, &t.RevokedApps} {
		if *l == nil {
			*l = []string{}
		}
		sort.Strings(*l)
	}
	b, err := canonJSON(&t)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, append([]byte(statusDomain), b...))
	return &Signed{Doc: base64.StdEncoding.EncodeToString(b), Key: KeyFingerprint(priv.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyStatusTicket checks the signature under a pinned store key and decodes strictly.
func VerifyStatusTicket(pins []ed25519.PublicKey, s *Signed) (*StatusTicket, error) {
	var t StatusTicket
	if err := openSigned(statusDomain, pins, s, &t); err != nil {
		return nil, err
	}
	if t.V != 1 || t.ExpiresMs <= t.IssuedMs {
		return nil, errors.New("status ticket has a bad header")
	}
	if !sort.StringsAreSorted(t.RevokedCerts) || !sort.StringsAreSorted(t.RevokedBuilds) || !sort.StringsAreSorted(t.RevokedApps) {
		return nil, errors.New("status ticket lists are not sorted")
	}
	return &t, nil
}

// RevocationState is the ticket RottenCore currently holds.
type RevocationState struct {
	Ticket *StatusTicket
}

// Freshness is fresh, grace or stale at now.
func (s *RevocationState) Freshness(now time.Time) string {
	if s == nil || s.Ticket == nil {
		return "none"
	}
	ms := now.UnixMilli()
	switch {
	case ms < s.Ticket.ExpiresMs:
		return "fresh"
	case ms < s.Ticket.ExpiresMs+StatusOfflineGrace.Milliseconds():
		return "grace"
	}
	return "stale"
}

// CheckRevocation returns a reason when revoked ("" otherwise) and the freshness of the list. A revocation
// on a stale list still counts: a stale list can make something unverifiable, never un-revoke it.
func CheckRevocation(s *RevocationState, appID, build string, certFPs []string, now time.Time) (string, string) {
	if now.IsZero() {
		now = time.Now()
	}
	state := s.Freshness(now)
	if s == nil || s.Ticket == nil {
		return "", state
	}
	has := func(l []string, v string) bool {
		i := sort.SearchStrings(l, v)
		return v != "" && i < len(l) && l[i] == v
	}
	t := s.Ticket
	if has(t.RevokedApps, appID) {
		return "the Rotten Apple store has revoked this app", state
	}
	if has(t.RevokedBuilds, build) {
		return "the Rotten Apple store has revoked this build", state
	}
	for _, fp := range certFPs {
		if has(t.RevokedCerts, fp) {
			return "the Rotten Apple store has revoked the developer certificate that signed this app", state
		}
	}
	return "", state
}

// RevocationCache keeps the last good ticket on disk.
type RevocationCache struct {
	Path string              // e.g. ~/Library/Application Support/RottenCore/status-ticket.json
	Pins []ed25519.PublicKey // store keys (production: PinnedStoreKeys)
}

// Load returns the cached state (empty when none or when the cached file no longer verifies).
func (c *RevocationCache) Load() *RevocationState {
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return &RevocationState{}
	}
	s, err := ParseSigned(b)
	if err != nil {
		return &RevocationState{}
	}
	t, err := VerifyStatusTicket(c.Pins, s)
	if err != nil {
		return &RevocationState{}
	}
	return &RevocationState{Ticket: t}
}

// Store saves a verified ticket if it is newer than the cached one. It returns the state now in force.
func (c *RevocationCache) Store(s *Signed) (*RevocationState, error) {
	t, err := VerifyStatusTicket(c.Pins, s)
	if err != nil {
		return c.Load(), err
	}
	cur := c.Load()
	if cur.Ticket != nil && t.IssuedMs <= cur.Ticket.IssuedMs {
		return cur, nil // never go back to an older list
	}
	b, err := json.Marshal(s)
	if err != nil {
		return cur, err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return cur, err
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return cur, err
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		os.Remove(tmp)
		return cur, err
	}
	return &RevocationState{Ticket: t}, nil
}

// Refresh fetches GET <store>/v1/status and stores it; on any network error the cached state is returned
// with the error, so the caller can carry on offline (grace) and say so.
func (c *RevocationCache) Refresh(ctx context.Context, n *Net, storeURL string) (*RevocationState, error) {
	var s Signed
	if err := n.GetJSON(ctx, storeURL+"/v1/status", &s); err != nil {
		return c.Load(), err
	}
	return c.Store(&s)
}

// openSigned verifies a store-signed envelope under pins and decodes it strictly and canonically
// (rarxai openDoc).
func openSigned(domain string, pins []ed25519.PublicKey, s *Signed, out interface{}) error {
	if s == nil || len(s.Doc) > 4<<20 || len(s.Sig) > 200 {
		return errors.New("signed document missing or oversized")
	}
	var key ed25519.PublicKey
	for _, p := range pins {
		if len(p) == ed25519.PublicKeySize && KeyFingerprint(p) == s.Key {
			key = p
		}
	}
	if key == nil {
		return errors.New("signed by a key RottenCore does not pin")
	}
	b, err := base64.StdEncoding.DecodeString(s.Doc)
	if err != nil {
		return errors.New("document is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("bad signature encoding")
	}
	if !ed25519.Verify(key, append([]byte(domain), b...), sig) {
		return errors.New("bad signature")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("document does not parse: " + err.Error())
	}
	if again, err := canonJSON(out); err != nil || !bytes.Equal(again, b) {
		return errors.New("document is not canonical")
	}
	return nil
}
