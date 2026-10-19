package devhub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DeviceService registers and looks up developer devices. The local default keeps a JSON file; the dev-hub
// API implementation (future) talks to ra-core. See docs/DEV_HUB.md for the migration.
type DeviceService interface {
	// StartRegistration records a new pending device for this machine's platform and returns it with a
	// pairing code to show the developer. The caller supplies the device public key it generated.
	StartRegistration(platform Platform, publicKey []byte) (*Device, error)
	// Approve marks a device approved under a team (or individual). In production the store does this when
	// the developer confirms the pairing code in the dashboard; locally it is an explicit call.
	Approve(id, teamID string, individual bool) (*Device, error)
	// Current returns the approved device for this machine, or ErrNoDevice.
	Current() (*Device, error)
}

// LocalDeviceService is a file-backed DeviceService (one device record per file) used until the dev-hub API
// is live. It is intentionally simple: a documented stand-in, not the source of trust.
type LocalDeviceService struct {
	Path string // JSON file, e.g. <support dir>/devhub/device.json
	mu   sync.Mutex
	now  func() time.Time
}

func (s *LocalDeviceService) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *LocalDeviceService) load() (*Device, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var d Device
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *LocalDeviceService) store(d *Device) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	return os.WriteFile(s.Path, append(b, '\n'), 0o600)
}

func (s *LocalDeviceService) StartRegistration(platform Platform, publicKey []byte) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if platform != PlatformMac && platform != PlatformWindows {
		return nil, fmt.Errorf("unknown device platform %q", platform)
	}
	code, err := NewPairingCode()
	if err != nil {
		return nil, err
	}
	d := &Device{ID: "dev_" + fmt.Sprint(s.clock().UnixNano()), Platform: platform, PublicKey: publicKey,
		PairingCode: code, CreatedMs: s.clock().UnixMilli()}
	if err := s.store(d); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *LocalDeviceService) Approve(id, teamID string, individual bool) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return nil, ErrNoDevice
	}
	if d.ID != id {
		return nil, fmt.Errorf("no pending device %q", id)
	}
	d.Approved, d.TeamID, d.Individual, d.ApprovedMs = true, teamID, individual, s.clock().UnixMilli()
	if err := s.store(d); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *LocalDeviceService) Current() (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil || !d.Approved {
		return nil, ErrNoDevice
	}
	return d, nil
}

// BuildContext is the team/individual account, build API key and SDK selection a build runs under. In
// production ContextProvider.Context fetches it from the dev account (team or individual) with the build API
// key; locally it is read from a file.
type BuildContext struct {
	TeamID     string       `json:"teamId,omitempty"` // empty with Individual = individual account
	Individual bool         `json:"individual,omitempty"`
	Role       string       `json:"role"`     // developer | owner | admin
	BuildKey   string       `json:"buildKey"` // the build API key (required; never logged)
	Device     *Device      `json:"device,omitempty"`
	SDKs       SDKSelection `json:"sdks"`
}

// AccountLabel is a short description for the UI ("team T-josh" or "individual account").
func (c *BuildContext) AccountLabel() string {
	if c.Individual || c.TeamID == "" {
		return "individual account"
	}
	return "team " + c.TeamID
}

// Exempt reports whether SDK gating is skipped (owners and admins are exempt).
func (c *BuildContext) Exempt() bool { return c.Role == "owner" || c.Role == "admin" }

// RequireBuildKey returns ErrNoBuildKey when no build API key is set.
func (c *BuildContext) RequireBuildKey() error {
	if c == nil || c.BuildKey == "" {
		return ErrNoBuildKey
	}
	return nil
}

// SDKSelection is the per-app SDK picture from the store: what the developer selected for the app and what
// their account level has unlocked. The builder refuses an SDK that is declared but not both selected and
// unlocked (unless the context is exempt).
type SDKSelection struct {
	Selected []string `json:"selected"` // chosen for this app in the store
	Unlocked []string `json:"unlocked"` // allowed by the account's level/approvals
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ValidateSDKs checks a build's declared SDKs against the selection. Owners/admins are exempt. It returns
// the sorted, de-duplicated list to embed in the signed build manifest.
func (c *BuildContext) ValidateSDKs(declared []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, sdk := range declared {
		if seen[sdk] {
			continue
		}
		seen[sdk] = true
		out = append(out, sdk)
		if c.Exempt() {
			continue
		}
		if !has(c.SDKs.Selected, sdk) {
			return nil, fmt.Errorf("SDK %q is not selected for this app in the store", sdk)
		}
		if !has(c.SDKs.Unlocked, sdk) {
			return nil, fmt.Errorf("SDK %q is not unlocked for your account level", sdk)
		}
	}
	return out, nil
}

// ContextProvider supplies a BuildContext. Local default reads a JSON file; the dev-hub API version fetches
// it from ra-core.
type ContextProvider interface {
	Context() (*BuildContext, error)
}

// LocalContextProvider reads a BuildContext from a JSON file (e.g. <support dir>/devhub/context.json).
type LocalContextProvider struct{ Path string }

func (p LocalContextProvider) Context() (*BuildContext, error) {
	b, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, ErrNoBuildKey
	}
	var c BuildContext
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
