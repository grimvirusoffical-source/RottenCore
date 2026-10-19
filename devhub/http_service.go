package devhub

import (
	"context"
	"fmt"
)

// HTTPDeviceService adapts the dev-hub Client to the DeviceService interface, caching the approved device
// locally so Current() works between runs and offline. It is the primary; LocalDeviceService stays as the
// fallback behind the same interface (docs/DEV_HUB.md).
type HTTPDeviceService struct {
	Client *Client
	Cache  *LocalDeviceService // persists the device record (pending, then approved)
	Name   string              // device name shown in the dashboard
}

// StartRegistration opens a pairing with the store and caches the pending device with its poll secret. The
// publicKey must be the Client's device key; it is recorded for reference.
func (s *HTTPDeviceService) StartRegistration(platform Platform, publicKey []byte) (*Device, error) {
	name := s.Name
	if name == "" {
		name = "Rotten Core device"
	}
	p, err := s.Client.StartPairing(name)
	if err != nil {
		return nil, err
	}
	d := &Device{
		ID: p.Code, Platform: platform, PublicKey: publicKey, PairingCode: p.Code,
		PollSecret: p.PollSecret, CreatedMs: s.Client.now().UnixMilli(),
	}
	if err := s.Cache.store(d); err != nil {
		return nil, err
	}
	return d, nil
}

// Approve polls the pairing once and, if the dashboard approved it, finalizes the cached device. The teamID
// and individual arguments are ignored: the store decides the team from the approval (the interface shape is
// shared with the local stand-in). A still-pending or denied pairing returns an error.
func (s *HTTPDeviceService) Approve(id, _ string, _ bool) (*Device, error) {
	d, err := s.Cache.load()
	if err != nil {
		return nil, ErrNoDevice
	}
	if d.PairingCode == "" || d.PollSecret == "" {
		return nil, fmt.Errorf("no pending pairing to approve; start registration first")
	}
	st, err := s.Client.PollPairing(context.Background(), d.PairingCode, d.PollSecret)
	if err != nil {
		return nil, err
	}
	switch st.State {
	case "approved":
		d.Approved = true
		d.TeamID = st.Team
		d.Individual = st.Team == ""
		d.Targets = st.Targets
		if st.Platform == "windows" {
			d.Platform = PlatformWindows
		} else if st.Platform == "macos" {
			d.Platform = PlatformMac
		}
		d.PollSecret = "" // done with it
		if err := s.Cache.store(d); err != nil {
			return nil, err
		}
		return d, nil
	case "denied":
		return nil, fmt.Errorf("the pairing was denied in the dashboard")
	default:
		return nil, fmt.Errorf("the pairing is still pending; approve code %s in your Rotten Apple dev dashboard", d.PairingCode)
	}
}

// Current returns the cached approved device, or ErrNoDevice.
func (s *HTTPDeviceService) Current() (*Device, error) { return s.Cache.Current() }
