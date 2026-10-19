package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// Dev-account flags.
var (
	devTeam       string
	devIndividual bool
)

// Dev-hub wiring: when RA_DEVHUB_URL (and, for key routes, RA_API_KEY) are set, Rotten Core talks to the
// real store API (docs/DEV_HUB_API.md); otherwise it uses the local file-backed stand-ins. Both sit behind
// the DeviceService / ContextProvider interfaces, so the rest of the CLI does not change (docs/DEV_HUB.md).
func devhubURL() string { return envOr("RA_DEVHUB_URL", "") }
func apiKey() string    { return envOr("RA_API_KEY", "") }

func localDevice() *devhub.LocalDeviceService {
	return &devhub.LocalDeviceService{Path: filepath.Join(core.SupportDir(), "devhub", "device.json")}
}

// deviceKeyPath is the persistent Ed25519 device key (never a build key; never leaves the machine).
func deviceKeyPath() string { return filepath.Join(core.SupportDir(), "devhub", "device.key") }

// loadOrCreateDeviceKey returns this machine's device signing key, creating it on first use.
func loadOrCreateDeviceKey(ctx context.Context) (core.Signer, error) {
	path := deviceKeyPath()
	if _, err := os.Stat(path); err == nil {
		return ca.ReadKey(path)
	}
	k, _, err := ca.GenerateKey(ctx, &ca.Mixer{}, core.AlgEd25519, "device")
	if err != nil {
		return nil, err
	}
	if err := ca.WriteKey(path, k); err != nil {
		return nil, err
	}
	return k, nil
}

// devhubClient builds the HTTP client. When withDevice, it loads the persistent device key for proofs.
func devhubClient(ctx context.Context, withDevice bool) (*devhub.Client, error) {
	plat, err := devhub.DevicePlatform()
	if err != nil {
		plat = devhub.PlatformMac // reads (context) do not depend on the platform
	}
	c := &devhub.Client{BaseURL: devhubURL(), APIKey: apiKey(), Platform: plat}
	if withDevice {
		k, err := loadOrCreateDeviceKey(ctx)
		if err != nil {
			return nil, err
		}
		dk, ok := k.(devhub.DeviceKey)
		if !ok {
			return nil, errors.New("device key is not an Ed25519 signing key")
		}
		c.Device = dk
	}
	return c, nil
}

func deviceService() devhub.DeviceService {
	if devhubURL() != "" {
		if c, err := devhubClient(context.Background(), true); err == nil {
			return &devhub.HTTPDeviceService{Client: c, Cache: localDevice(), Name: "Rotten Core device"}
		}
	}
	return localDevice()
}

func contextProvider() devhub.ContextProvider {
	if devhubURL() != "" && apiKey() != "" {
		if c, err := devhubClient(context.Background(), false); err == nil {
			return c
		}
	}
	return devhub.LocalContextProvider{Path: filepath.Join(core.SupportDir(), "devhub", "context.json")}
}

// buildContext loads the dev-hub build context and attaches the current approved device. It returns nil (no
// context, local build) when neither a context file nor a device exists; it returns devhub.ErrNoBuildKey
// when a context exists without a build API key.
func buildContext() (*devhub.BuildContext, error) {
	c, err := contextProvider().Context()
	if err != nil {
		if errors.Is(err, devhub.ErrNoBuildKey) {
			return nil, nil // no context configured: a plain local build
		}
		return nil, err
	}
	if d, derr := deviceService().Current(); derr == nil {
		c.Device = d
	}
	return c, nil
}

// runDevice handles `rottencore device ...`. Nothing here touches a real store; approval is a local stand-in
// until the dev-hub API is live (docs/DEV_HUB.md).
func runDevice(ctx context.Context, cmd string, rest []string) bool {
	if cmd != "device" {
		return false
	}
	need(rest, 1)
	svc := deviceService()
	switch rest[0] {
	case "register":
		plat, err := devhub.DevicePlatform()
		check(err)
		key, err := loadOrCreateDeviceKey(ctx)
		check(err)
		d, err := svc.StartRegistration(plat, key.Public())
		check(err)
		out(d, func() {
			fmt.Printf("Device registration started (%s).\n", plat)
			fmt.Printf("Pairing code: %s\n", d.PairingCode)
			fmt.Println("Approve this code in your Rotten Apple dev dashboard to finish. The device key stays on this machine.")
		})
	case "approve":
		// local stand-in for the dashboard approval (the store does this in production)
		if len(rest) < 2 {
			fail(errors.New("usage: rottencore device approve <id> --team T [--individual]"), 2)
		}
		d, err := svc.Approve(rest[1], devTeam, devIndividual)
		check(err)
		out(d, func() { fmt.Printf("device %s approved under %s\n", d.ID, d.PairingLabel()) })
	case "status":
		d, err := svc.Current()
		if err != nil {
			out(map[string]string{"status": "unregistered"}, func() { fmt.Println(devhub.ErrNoDevice.Error()) })
			return true
		}
		out(d, func() {
			fmt.Printf("device %s: %s, approved under %s\n", d.ID, d.Platform, d.PairingLabel())
			fmt.Printf("may build: %v\n", devhub.TargetsFor(d.Platform))
		})
	default:
		fail(errors.New("usage: rottencore device register|approve|status"), 2)
	}
	return true
}
