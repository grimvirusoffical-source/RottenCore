package main

import (
	"context"
	"errors"
	"fmt"
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

func deviceService() *devhub.LocalDeviceService {
	return &devhub.LocalDeviceService{Path: filepath.Join(core.SupportDir(), "devhub", "device.json")}
}

func contextProvider() devhub.LocalContextProvider {
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
		key, _, err := ca.GenerateKey(ctx, &ca.Mixer{}, core.AlgEd25519, "device")
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
