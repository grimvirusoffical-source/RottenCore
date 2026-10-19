package devhub

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDevicePlatformTargets(t *testing.T) {
	if !PlatformMac.Allows(TargetMacArm64) || !PlatformMac.Allows(TargetIOS) || PlatformMac.Allows(TargetWindows) || PlatformMac.Allows(TargetAndroid) {
		t.Fatal("mac device targets")
	}
	if !PlatformWindows.Allows(TargetWindows) || !PlatformWindows.Allows(TargetAndroid) || PlatformWindows.Allows(TargetMacArm64) || PlatformWindows.Allows(TargetIOS) {
		t.Fatal("windows device targets")
	}
	// linux and extensions are allowed on either device
	for _, p := range []Platform{PlatformMac, PlatformWindows} {
		if !p.Allows(TargetLinux) || !p.Allows(TargetExtensions) {
			t.Fatalf("%s should allow linux/extensions", p)
		}
	}
}

func TestLocalDeviceRegistrationFlow(t *testing.T) {
	s := &LocalDeviceService{Path: filepath.Join(t.TempDir(), "device.json"), now: func() time.Time { return time.Unix(1700000000, 0) }}
	if _, err := s.Current(); err != ErrNoDevice {
		t.Fatal("expected no device")
	}
	d, err := s.StartRegistration(PlatformMac, []byte("pub"))
	if err != nil || d.Approved || d.PairingCode == "" || d.Platform != PlatformMac {
		t.Fatalf("register: %+v %v", d, err)
	}
	// not approved yet
	if _, err := s.Current(); err != ErrNoDevice {
		t.Fatal("unapproved device is current")
	}
	if _, err := s.Approve(d.ID, "T-josh", false); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Current()
	if err != nil || !cur.Approved || cur.TeamID != "T-josh" || cur.Platform != PlatformMac {
		t.Fatalf("current: %+v %v", cur, err)
	}
}

func TestBuildKeyAndSDKGating(t *testing.T) {
	if (&BuildContext{}).RequireBuildKey() != ErrNoBuildKey {
		t.Fatal("empty key should error with ErrNoBuildKey")
	}
	c := &BuildContext{Role: "developer", BuildKey: "ra_sk_x", TeamID: "T-josh",
		SDKs: SDKSelection{Selected: []string{"analytics", "updates"}, Unlocked: []string{"analytics", "updates", "corepay"}}}
	if err := c.RequireBuildKey(); err != nil {
		t.Fatal(err)
	}
	// selected+unlocked passes
	out, err := c.ValidateSDKs([]string{"analytics", "analytics", "updates"})
	if err != nil || len(out) != 2 {
		t.Fatalf("valid sdks: %v %v", out, err)
	}
	// selected but not unlocked (level) fails
	if _, err := c.ValidateSDKs([]string{"corepay"}); err == nil {
		t.Fatal("corepay not selected should fail")
	}
	// unlocked but not selected fails
	c.SDKs.Selected = append(c.SDKs.Selected, "corepay")
	if _, err := c.ValidateSDKs([]string{"corepay"}); err != nil {
		t.Fatalf("now selected+unlocked: %v", err)
	}
	if _, err := c.ValidateSDKs([]string{"ai.gateway"}); err == nil {
		t.Fatal("unselected sdk should fail")
	}
	// owners and admins are exempt
	owner := &BuildContext{Role: "owner", BuildKey: "ra_sk_o"}
	if out, err := owner.ValidateSDKs([]string{"anything", "realmoney"}); err != nil || len(out) != 2 || !owner.Exempt() {
		t.Fatalf("owner exempt: %v %v", out, err)
	}
	if owner.AccountLabel() != "individual account" {
		t.Fatal("owner label")
	}
}
