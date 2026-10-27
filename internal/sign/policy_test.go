package sign

import (
	"errors"
	"testing"
)

func TestOwnerRole(t *testing.T) {
	owners := []string{"support@infected-nation.com", "grimvirusoffical@gmail.com"}
	if RoleForCert("Support@Infected-Nation.com", true, true, true, owners) != RoleOwner {
		t.Fatal("owner email should fold")
	}
	if RoleForCert("grimvirusoffical@gmail.com", true, true, true, owners) != RoleOwner {
		t.Fatal("second owner")
	}
	if RoleForCert("support@infected-nation.com", true, true, false, owners) != RoleDev {
		t.Fatal("owner without 2FA")
	}
	if RoleForCert("support@infected-nation.com", true, false, true, owners) != RoleDev {
		t.Fatal("owner without idVerified")
	}
	if RoleForCert("support@infected-nation.com", false, true, true, owners) != RoleDev {
		t.Fatal("owner without verified")
	}
	if RoleForCert("dev@example.com", true, true, true, owners) != RoleDev {
		t.Fatal("stranger is not an owner")
	}
	if RoleForCert("support@infected-nation.com", true, true, true, nil) != RoleDev {
		t.Fatal("cert that lists nobody is not an owner cert")
	}
	if RoleFromProfile("support@infected-nation.com", true, true, true) != RoleOwner {
		t.Fatal("profile")
	}
}

func TestPlatformMatrix(t *testing.T) {
	cases := []struct {
		host string
		ok   []string
		no   []string
	}{
		{"darwin", []string{"macos", "ios", "android", "windows", "linux"}, nil},
		{"windows", []string{"windows", "macos", "ios", "linux", "android"}, nil},
		{"linux", []string{"linux", "windows", "android", "macos"}, []string{"ios"}},
	}
	for _, tc := range cases {
		got, err := HostPlatforms(tc.host)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(tc.ok) {
			t.Fatalf("%s: %v", tc.host, got)
		}
		for i := range tc.ok {
			if got[i] != tc.ok[i] {
				t.Fatalf("%s[%d]=%s", tc.host, i, got[i])
			}
		}
		for _, p := range tc.ok {
			if err := Allow(tc.host, p, RoleOwner, false, false, false); err != nil {
				t.Errorf("%s owner without launcher %s: %v", tc.host, p, err)
			}
			if err := Allow(tc.host, p, RoleDev, false, true, true); !errors.Is(err, ErrDevLauncher) {
				t.Errorf("%s dev without launcher %s: %v", tc.host, p, err)
			}
			if err := Allow(tc.host, p, RoleDev, true, true, true); err != nil {
				t.Errorf("%s dev with launcher %s: %v", tc.host, p, err)
			}
			if err := Allow(tc.host, p, RoleOwner, true, true, false); !errors.Is(err, ErrLauncherDown) {
				t.Errorf("%s launcher not running %s: %v", tc.host, p, err)
			}
		}
		for _, p := range tc.no {
			if err := Allow(tc.host, p, RoleOwner, false, false, false); err == nil || !stringsContains(err.Error(), "cannot sign for") {
				t.Errorf("%s should refuse %s: %v", tc.host, p, err)
			}
		}
	}
	if _, err := HostPlatforms("freebsd"); err == nil {
		t.Fatal("freebsd")
	}
	if err := Allow("linux", "mac", RoleOwner, false, false, false); err == nil {
		t.Fatal("mac is not a platform id; the flag spells it macos")
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && contains(s, sub)))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
