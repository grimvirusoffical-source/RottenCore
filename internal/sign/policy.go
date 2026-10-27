package sign

import (
	"errors"
	"fmt"
	"strings"
)

// Roles. An owner is a verified account with 2FA and idVerified whose email is one of
// the Red-XAI owner addresses and is listed on the lifetime cert. Everyone else signed
// in is a developer: they may sign only while the launcher is installed and running.
const (
	RoleOwner = "owner"
	RoleDev   = "dev"
)

// OwnerEmails are the only accounts that can unlock the lifetime certificate.
var OwnerEmails = []string{
	"support@infected-nation.com",
	"grimvirusoffical@gmail.com",
}

// ErrDevLauncher is returned when a developer tries to sign without the launcher.
var ErrDevLauncher = errors.New("developers can sign only while the Rotten Apple launcher is installed and running")

// ErrLauncherDown is returned when a signature requires the launcher and it is not up.
var ErrLauncherDown = errors.New("the Rotten Apple launcher has to be installed and running")

// IsOwnerEmail reports whether email is one of OwnerEmails.
func IsOwnerEmail(email string) bool {
	email = strings.TrimSpace(email)
	for _, o := range OwnerEmails {
		if strings.EqualFold(o, email) {
			return true
		}
	}
	return false
}

// Listed reports whether email is on the certificate's owner_emails.
// An empty list is not an owner list: the cert has to name the account.
func Listed(email string, owners []string) bool {
	if len(owners) == 0 {
		return false
	}
	email = strings.TrimSpace(email)
	for _, o := range owners {
		if strings.EqualFold(strings.TrimSpace(o), email) {
			return true
		}
	}
	return false
}

// RoleFromProfile classifies a signed-in account before the cert document is required.
// verified is the account's verified flag (email_verified), separate from idVerified.
func RoleFromProfile(email string, verified, idVerified, mfa bool) string {
	if IsOwnerEmail(email) && verified && idVerified && mfa {
		return RoleOwner
	}
	return RoleDev
}

// RoleForCert is the signing role. The profile has to be an owner and the cert has to
// list that same email, or the account is treated as a developer.
func RoleForCert(email string, verified, idVerified, mfa bool, certOwners []string) string {
	if RoleFromProfile(email, verified, idVerified, mfa) == RoleOwner && Listed(email, certOwners) {
		return RoleOwner
	}
	return RoleDev
}

// ValidPlatform reports whether p is a platform the sign command accepts.
func ValidPlatform(p string) bool {
	switch p {
	case "macos", "ios", "android", "windows", "linux":
		return true
	default:
		return false
	}
}

// HostPlatforms is the platform matrix for the computer doing the signing.
//
//	darwin  → macos, ios, android, windows, linux
//	windows → windows, macos, ios, linux, android
//	linux   → linux, windows, android, macos
//
// The spec writes "mac" for the Windows and Linux rows; the command line spells that macos.
func HostPlatforms(goos string) ([]string, error) {
	var src []string
	switch goos {
	case "darwin":
		src = []string{"macos", "ios", "android", "windows", "linux"}
	case "windows":
		src = []string{"windows", "macos", "ios", "linux", "android"}
	case "linux":
		src = []string{"linux", "windows", "android", "macos"}
	default:
		return nil, fmt.Errorf("lifetime signing is not available on %s", goos)
	}
	out := make([]string, len(src))
	copy(out, src)
	return out, nil
}

// Allow decides whether this computer and role may produce the signature.
// withLauncher means the signature sets launcher_required.
func Allow(goos, platform, role string, withLauncher, installed, running bool) error {
	if !ValidPlatform(platform) {
		return errors.New("platform must be macos, ios, android, windows or linux")
	}
	ok, err := HostPlatforms(goos)
	if err != nil {
		return err
	}
	found := false
	for _, p := range ok {
		if p == platform {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("this computer cannot sign for %s", platform)
	}
	if withLauncher {
		if !installed || !running {
			return ErrLauncherDown
		}
		return nil
	}
	if role != RoleOwner {
		return ErrDevLauncher
	}
	return nil
}
