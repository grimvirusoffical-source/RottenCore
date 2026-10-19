//go:build darwin

package ca

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// KeychainStore keeps raw private-key material in the macOS login Keychain (encrypted at rest by the OS).
// Service is the generic-password service name; each key is one item keyed by its label (account). The key
// bytes never touch disk in the clear and are never copied off the Mac. Alg is stored alongside so the
// key reloads as the right type.
//
// Put feeds `security -i` over stdin so the private-key blob never appears in process argv (visible to
// `ps`). Get uses `/usr/bin/security find-generic-password -w`, which prints the secret on stdout only,
// into this process.
//
// Access control (QA F2): because every read is performed by /usr/bin/security, the item ACL sees
// `security` as the accessing application. Listing our binaries with -T (TrustedApps) therefore does NOT
// gate or authorise our reads, and these items are NOT non-exportable: anything that can run `security`
// as Josh and get a click on "Allow" can read them. The protection is the per-read GUI prompt. The
// rollout therefore runs from Terminal on the Mac (never SSH) and Josh clicks "Allow" for each prompt and
// NEVER "Always Allow" (that would add `security` to the ACL and let any process read the key silently).
// Empty TrustedApps writes -T "" (no app pre-authorised: every read prompts), which is what the rollout
// uses. A Security.framework (cgo) build would make our binary the accessor; it cannot be cross-built from
// the Linux box (no macOS SDK/toolchain), so it is future work.
//
// This is a software-key store: the bytes exist in Keychain, not in the Secure Enclave (the Enclave only
// holds P-256 keys, which these tiers do not use). For the production root, the runbook also calls for an
// offline USB backup; Keychain is the live copy.
type KeychainStore struct {
	Service     string
	TrustedApps []string // absolute paths for -T; see the F2 note above (ineffective while reads go through security)
}

func (KeychainStore) Kind() string { return "macOS Keychain" }

func (s KeychainStore) service() string {
	if s.Service != "" {
		return s.Service
	}
	return "com.redx.rottencore.ca"
}

// safeKeychainToken rejects labels/services that could break the interactive security command line.
var safeKeychainToken = regexp.MustCompile(`^[A-Za-z0-9._@+/-]+$`)

func (s KeychainStore) Put(label string, k core.Signer) error {
	if !safeKeychainToken.MatchString(label) {
		return fmt.Errorf("keychain label %q has unsafe characters", label)
	}
	svc := s.service()
	if !safeKeychainToken.MatchString(svc) {
		return fmt.Errorf("keychain service %q has unsafe characters", svc)
	}
	if _, err := s.Get(label); err == nil {
		return fmt.Errorf("a key labelled %q already exists in the Keychain; refusing to overwrite", label)
	}
	blob := k.Alg() + ":" + hex.EncodeToString(privBytes(k))
	// Interactive mode: the add-generic-password line is read from stdin. argv is only ["security","-i"],
	// so the private-key hex never appears in process arguments or the environment.
	trust := ""
	for _, app := range s.TrustedApps {
		app = strings.TrimSpace(app)
		if app == "" {
			continue
		}
		if !filepath.IsAbs(app) || !safeKeychainToken.MatchString(app) {
			return fmt.Errorf("keychain TrustedApps entry %q must be an absolute path without spaces or shell characters", app)
		}
		// Quote for the interactive security line; paths are absolute and should not contain spaces
		// that break -T (caller must use paths without spaces, e.g. /Users/.../bin/rottencore).
		trust += fmt.Sprintf(" -T %s", app)
	}
	if trust == "" {
		trust = ` -T ""` // no apps trusted — Get may prompt (fails over SSH)
	}
	line := fmt.Sprintf("add-generic-password -a %s -s %s -w %s%s -D RottenCore\\ CA\\ private\\ key\n", label, svc, blob, trust)
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(line)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security -i add-generic-password: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func (s KeychainStore) Get(label string) (core.Signer, error) {
	if !safeKeychainToken.MatchString(label) {
		return nil, fmt.Errorf("keychain label %q has unsafe characters", label)
	}
	// -w prints the password on stdout only; label and service are not secret.
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-a", label, "-s", s.service(), "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("no Keychain key labelled %q (%v)", label, err)
	}
	blob := strings.TrimSpace(string(out))
	i := strings.IndexByte(blob, ':')
	if i < 0 {
		return nil, fmt.Errorf("the Keychain item %q is not a RottenCore key", label)
	}
	raw, err := hex.DecodeString(blob[i+1:])
	if err != nil {
		return nil, err
	}
	return signerFromPriv(blob[:i], raw)
}

// Has reports whether an item exists, reading attributes only (no -w), so it never triggers an ACL prompt.
func (s KeychainStore) Has(label string) bool {
	if !safeKeychainToken.MatchString(label) {
		return false
	}
	return exec.Command("/usr/bin/security", "find-generic-password", "-a", label, "-s", s.service()).Run() == nil
}

// GetSecret returns a raw generic-password secret (e.g. the build API key under account ra-build-api-key).
// The value comes back on stdout into this process only.
func (s KeychainStore) GetSecret(label string) (string, error) {
	if !safeKeychainToken.MatchString(label) {
		return "", fmt.Errorf("keychain label %q has unsafe characters", label)
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-a", label, "-s", s.service(), "-w").Output()
	if err != nil {
		return "", fmt.Errorf("no Keychain secret labelled %q (%v)", label, err)
	}
	return strings.TrimSpace(string(out)), nil
}
