//go:build darwin

package ca

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// KeychainStore keeps raw private-key material in the macOS login Keychain (encrypted at rest by the OS).
// Service is the generic-password service name; each key is one item keyed by its label (account). The key
// bytes never touch disk in the clear and are never copied off the Mac. Alg is stored alongside so the
// key reloads as the right type.
//
// This is a software-key store: the bytes exist in Keychain, not in the Secure Enclave (the Enclave only
// holds P-256 keys, which these tiers do not use). For the production root, the runbook also calls for an
// offline USB backup; Keychain is the live copy.
type KeychainStore struct{ Service string }

func (KeychainStore) Kind() string { return "macOS Keychain" }

func (s KeychainStore) service() string {
	if s.Service != "" {
		return s.Service
	}
	return "com.redx.rottencore.ca"
}

func (s KeychainStore) Put(label string, k core.Signer) error {
	if _, err := s.Get(label); err == nil {
		return fmt.Errorf("a key labelled %q already exists in the Keychain; refusing to overwrite", label)
	}
	blob := k.Alg() + ":" + hex.EncodeToString(privBytes(k))
	// -U would update; we never pass it, so an existing item is kept and this fails instead.
	cmd := exec.Command("security", "add-generic-password", "-a", label, "-s", s.service(), "-w", blob, "-T", "", "-D", "RottenCore CA private key")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security add-generic-password: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func (s KeychainStore) Get(label string) (core.Signer, error) {
	out, err := exec.Command("security", "find-generic-password", "-a", label, "-s", s.service(), "-w").Output()
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
