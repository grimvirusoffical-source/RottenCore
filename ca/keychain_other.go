//go:build !darwin

package ca

import (
	"errors"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// KeychainStore is only available on macOS; on other systems its methods return an error so the ceremony
// tooling compiles everywhere but the root key can only be made and kept on Josh's Mac.
// TrustedApps mirrors the darwin field so callers can set ROTTEN_KEYCHAIN_TRUST on every OS.
type KeychainStore struct {
	Service     string
	TrustedApps []string
}

func (KeychainStore) Kind() string { return "macOS Keychain (unavailable on this OS)" }

var errNoKeychain = errors.New("the macOS Keychain is only available on macOS; run the ceremony on Josh's Mac")

func (KeychainStore) Put(string, core.Signer) error   { return errNoKeychain }
func (KeychainStore) Get(string) (core.Signer, error) { return nil, errNoKeychain }
