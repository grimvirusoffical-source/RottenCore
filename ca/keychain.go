package ca

import (
	"path/filepath"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

// KeyStore is where a private key lives. FileStore writes a JSON key file (the box, a server, a USB drive);
// KeychainStore (macOS only) keeps the key in the login Keychain, which encrypts it at rest and never lets
// it leave the Mac. The root ceremony and Mega developer-key generation use KeychainStore on Josh's Mac so
// the private key is made and stored where it will live and is never copied to the box or the server.
type KeyStore interface {
	// Put stores a freshly generated signer under a label. It must refuse to overwrite an existing key.
	Put(label string, k core.Signer) error
	// Get loads a signer by label.
	Get(label string) (core.Signer, error)
	// Kind names the store for a runbook ("file" or "macOS Keychain").
	Kind() string
}

// FileStore writes keys as 0600 JSON files in Dir (label -> <Dir>/<label>.key.json).
type FileStore struct{ Dir string }

func (f FileStore) Kind() string { return "file" }

func (f FileStore) path(label string) string { return filepath.Join(f.Dir, label+".key.json") }

func (f FileStore) Put(label string, k core.Signer) error { return WriteKey(f.path(label), k) }

func (f FileStore) Get(label string) (core.Signer, error) { return ReadKey(f.path(label)) }
