// Package seal is the single hook point for encrypting and decrypting Rotten Core and Poison Apple data.
//
// ROTTEN CORE DOES NOT ENCRYPT ANYTHING. Josh has a separate encrypter/decoder being built; it plugs in
// by calling Register with its own Sealer. Until then Current() is Noop, which returns every input
// unchanged, so behaviour and bytes are exactly as if the hook were not there.
//
// Every place that will encode or decode data calls Current().Seal or Current().Open and is marked with
// the comment tag "ENCRYPTION-HOOK:" followed by the hook id. docs/ENCRYPTION-HOOKS.md lists all of them.
//
// Rules for implementers:
//   - Public certificates, certificate chains, signatures, .rasig files, SHA256SUMS and the store's
//     revocation tickets are NEVER passed through a Sealer: signing and verification work on plain bytes.
//   - Where a hook sits before hashing/signing (builder), the signature covers the bytes the Sealer
//     returned, so whatever is published is exactly what was signed.
//   - aad binds the sealed bytes to their context (for example "cert:<fingerprint>" or
//     "artifact:<filename>"); an implementation must authenticate it.
package seal

import "sync"

// Purpose says what is being sealed; a Sealer may treat purposes differently.
type Purpose string

// Purposes, one per hook family.
const (
	PrivateKey      Purpose = "private-key"      // CA / developer / host private keys written by the cert generator
	CertBundle      Purpose = "cert-bundle"      // certificate + private key bundles
	BuildArtifact   Purpose = "build-artifact"   // builder packaging output
	Upload          Purpose = "upload"           // uploader request bodies
	InstallPayload  Purpose = "install-payload"  // installer: downloaded/opened payloads
	UpdatePayload   Purpose = "update-payload"   // updater: downloaded update artifacts
	LauncherPackage Purpose = "launcher-package" // Poison Apple package installs
)

// Sealer encrypts (Seal) and decrypts (Open). ID names the implementation and version, e.g.
// "redxai-encrypter-v1"; it is recorded next to sealed data so it can be opened later.
type Sealer interface {
	ID() string
	Seal(p Purpose, plaintext, aad []byte) ([]byte, error)
	Open(p Purpose, sealed, aad []byte) ([]byte, error)
}

// Noop is the default: no encryption, bytes pass through unchanged.
type Noop struct{}

// NoopID is Noop's ID.
const NoopID = "none"

func (Noop) ID() string                                  { return NoopID }
func (Noop) Seal(_ Purpose, b, _ []byte) ([]byte, error) { return b, nil }
func (Noop) Open(_ Purpose, b, _ []byte) ([]byte, error) { return b, nil }

var (
	mu      sync.RWMutex
	current Sealer = Noop{}
)

// Register installs the encrypter/decoder. Passing nil restores Noop.
func Register(s Sealer) {
	mu.Lock()
	defer mu.Unlock()
	if s == nil {
		s = Noop{}
	}
	current = s
}

// Current is the Sealer in force (Noop unless something registered one).
func Current() Sealer {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Active reports whether real encryption is plugged in.
func Active() bool { return Current().ID() != NoopID }
