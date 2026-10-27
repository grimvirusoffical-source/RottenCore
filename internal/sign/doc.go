// Package sign is RottenCore's lifetime-certificate signing.
//
// It is the internal stand-in for the shared Red-XAI signing module (Grok Bot owns that
// module). Callers should stay on Payload, Canonical, Sign, Verify, and Sealer. Swapping
// this package for the shared module should not make those callers change shape.
//
// Sign covers the canonical JSON of the payload with ed25519. The private key is only an
// argument; this package never logs it and never writes it. After signing, the whole
// carrier is sealed by calling Red-SecretsXAI (red-xai-encrypt). The cipher is not
// reimplemented here.
package sign
