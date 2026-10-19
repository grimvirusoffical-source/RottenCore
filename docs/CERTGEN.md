# Certificate generator (`rottencore-ca`)

The Red-XAI CA tooling for the ra-core signing chain. It is **real** (it generates keys, issues certs and
builds revocation tickets that Rotten Core verifies), using a **TEST root** until Josh runs the production
root ceremony. See `docs/ROLLOUT-RUNBOOK.md` for the end-to-end ceremony.

## Magnitude tiers
Tier picks the key algorithm and validity by account level (`ca.DefaultTiers`, overridable with `--tiers`):

| tier | algorithm | validity | used for |
|---|---|---|---|
| standard | Ed25519 | 365 d | ordinary developer certs |
| mega | P-384 | 730 d | Mega developers (Josh) |
| owner / admin | P-384 | 730 d | owner / admin certs |
| service | P-384 | 365 d | host update-signer certs |
| issuing | P-384 | 5 y | the ra-core issuing CA |
| root | P-384 | 20 y | the root CA |

`issue` enforces the tier's algorithm, so the requester must generate the matching key type. P-384 is
`ECDSA/SHA-384` (97-byte uncompressed point, 96-byte raw `r||s`, CryptoKit-compatible) and verifies
end-to-end in Rotten Core. The ceremony runbook uses Ed25519 for now (the Poison Apple launcher does not
verify P-384 yet).

## White-noise entropy
Key generation mixes optional noise into the OS CSPRNG; it **never replaces** it (if the OS reader fails,
keygen fails with `ErrNoOSRandom`). Noise sources: CPU jitter (always available) and, with `--mic`, the
microphone (`ffmpeg`/`avfoundation` on macOS, `arecord` elsewhere; skipped if the recorder is missing).
Material is `HKDF-SHA-512(ikm = OS-CSPRNG(64) || SHA-512(noise), salt "ra-core keygen v1", info)`. Each
source runs SP 800-90B-style health tests (repetition count, adaptive proportion); a source that fails is
dropped and the key falls back to the OS CSPRNG alone. **Logged:** source kind, byte count, pass/fail, a
min-entropy estimate. **Never logged:** raw samples or derived bytes.

## Commands
```
rottencore-ca ceremony-root   --out root.cert.json [--keychain --label L] [--alg ed25519|p384] [--mic] [--dir D]
rottencore-ca issuing-csr     --out issuing.csr.json [--keychain --label L] [--alg ...] [--dir D]
rottencore-ca sign-intermediate --req issuing.csr.json --out issuing.bundle.json [--keychain --label rottencore-root] --dir D
rottencore-ca keygen          --alg ed25519|p384 (--out key.json | --keychain --label L) [--mic]
rottencore-ca request         (--key key.json | --keychain --label L) --name N [--kind developer|update-signer|ca] --out req.json
rottencore-ca issue           --dir D --req req.json --dev ID --team T --role developer|owner|admin [--mega] --out bundle.json
rottencore-ca certify-host    --dir D --pub BASE64 [--alg ed25519] --host NAME --team T --role owner --out chain.json
rottencore-ca revoke          --dir D --kind cert|build|app --value V
rottencore-ca root-hex        --dir D     # the root public key as hex, for `rottencore --trust-test-root`
```

## Key storage
- **File store** (default): `--out`/`--dir`, written 0600 JSON through the `certgen.private-key`
  ENCRYPTION-HOOK (no-op today).
- **Keychain store** (`--keychain`, macOS only): the key is a login-Keychain item, encrypted at rest by the
  OS and never copied off the Mac. Used for the root ceremony and developer keys.

## Host update keys
`certify-host` issues an **update-signer** certificate for a Red-XAI Host update key (owner/admin only). The
host keeps its private key; only its public key (as served at `/v1/updates/keys`) is certified. Serve the
returned chain as the `chain` field of each key so Rotten Core can trust it (open question: RedX host does
not serve `chain` yet).

## Revocation
`revoke` adds a cert fingerprint, build or app to the revocation list; ra-core publishes it in the store's
signed status ticket (`GET /v1/status`). Rotten Core's `VerifyFileSignature` returns `revoked` (hard refusal)
for anything on the list.
