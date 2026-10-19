# Encryption hooks

**Rotten Core does not encrypt anything.** Every place that will one day encode or decode data goes through
`package seal` instead of calling a cipher directly. The default `Sealer` is `Noop` (id `"none"`): it returns
its input unchanged, so with nothing registered the bytes on disk and on the wire are exactly what they would
be with no hook at all. Josh's separate encrypter/decoder plugs in later by calling `seal.Register(...)`.

Each call site carries the comment tag `// ENCRYPTION-HOOK: <id>` so every hook is greppable:

```
rg "ENCRYPTION-HOOK"
```

## Rules for an implementer
- Public certificates, certificate **chains**, signatures, `.rasig` files, `SHA256SUMS` and the store's
  revocation **status tickets** are never sealed — signing and verification run on plain bytes.
- Where a hook sits **before** hashing or signing (the builder), the signature covers the bytes the `Sealer`
  returned, so what is published is exactly what was signed.
- `aad` binds sealed bytes to their context (e.g. `key:<fingerprint>`, `artifact:<filename>`); a real
  `Sealer` must authenticate it.
- `KeyFile` / `CertBundle` record the sealer id that wrote them; reading refuses a file sealed by a different
  sealer than the one currently registered.

## Hook sites

### Implemented (live in code today, no-op)
| id | purpose (`seal.Purpose`) | where | what passes through |
|---|---|---|---|
| `certgen.private-key` | `PrivateKey` | `ca.WriteKey` | a CA / developer / host private key before it is written 0600 |
| `certgen.private-key-open` | `PrivateKey` | `ca.ReadKey` | the same bytes after reading |
| `certgen.cert-bundle` | `CertBundle` | `ca.WriteBundle` | a cert-bundle file (the chain alone stays plain elsewhere) |
| `certgen.cert-bundle-open` | `CertBundle` | `ca.ReadBundle` | the same bundle after reading |
| `builder.package` | `BuildArtifact` | `builder` packaging (`sealCopy`) | each built artifact before it is hashed, signed (`.rasig`) and uploaded |

The macOS **Keychain** key store (`ca.KeychainStore`) is a second at-rest protection for private keys and is
independent of this hook: the OS encrypts Keychain items. The seal hook still runs for keys written to files.

### Planned (reserved `seal.Purpose`, call sites land with their packages)
| id | purpose | where (coming) |
|---|---|---|
| `uploader.body` | `Upload` | the uploader, before each chunk leaves for a store |
| `installer.payload` | `InstallPayload` | the installer, around downloaded/opened payloads |
| `updater.payload` | `UpdatePayload` | the updater, around downloaded update artifacts |
| `launcher.package-install` | `LauncherPackage` | Poison Apple, around signed dependency package installs |

Until those packages exist the purposes are defined in `seal/seal.go` so the ids are stable.
