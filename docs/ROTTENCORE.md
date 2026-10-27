# RottenCore specification (v0.1.0)

RottenCore is the one installer every Red-XAI app ships with: RedX, Gendragoon, QuickLaunch, Rotten Apple
store apps and anything else Red-XAI LLC publishes for macOS. It has three parts, all on one engine:

| Part | Where | What |
|---|---|---|
| `core/` (Go) | this repo | detection, checksums, trust, install engine (.app, .dmg, .pkg, .zip), installed-app list, updates, uninstall |
| `rottencore` CLI | `cmd/rottencore` | the engine on the command line; `--json` for apps |
| `RottenCoreKit` (Swift package) | `apple/` | typed Swift API over the bundled `rottencore` binary, for apps that embed RottenCore |
| RottenCore Installer.app | `apple/Sources/RottenCoreInstaller` | the standalone SwiftUI app (macOS 12+, universal), dark by default |

Why Go for the engine: the Rotten Apple store and its launcher are Go, the engine is fully testable without
a Mac (the macOS tools sit behind a `Runner` interface with a fake in the tests), and one static universal
binary serves the app, the CLI and every app that embeds it.

## 1. Where an app came from

RottenCore decides the **source** in this order and records how (`detectedBy`):

1. **Embedded manifest** `rottencore.json` (primary). Looked for in
   `App.app/Contents/Resources/rottencore.json`, at the root of a `.dmg` (or in the `.app` inside it), in a
   `.pkg`'s Resources (read with `xar`), at the root of a `.zip` or in its top-level app.
2. **Sidecar manifest** `<file>.rottencore.json` next to the download (the only place that can carry the
   file's own sha256, since a file cannot contain its own hash).
3. **Download origin**: Spotlight's `kMDItemWhereFroms` (the URL a browser saved it from).
   `https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>` means GitHub;
   `<store>/v1/catalog/apps/<id>/download` on the configured store means the store. The quarantine flag
   (`com.apple.quarantine`) is recorded as a signal (the downloading app), never as proof.
4. A `.rarxai` file, or a store attestation with no manifest, means the store.
5. Otherwise the source is `unknown`.

The source only decides **where to check the bytes and where updates come from**. It never decides trust.

## 2. rottencore.json (schema 1)

```json
{
  "schema": 1,
  "appId": "com.redx.app",
  "name": "RedX",
  "version": "0.4.3",
  "source": "github",
  "github": { "owner": "grimvirusoffical-source", "repo": "RedX", "tag": "v0.4.3",
              "asset": "redx-0.4.3-macos-universal.dmg", "assetPattern": "redx-{version}-macos-universal.dmg",
              "sums": "SHA256SUMS" },
  "store": { "url": "https://api.rottenapplestore.org", "listingId": 12 },
  "artifact": { "kind": "dmg", "name": "redx-0.4.3-macos-universal.dmg", "sha256": "<sidecar only>" },
  "install": { "bundle": "RedX.app", "pkg": "RedX.pkg", "pkgIds": ["com.redx.pkg"], "destination": "/Applications" },
  "minMacOS": "12.0",
  "ageRating": "everyone"
}
```

| Field | Rule |
|---|---|
| `schema` | 1 |
| `appId` | reverse-DNS, lower case (the store's rule) |
| `name`, `version` | 1–80 chars; version like `1.2.3`, optional `v`, optional `-suffix` |
| `source` | `store` or `github` (a claim; see §4) |
| `github` | required for `github`: `owner`, `repo`; `tag` (default `v<version>` then `<version>`), `asset` (default the file name), `assetPattern` for updates (`{version}` = tag without `v`), `sums` (default `SHA256SUMS`) |
| `store` | `url` (https origin; default from config, `https://api.rottenapplestore.org`), `listingId` |
| `artifact.sha256` | 64 lower-case hex; only meaningful in a sidecar |
| `install.bundle` / `install.pkg` | which `.app` / `.pkg` to take from a dmg or zip when there is more than one |
| `install.pkgIds` | receipt ids the package installs (RottenCore also detects new receipts) |
| `install.destination` | `/Applications` (default) or `~/Applications` |
| `minMacOS`, `ageRating` | shown and checked (`everyone`, `13+`, `18+`); the store and Red-XAI Accounts enforce age rules |

Unknown fields are refused, so a typo cannot silently drop a setting. Max 64 KB.

## 3. Checking the bytes

Every file (not a bare `.app` folder) is hashed with SHA-256 and compared with every checksum that is known:

* the store attestation (§4),
* the GitHub release's `SHA256SUMS` (fetched over HTTPS from that release; no token is ever sent),
* a sidecar manifest's `artifact.sha256`.

**Any mismatch is a hard refusal**: nothing is installed, whatever the person accepts. No checksum at all is
reported ("no checksum is published for this file") and the file is untrusted.

All downloads are HTTPS only, redirects included (loopback HTTP is allowed only inside the tests), capped
at 4 GiB, written to a `.part` file and renamed when complete.

## 4. Trust

* **Trusted** = the Rotten Apple store vouches for this exact file: a **store attestation** verifies under a
  store public key **pinned in the RottenCore binary**, its `sha256` and `bytes` equal the file, and its
  `appId` equals the manifest's. Trusted apps install with no warning.
* **Everything else is untrusted**: GitHub builds, unknown sources, missing or unverifiable manifests. The app
  shows **"RottenCore doesn't trust this app: it isn't from the Rotten Apple store."** and the Install button
  stays off until the person ticks "I understand the risk"; the CLI needs `--accept-untrusted` (exit 3
  otherwise). The engine enforces it again, so a UI bug cannot skip it.

Not spoofable by writing `"source": "store"`: the claim is ignored without a valid signature (and the reason
says so). Pinned keys come only from code (`core.PinnedStoreKeys`); config files, environment variables and
manifests cannot add one. Tests cover: no pinned key, a foreign key, another app's attestation, another
file's attestation (refused), an edited document, a store review receipt replayed as an attestation (other
signature domain), and a manifest claim with no attestation.

**The attestation** is the store's existing signed-document envelope (`rarxai.Signed`: base64 canonical JSON,
key fingerprint `sha256:<hex>`, Ed25519) signed with the store's existing key (the one that signs review
receipts and the status ticket), under its own domain string `ROTTENCORE-ATTEST-v1\0`:

```json
{ "v": 1, "appId": "...", "version": "...", "build": 7,
  "artifact": { "name": "x.rarxai", "kind": "rarxai|app|dmg|pkg|zip", "sha256": "<hex>", "bytes": 123 },
  "ageRating": "13+", "issuedMs": 0 }
```

Where it comes from: embedded `rottencore.attestation.json`, a sidecar `<file>.rottencore-attestation.json`,
or the store: `GET <store>/v1/catalog/apps/{id}/attestation` (RottenApple PR #1, branch
`rottencore-store-api`). The store also adds `packageSha256`/`packageBytes` to listings and `X-RA-SHA256` to
downloads.

**Status (v0.1.0): `PinnedStoreKeys` is empty.** Red-XAI has not provisioned the production store signing key,
so **no app verifies as store-trusted yet**. The private key is never committed anywhere; the store loads it
from its key file or environment at start; tests use throwaway keys. Pinning the public key is a code change
and a new RottenCore release.

## 5. Store apps (.rarxai) go to the Rotten Apple launcher

Store packages are `.rarxai` (signed manifest, Merkle payload, developer certificate chain, store review
receipt). Their whole lifecycle stays in the Rotten Apple launcher (`ra-launcher`), which already does the
signature and receipt checks, the signed status ticket (revocations), age gating on the store-confirmed
rating, entitlements for paid apps and the splash rules. RottenCore does not re-implement any of that:

* a `.rarxai` file → `ra-launcher [--store URL] install <file>` (found via `ROTTENCORE_RA_LAUNCHER`, `PATH`,
  `/Applications/Rotten Apple.app/Contents/MacOS/ra-launcher`, `/usr/local/bin`, `/opt/homebrew/bin`),
  recorded as `managed: "ra-launcher"`;
* `rottencore install store:<app id>` and the app's **Get** button → open
  `rottenapple://install?app=<id>&store=<origin>` (the launcher's own install sheet);
* update and uninstall of those apps → `ra-launcher update` / `ra-launcher uninstall`.

Store-distributed `.dmg`/`.pkg`/`.zip` files with a store attestation use RottenCore's own engine below.

## 6. Install engine (same for every source)

| Kind | What happens |
|---|---|
| `.app` | `ditto` into /Applications (or ~/Applications); an existing copy is moved aside and put back on any failure |
| `.zip` | `ditto -x -k` into a private temp folder, then as `.app` |
| `.dmg` | `hdiutil attach -nobrowse -readonly -noautoopen` at a private mount point, the `.app` or `.pkg` inside (`install.bundle`/`install.pkg`, or the only one), always detached (`-force` if needed) |
| `.pkg` | `pkgutil --check-signature` (unsigned allowed, a broken signature refused), then `installer -pkg … -target /` as root; new receipts are recorded |

Root is asked for only when needed: `/Applications` not writable, or a `.pkg`. The app uses the standard
macOS administrator dialog (`osascript … with administrator privileges`, arguments quoted), the CLI uses
`sudo`. Code signatures: `codesign -dv`; if signed, `codesign --verify --deep --strict` must pass or the
install is rolled back; `spctl --assess` (Gatekeeper/notarization) is recorded, not required.

## 7. Installed list, updates, uninstall

`~/Library/Application Support/RottenCore/installed.json` (mode 0600, atomic writes, a lock file across
processes) records per app: id, name, version, source, trusted / accepted-risk, kind, file name, sha256,
installed paths, package receipts, GitHub or store reference, age rating, codesign result, dates.

* **Updates**: GitHub apps → `releases/latest` of the recorded repo; the asset by `assetPattern`, else the
  best macOS installer (universal first, same kind as before); the new file goes through §3–§6 again,
  including the untrusted warning. Store apps → the listing's version; the update runs in ra-launcher.
* **Uninstall**: apps go to the Trash (only `.app` folders directly inside an Applications folder);
  packages: a root step (`rottencore pkg-remove <id>`) deletes the files of the receipt, never anything under
  system folders (/System, /bin, /usr except /usr/local, /etc, /var, /Library/Apple …), removes empty
  folders, then `pkgutil --forget`.

## 8. Config, accounts, privacy

`config.json` in the same folder: `storeURL` (default `https://api.rottenapplestore.org`, not live yet;
`ROTTENCORE_STORE_URL` overrides), `githubAPI`, `theme` (`dark` default, `light`, `system`), `accountsIssuer`,
`accountsClientId`. It holds no secrets and cannot add trusted keys.

Sign-in: a hook for **Red-XAI Accounts** (OIDC, authorization code + PKCE S256, discovery at
`/.well-known/openid-configuration`, contract: red-xai-accounts `docs/API.md`). Discovery, the authorize URL
and the code exchange are implemented and tested against a fake provider; the browser round trip is not
wired and sign-in shows **"coming soon"** until the issuer is live and a `rottencore` public client is
registered. A session that already has an access token is used for lifetime signing (§11) by setting
`ROTTENCORE_ACCESS_TOKEN` for that process. The token is not written to the support folder. Age rules
(13 and up) are enforced by Red-XAI Accounts and the store, not by RottenCore.

No telemetry. RottenCore talks only to the store, GitHub (public API; an optional `ROTTENCORE_GITHUB_TOKEN` is sent only to the GitHub API host, only to lift the anonymous rate limit, as CI does) and the account issuer.

## 9. Embedding RottenCore in an app's installer

Ship `rottencore.json` inside the app (and the dmg / pkg Resources), and optionally put
`RottenCore Installer.app` in the dmg. Apps that want to drive it from Swift add the `RottenCoreKit` package
and bundle the `rottencore` binary as `Contents/Resources/rottencore`. Example: `examples/redx/`.

## 10. CLI

```
rottencore inspect <file>
rottencore install <file | github:owner/repo[@tag] | store:<app id>> [--accept-untrusted] [--user] [--yes]
rottencore list | check-updates | update <app id> | uninstall <app id>
rottencore search <words> | info <app id>
rottencore config [--store-url URL] [--accounts-issuer URL] [--theme dark|light|system]
rottencore whoami
rottencore sign --lifetime --with-launcher|--without-launcher --platform macos|ios|android|windows|linux <file>
rottencore agent | agent shutdown
rottencore signin | version
--json  → {"ok":true,"result":…} | {"ok":false,"error":"…","code":"error|usage|untrusted|refused"}
--secrets-stdin  the Red-SecretsXAI password on stdin (one line) for an owner one-shot sign
--via-agent      ask the unlocked signing agent instead of prompting
exit 0 ok, 1 error, 2 usage, 3 untrusted (accept the warning), 4 refused (checksum mismatch)
```

`whoami`, `sign` and `agent` are specified in §11. The password is never an argument.

## 11. Lifetime certificate signing

Owners sign a build with the Red-XAI lifetime certificate. Developers can sign the same matrix only while
the Rotten Apple or Poison Apple launcher is installed and running, and only with the launcher required.
Official OS signing (Developer ID, notarization, Authenticode) is still recommended. This overlay works
either way, including on a build that is already signed.

The Mac app's **Sign** section uses charcoal `#0C0D10`, crimson `#E23B3B` and bone `#ECE8E4`. On an owner
login it offers **Sign with launcher** and **Sign without launcher**, plus the platform picker for this
computer. **Sign without launcher stays disabled for developers**; seeing the launcher only enables
**Sign with launcher**. The app keeps a background signing agent for the login. Leaving the Sign section
does not stop it. Sign-out does.

### Who can sign

An **owner** is an account whose email is `support@infected-nation.com` or `grimvirusoffical@gmail.com`,
with `verified`, `idVerified` and a second factor, and whose email is listed on the lifetime cert
(`owner_emails`). Anyone else with a session is a **developer**.

| Computer | Platforms |
|---|---|
| Mac | macos, ios, android, windows, linux |
| Windows | windows, macos, ios, linux, android |
| Linux | linux, windows, android, macos |

The command spells the Mac platform `macos`. A platform outside that computer's row is refused.

| Role | Launcher | Result |
|---|---|---|
| Owner, verified + 2FA + idVerified | installed and running, or not | `--with-launcher` or `--without-launcher` |
| Owner | not installed or not running | `--without-launcher` only |
| Developer | installed and running | `--with-launcher` only |
| Developer | anything else | refused |

`--with-launcher` sets `launcher_required` and requires the launcher to be installed and running.
`--without-launcher` is owner-only and sets `launcher_required` false.

### Accounts

RottenCore uses the OIDC stub in `core/oidc.go`. The access token stays in memory (`ROTTENCORE_ACCESS_TOKEN`,
or the agent's handshake). It is not logged and not stored.

| Call | When |
|---|---|
| discovery userinfo | every `whoami` and every sign |
| `GET {issuer}/v1/rxa-account` | userinfo omitted `idVerified` / `id_verified`; merged fields are `idVerified` and `idVerifiedMs` |
| `GET {issuer}/v1/rxa-lifetime-cert` | signing and unlocking, `Authorization: Bearer` |

The lifetime-cert document is kind `rxa-lifetime-cert`: `cert_id`, `pubkey` (hex), `private_enc`
(Red-SecretsXAI ciphertext only), `issued`, `owner_emails`, `sig_id_prefix`. `private_enc` is readable only
by an owner session. A non-owner token is not decrypted in this process even if Accounts attaches a
ciphertext. Responses are requested with `Cache-Control: no-store`. A non-200 body is discarded and is not
copied into an error. Unknown fields on the cert are ignored.

### Payload

`internal/sign` is the swap point for the shared signing package. Callers use `Payload`, `Canonical`,
`Sign`, `Verify` and `Sealer`. The cipher is not implemented here.

The signed bytes are canonical JSON with `sig` omitted, field order:

`type`, `sig_id`, `app_id`, `version`, `cert` (`id`, `pubkey`, `issuer`), `hash`, `nonce`, `prev_sig_id`
when present, `platforms`, `launcher_required`.

| Field | Value |
|---|---|
| `type` | `rotten_core_signed` |
| `sig_id` | `sig_id_prefix` plus `_` plus 16 random bytes hex; empty prefix uses `rxa` |
| `app_id`, `version` | from the local `rottencore.json` (or the app bundle). The store and GitHub are not contacted |
| `cert.issuer` | `red-x-accounts-owner` |
| `hash` | lowercase sha256 hex of the file. A directory or `.app` is a sorted regular-file tree: relative path, NUL, contents, NUL |
| `sig` | ed25519 over the canonical JSON, lowercase hex. Stored last |
| `nonce` | 32 random bytes, hex |
| `prev_sig_id` | the previous `sig_id` for this `app_id`, from `sig-chain.json` in the support folder |
| `platforms` | the one `--platform` |
| `launcher_required` | true for `--with-launcher` |

The same cert is used for later versions. Each signature gets a new `sig_id`, `nonce`, `hash` and `version`.
The private key is the hex of a 32-byte seed or a 64-byte Go ed25519 key, decrypted in memory and wiped.
It is checked against `pubkey` before use.

The whole carrier JSON is then sealed with Red-SecretsXAI (password mode) and written to
`<path>.rotten_core_signed` (mode 0600). The plaintext JSON is wiped and is not written. `sig-chain.json`
stores only `app_id` → `sig_id`.

### Red-SecretsXAI

RottenCore calls `red-xai-encrypt` (`encrypt_text` / `decrypt_text`, `mode="password"`) through `python3`.
It does not implement or change the cipher. The password and the payload are length-prefixed frames on
stdin, never arguments and never environment variables. The child environment is limited to `PATH`, `HOME`,
`LANG`, `LC_ALL`, `TMPDIR`, `TMP`, `TEMP`, `SYSTEMROOT` and `RSX_LIB`. If the child's output contains the
password or the payload, the error is the generic "Red-SecretsXAI failed".

### Signing agent

`rottencore agent` is the in-memory unlock used by the Mac app and by developers. The app writes two
frames on stdin (access token, then Red-SecretsXAI password) and does not put either in the agent's
environment. Only an owner session can unlock. The process keeps the key and the password until shutdown,
then wipes both. The socket is `{support}/sign-agent.sock`, mode 0600. When that path does not fit in a unix address (macOS allows 104 bytes including the trailing NUL), it is a short private socket under `/tmp/rc-<hash>/s` instead. One agent answers. Requests are
newline JSON (`status`, `shutdown`, `sign`) and unknown fields are refused without echoing the line.
Every `sign` re-checks the caller's token. A developer may sign only with the launcher required and the
launcher up, using the unlocked owner cert. `rottencore sign --via-agent` (and every developer sign, and
every Sign button) talks to that socket. An owner can still sign once from the command line without the
agent; that prompts on `/dev/tty` or reads `--secrets-stdin`.

Nothing in the CLI JSON, the carrier, the chain file, or a log line is the plaintext private key.
