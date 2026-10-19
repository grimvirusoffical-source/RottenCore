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
registered. Age rules (13 and up) are enforced by Red-XAI Accounts and the store, not by RottenCore.

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
rottencore signin | version
--json  → {"ok":true,"result":…} | {"ok":false,"error":"…","code":"error|usage|untrusted|refused"}
exit 0 ok, 1 error, 2 usage, 3 untrusted (accept the warning), 4 refused (checksum mismatch)
```
