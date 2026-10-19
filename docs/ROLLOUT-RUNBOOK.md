# Rollout runbook — root ceremony and signing

Step-by-step commands for standing up the Red-XAI signing chain and signing a release. **Josh confirmed the
live signed rollout (2026-10-19).** QA Dev runs the Mac steps on xlr1-mac via Tailscale using
`/workspace/rollout/mac-sign.sh`. The box then publishes with `/workspace/rollout/publish.sh` after the
signed files are copied back. Do **not** modify any GitHub release until the Mac ceremony has finished and
the public root fingerprint is recorded.

## Phased Mac ceremony (server-hosted issuing CA)

The **issuing CA private key lives on ra-core**, not the Mac. Grok Bot runs `issuing-csr` on the
server and drops `issuing.csr.json` for the Mac.

1. `./mac-sign.sh root` — production root in Keychain; sign the CSR → `issuing.bundle.json` + `root.cert.json`
2. Load the bundle on the server; confirm `GET /v1/devhub/ca/chain` shows `issuing:true`
3. `./mac-sign.sh pair` runs `rottencore devhub-pair`. It generates the device and Mega keys in-process into the Keychain, pairs via `/v1/devhub/pairings`, gets the Mega cert from `/certs`, and requires an exact subject devId/teamId
4. `./mac-sign.sh sign` — latest-only sign → staging → tarball
5. Box verifies sha256; `./mac-cleanup.sh --confirm <sha256>` (required form)

**Run the phases in Terminal on the Mac and click "Allow", never "Always Allow" (QA F2).** Keychain reads
go through `/usr/bin/security`, so `-T` trust lists cannot single out our binaries and the items are not
non-exportable. The per-read prompt is the control, and the scripts refuse to run over SSH.
`ROTTEN_KEYCHAIN_TRUST` is no longer set by the rollout. `sign` reads josh-mega once (`rottencore sign-batch`).
`pair` runs entirely in Go (`rottencore devhub-pair`). Clients send `X-RA-Launcher: 0.2.0`.

See `scripts/rollout/QA-README.md`.

## Box-side scripts (Josh plan 2026-10-19 21:06 UTC)

Canonical copies for QA live under `/workspace/rollout/` and are also committed in
`scripts/rollout/`.

- **Latest only:** inventory and `mac-sign.sh` cover the newest *published* release per
  repo. Newer drafts are flagged but not signed (unless the repo has only drafts).
- **No Mac copies:** signed files go to a temporary staging dir, packed into
  `rottencore-signed.tgz`. QA runs `mac-cleanup.sh` only after the box verifies that
  tarball's sha256. Keychain keys stay.
- **Mega subject ids:** `mac-sign.sh` requires `ROTTEN_DEV_ID` and `ROTTEN_TEAM_ID`
  (`A<accountId>` / `T<teamId>` from the production ra-core store, printed by `ra-core account-status` as certDevId / certTeamId; not Red-XAI Accounts ids). It refuses to run if unset. Keygen failures stop the script;
  existing Keychain labels are detected with `security find-generic-password` (no `|| true`).
- **Older → draft:** after the latest release's assets are replaced, `publish.sh` converts
  every other release in those repos to a draft (tags kept) when backups under
  `/workspace/release-backups` fully match. `restore.sh --undraft` reverses that.

See `scripts/rollout/QA-README.md` for the exact Mac and box commands.


## What this sets up
```
Red-XAI Root (Josh's Mac, Keychain, offline)          <-- private key never leaves the Mac
   └─ signs CSR of ──> ra-core Issuing CA (server)     <-- issuing key generated and kept on the server
          └─ issues ──> Mega developer cert (Josh's Mac) <-- developer key generated and kept on the Mac
                 └─ signs ──> app/release artifacts (.rasig)
```

## Key custody (decision)
- The **root private key** is generated on **Josh's Mac** and stored **encrypted in the macOS Keychain**. It
  is **never** copied to the box or the ra-core server. Later it is moved to an **offline USB drive with a
  backup** (two copies kept apart); the Mac copy can then be retired.
- Only the **public root certificate** is exported and pinned in Rotten Core / Poison Apple.
- The **issuing CA key** for tonight's ceremony is generated **on Josh's Mac** under Keychain label
  `rottencore-issuing` (the Mac-hosted option). Only its **public bundle** later gets loaded into ra-core
  through the runbook process (root-owned 0600 files, values via stdin). The long-term plan still moves the
  issuing key onto the ra-core server; tonight we keep it on the Mac so signing can finish without server
  writes.
- Developer keys (including Josh's Mega key) are generated **on the developer's Mac**; only a **CSR** goes to
  the issuing CA.

## Algorithm choice
Use **Ed25519** for the root and issuing ceremony keys for this first rollout. Rotten Core verifies **P-384**
cert v2 end-to-end for the installer/updater path, but the **Poison Apple launcher's rarxai verifier does not
accept P-384 yet**, so Ed25519 keeps every verifier (including the launcher) able to check the chain. Move the
higher tiers to P-384 once the launcher verifies it end-to-end.

The tool is `rottencore-ca` (`go build ./cmd/rottencore-ca`). Health of the entropy mixer is printed as JSON
to stderr and appended to `<dir>/audit.log`; raw samples are never logged.

---

## 1. Root ceremony — on Josh's Mac, offline
Do this with networking off. `--mic` adds the Mac microphone as an *optional* extra noise source, mixed
through HKDF-SHA-512 with the OS CSPRNG (it never replaces it); omit it to use CPU-jitter noise only.

```sh
# a working directory for public outputs and the audit log (NOT the private key)
mkdir -p ~/redx-ceremony && cd ~/redx-ceremony

# generate the root key INTO the Keychain and export ONLY the public root certificate
rottencore-ca ceremony-root \
  --production \
  --keychain --label rottencore-root \
  --alg ed25519 --mic \
  --dir ~/redx-ceremony \
  --out ~/redx-ceremony/root.cert.json
```
- `--production` makes a real (non-TEST) root. Without it, every issued cert carries `test:true` and
  production verifiers refuse it.
- The private key is now a Keychain item (`service com.redx.rottencore.ca`, account `rottencore-root`). It
  never touched disk in the clear.
- `root.cert.json` is the **public** root certificate — this is what gets pinned (`PinnedCARoots`). Share it;
  it is not secret.
- Back up: export the Keychain item to an **offline USB** and make a second copy. Keep both off the network.

## 2. Issuing CA — on Josh's Mac tonight (Mac-hosted option)
Generate the issuing key in the Mac Keychain and emit only a CSR. The public bundle is loaded into ra-core
later by Grok Bot (root-owned 0600 files, values via stdin).
```sh
rottencore-ca issuing-csr \
  --keychain --label rottencore-issuing \
  --dir ~/redx-ceremony --alg ed25519 \
  --out ~/redx-ceremony/issuing.csr.json
# CSR carries no private key; the key lives in Keychain as rottencore-issuing
```

## 3. Sign the issuing CSR — back on Josh's Mac
```sh
rottencore-ca sign-intermediate \
  --keychain --label rottencore-root \
  --dir ~/redx-ceremony \
  --req ~/redx-ceremony/issuing.csr.json \
  --alg ed25519 \
  --out ~/redx-ceremony/issuing.bundle.json
# return issuing.bundle.json (public certs only) to the server
```
On the server, place `issuing.bundle.json` next to the issuing key as `issuing.bundle.json` and the key as
`issuing.key.json` (or keep using the `rottencore-issuing` Keychain label on a Mac-hosted issuer).

## 4. Mega developer cert — on Josh's Mac
Key generated on the Mac; only a CSR goes to the issuing CA.
```sh
# on Josh's Mac: make the developer key (Keychain) and a CSR
rottencore-ca keygen --keychain --label josh-mega --alg ed25519 --dir ~/redx-ceremony
rottencore-ca request --keychain --label josh-mega --name "Josh Franklinn (Mega)" \
  --out ~/redx-ceremony/josh-mega.csr.json

# on Josh's Mac (issuing CA is Keychain-hosted tonight): issue the Mega cert from the CSR
rottencore-ca issue \
  --keychain --label rottencore-issuing \
  --dir ~/redx-ceremony \
  --req ~/redx-ceremony/josh-mega.csr.json \
  --dev josh --team T-josh --role developer --mega \
  --tiers ~/redx-ceremony/tiers-ed25519.json \
  --out ~/redx-ceremony/josh-mega.bundle.json
```
`tiers-ed25519.json` forces every tier (including Mega) to Ed25519 for tonight so Poison Apple's rarxai
verifier can check the chain. Move Mega/owner/root to P-384 once the launcher verifies P-384 end-to-end.
> To issue the Mega cert as **P-384** instead (once the launcher verifies P-384), use `--alg p384` for both
> `keygen` and `request`; the Mega tier is P-384 by default and `issue` enforces the match.

## 5. Sign a release — the signing device policy
`rottencore sign` detects the host OS and will **refuse** to sign a target that host may not sign:
- **On a Mac:** sign **Mac and iOS** assets here. **Android and Windows** assets are listed as needing a
  **Windows device** — build and sign those on Windows.
- **On a Windows machine:** sign **Windows and Android** assets; **Mac and iOS** assets need a Mac.
- Linux and browser-extension assets may be signed on any host.

```sh
# on Josh's Mac: sign the Mac arm64 disk image
rottencore sign ./out/quicklaunch-1.0.0-beta-macos-arm64.dmg \
  --keychain --label josh-mega \
  --bundle ~/redx-ceremony/josh-mega.bundle.json \
  --app com.redx.quicklaunch --app-version 1.0.0
# Mega private key stays in Keychain; writes .rasig and regenerates SHA256SUMS
```
- Where a container format can carry the signature inside the file, `rottencore sign` embeds it; no Rotten
  Core format supports that yet (an embedded signature cannot cover the bytes of the file that contains it),
  so a detached **`.rasig`** sidecar is written and **`SHA256SUMS`** is regenerated.
- Trying to sign an Android or Windows asset on the Mac prints, e.g.:
  `android assets must be built and signed on a Windows device, not on this Mac host` (exit 4).

## 6. Whole-project build (optional)
`rottencore build <request.json>` builds every target the **current host** may sign, in order, labels and
names each output (e.g. `QuickLaunch Beta 1.0.0 (Mac, M1 chip)` → `quicklaunch-1.0.0-beta-macos-arm64.dmg`),
signs each `.rasig`, writes `SHA256SUMS`, and lists the deferred targets with the device each one needs.

## Pin the public root
Once the **production** (non-TEST) root exists, add its public key to `core.PinnedCARoots` and the store
public key stays pinned in `core.PinnedStoreKeys`. Until then, developers and QA can trust a TEST root for a
run with `rottencore --trust-test-root <hex>` (results are labelled TEST and never count as production).

## Tonight's scripts
- `/workspace/rollout/mac-sign.sh` — QA runs this on Josh's Mac over Tailscale (ceremony + sign every Mac/iOS/Linux/extension asset).
- `/workspace/rollout/publish.sh` — box publishes the signed copies back to GitHub after they land in `/workspace/rollout/signed/`.
- `/workspace/rollout/restore.sh` — puts the `/workspace/release-backups/` originals back if something goes wrong.

## Still do NOT
- load the issuing bundle into ra-core until Grok Bot does it through the runbook process,
- sign Windows or Android assets (need a Windows device),
- charge Stripe,
- print or commit any private key.
