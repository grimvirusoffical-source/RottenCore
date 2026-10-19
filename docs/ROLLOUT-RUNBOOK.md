# Rollout runbook — root ceremony and signing

Step-by-step commands for standing up the Red-XAI signing chain and signing a release. **Nothing in this
runbook has been run.** It is waiting on Josh's confirmation. Do **not** run the ceremony on Josh's Mac,
message QA, touch the ra-core server, or modify any GitHub release until Josh says so.

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
- The **issuing CA key** is generated **on the server where ra-core runs**; only its **CSR** travels to the
  root. The issuing key never visits the root machine.
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
  --keychain --label rottencore-root \
  --alg ed25519 --mic \
  --dir ~/redx-ceremony \
  --out ~/redx-ceremony/root.cert.json
```
- The private key is now a Keychain item (`service com.redx.rottencore.ca`, account `rottencore-root`). It
  never touched disk in the clear.
- `root.cert.json` is the **public** root certificate — this is what gets pinned (`PinnedCARoots`). Share it;
  it is not secret.
- Back up: export the Keychain item to an **offline USB** and make a second copy. Keep both off the network.

> Until the real ceremony, `ceremony-root` marks the root **TEST** (every issued cert carries `test:true` and
> production verifiers refuse it). The production ceremony flips this once Josh confirms.

## 2. Issuing CA — on the ra-core server
Generate the issuing key where it will live and emit only a CSR.
```sh
rottencore-ca issuing-csr \
  --keychain=false --dir /etc/ra-core/ca --label rottencore-issuing \
  --alg ed25519 \
  --out /etc/ra-core/ca/issuing.csr.json
# send ONLY issuing.csr.json to the root machine (it carries no private key)
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

# on the issuing CA: issue the developer cert from the CSR
rottencore-ca issue \
  --dir /etc/ra-core/ca \
  --req josh-mega.csr.json \
  --dev josh --team T-josh --role developer --mega \
  --out josh-mega.bundle.json
```
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
  --key ~/redx-ceremony/josh-mega.key.json \
  --bundle ./out/josh-mega.bundle.json \
  --app com.redx.quicklaunch --app-version 1.0.0
# writes quicklaunch-1.0.0-beta-macos-arm64.dmg.rasig and regenerates ./out/SHA256SUMS
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

## Do NOT yet
- run any of the above on Josh's Mac,
- generate the production (non-TEST) root,
- message QA,
- change anything on the ra-core server,
- modify any GitHub release.

All of those wait on Josh's explicit go-ahead.
