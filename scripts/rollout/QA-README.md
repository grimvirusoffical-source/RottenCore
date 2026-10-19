# Live signed rollout — QA Dev instructions (xlr1-mac)

Josh confirmed the live signed rollout and the **21:06 UTC** plan changes: **latest release only** per repo, **no permanent signed copies on the Mac**, Mega cert subject ids from env, older releases converted to **draft** after publish (reversible; tags kept).

## What you need on the Mac

- Tailscale SSH to Josh's Mac (`xlr1-mac`)
- A way to copy files from the box to the Mac (scp over Tailscale, or `tailscale file cp`)
- **`ROTTEN_DEV_ID` and `ROTTEN_TEAM_ID`** from Josh's Red-XAI Accounts row (Grok Bot is creating the account). `mac-sign.sh` refuses to run without them.

## 1. Copy binaries + scripts + inventory onto the Mac

From the **box**:

```bash
cd /workspace/rollout
# pack (already built as rottencore-mac-rollout.tgz — rebuild if scripts changed)
tar -czf /workspace/rollout/rottencore-mac-rollout.tgz \
  bin/rottencore bin/rottencore-ca \
  mac-sign.sh mac-cleanup.sh \
  inventory.json tiers-ed25519.json QA-README.md
scp /workspace/rollout/rottencore-mac-rollout.tgz josh@xlr1-mac:~/
```

On the **Mac**:

```bash
mkdir -p ~/redx-ceremony/bin
cd ~
tar -xzf rottencore-mac-rollout.tgz -C ~/redx-ceremony
chmod +x ~/redx-ceremony/bin/rottencore ~/redx-ceremony/bin/rottencore-ca \
  ~/redx-ceremony/mac-sign.sh ~/redx-ceremony/mac-cleanup.sh
# inventory + tiers next to the scripts
cp -f ~/redx-ceremony/inventory.json ~/redx-ceremony/tiers-ed25519.json ~/redx-ceremony/ 2>/dev/null || true
```

If the Mac needs a GitHub token to download private release assets, set it for the session only — never write it to disk:

```bash
export GITHUB_TOKEN='…'   # do not echo it; do not commit it
```

## 2. Exact command QA runs on the Mac

```bash
export ROTTEN_CEREMONY_DIR="$HOME/redx-ceremony"
export ROTTEN_BIN_DIR="$HOME/redx-ceremony/bin"
export ROTTEN_INVENTORY="$HOME/redx-ceremony/inventory.json"
export ROTTEN_TIERS="$HOME/redx-ceremony/tiers-ed25519.json"
# REQUIRED — from Red-XAI Accounts (no hardcoded josh / T-josh):
export ROTTEN_DEV_ID='…'
export ROTTEN_TEAM_ID='…'
# optional: ROTTEN_MIC=off to skip microphone noise
# optional: ROTTEN_SIGNED_TGZ=$HOME/rottencore-signed.tgz

cd "$ROTTEN_CEREMONY_DIR"
./mac-sign.sh
```

The script is **idempotent** (safe to re-run). Keygen failures **stop the script** (no `|| true`). If a Keychain label already exists, keygen is skipped explicitly via `security find-generic-password`.

It will:

1. Run `rottencore-ca ceremony-root --production --keychain --label rottencore-root --alg ed25519 --mic`
2. Make issuing CA key in Keychain (`rottencore-issuing`), CSR, sign with root
3. Make Mega key in Keychain (`josh-mega`), CSR, issue Mega cert with `--dev "$ROTTEN_DEV_ID" --team "$ROTTEN_TEAM_ID"`
4. Register the Mac as a device for the Mega team (`--team "$ROTTEN_TEAM_ID"`)
5. Download / sign **only the latest published release** of each repo (see inventory); write into a **temporary staging** dir
6. Regenerate `SHA256SUMS` per release in staging
7. Pack staging + public certs into `~/rottencore-signed.tgz` and print its **sha256**
8. Print **only** the public root and Mega cert fingerprints

It never exports a private key. It does **not** leave a permanent `~/Rotten Apple Signed` tree — signed bytes live in staging until packed, then cleanup.

## Keychain safety (ceremony)

Private keys stay in the macOS Keychain. `mac-sign.sh` only passes `--keychain --label …` (never a key blob). Inside Rotten Core, `ca.KeychainStore.Put` feeds `security -i` over stdin so the key material never appears in process argv (`ps`). Do not paste hex keys into shell commands or the environment.

## 3. Copy the signed tarball back to the box and verify sha256

On the **Mac**, after success, note `SIGNED_TARBALL_SHA256=…` from the script output (also in `~/rottencore-signed.tgz.sha256` and `~/redx-ceremony/signed-tarball.receipt`).

```bash
scp ~/rottencore-signed.tgz box-user@<box-tailscale>:/workspace/rollout/
# also copy the .sha256 sidecar if useful
scp ~/rottencore-signed.tgz.sha256 box-user@<box-tailscale>:/workspace/rollout/
```

On the **box** (must match before cleanup):

```bash
cd /workspace/rollout
EXPECTED=$(cat rottencore-signed.tgz.sha256 | awk '{print $1}')
# or paste from the Mac receipt / mac-sign output
echo "$EXPECTED  rottencore-signed.tgz" | sha256sum -c -
tar -xzf rottencore-signed.tgz
# signed assets land at /workspace/rollout/signed/<repo>/<tag>/
# public certs under /workspace/rollout/ceremony/
```

Tell the parent/Josh the hash verified. **Only then** run cleanup on the Mac.

## 4. Mac cleanup (after box confirms the copy)

On the **Mac**:

```bash
cd ~/redx-ceremony
# pass the sha256 the box just verified:
./mac-cleanup.sh --confirm '<sha256-from-box>'
```

This deletes the staging dir, any leftover `~/Rotten Apple Signed`, and the local tarball. **Keychain keys stay.** Ceremony public JSON under `~/redx-ceremony/` stays.

## 5. Publish on the box (latest only; older → draft)

```bash
cd /workspace/rollout
export GITHUB_TOKEN='…'   # do not echo
./publish.sh --dry-run    # lists replacements + which releases become drafts
./publish.sh              # live: replace assets (exact names/labels), then draft older releases
```

`publish.sh` converts every **other** release in those repos to a **draft** only when that release's assets are fully present in `/workspace/release-backups` with matching sha256. Git **tags are left alone**. To undo drafts later:

```bash
./restore.sh --undraft --dry-run
./restore.sh --undraft
# and/or restore asset bytes:
./restore.sh --dry-run
./restore.sh
```

## Inventory policy

- One **latest published** release per GitHub repo (if a draft is newer, it is flagged in the report but the newest published is used; if a repo has only drafts, the newest draft is used).
- Windows/Android stay **deferred** (unsigned for now) on that latest release.
- Older published releases will be drafted after publish so unsigned copies are not downloadable.
