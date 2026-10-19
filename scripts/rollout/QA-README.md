# Live signed rollout — QA Dev (phased, server-hosted issuing CA)

Josh plan updates: **issuing CA key on ra-core**, Mac only holds root + device + Mega keys; **phased** mac-sign; **latest-only**; **no permanent signed copies on the Mac**; Mega subject `dev=A…` / `team=T…` from env.

Hub: `https://api.rottenapplestore.org` (ra-core 0.2.0). Clients send `X-RA-Launcher: 0.2.0`.

## Prerequisites

- Mac (`xlr1-mac`) over Tailscale; `ROTTEN_DEV_ID` / `ROTTEN_TEAM_ID` from Josh’s account in the **production ra-core store** (`A<accountId>`, `T<teamId>`; `ra-core account-status` prints `certDevId` / `certTeamId`). They are not Red-XAI Accounts ids.
- On the **server**, Grok Bot runs `rottencore-ca issuing-csr` and drops `issuing.csr.json` for the Mac (also copied to `/workspace/rollout/issuing.csr.json` when ready).
- Optional session `GITHUB_TOKEN` for private assets (passed to curl via `-H @-`, never left on argv).
- Unlock the login keychain for headless SSH (password over **stdin** only):

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db   # prompts; or pipe password to stdin — never put it on argv
export ROTTEN_KEYCHAIN_TRUST="$HOME/redx-ceremony/bin/rottencore:$HOME/redx-ceremony/bin/rottencore-ca"
```

Keychain items are stored with `-T` trusting those two binaries so Get works over SSH without a GUI prompt. Items stay non-exportable.

## 1. Pack / copy to the Mac

```bash
# on the box
cd /workspace/rollout
tar -czf rottencore-mac-rollout.tgz \
  bin/rottencore bin/rottencore-ca \
  mac-sign.sh mac-cleanup.sh lib.sh \
  phase-root.sh phase-pair.sh phase-sign.sh \
  inventory.json tiers-ed25519.json QA-README.md \
  test-mac-cleanup.sh
# include issuing.csr.json once Grok Bot has dropped it:
#   tar … issuing.csr.json
scp rottencore-mac-rollout.tgz josh@xlr1-mac:~/
```

On the Mac: extract into `~/redx-ceremony`, `chmod +x` bins and `*.sh`.

## 2. Phase commands

```bash
export ROTTEN_CEREMONY_DIR="$HOME/redx-ceremony"
export ROTTEN_BIN_DIR="$HOME/redx-ceremony/bin"
export ROTTEN_INVENTORY="$HOME/redx-ceremony/inventory.json"
export ROTTEN_TIERS="$HOME/redx-ceremony/tiers-ed25519.json"
export ROTTEN_DEV_ID='A…'    # required for pair
export ROTTEN_TEAM_ID='T…'
export RA_DEVHUB_URL='https://api.rottenapplestore.org'
export ROTTEN_KEYCHAIN_TRUST="$ROTTEN_BIN_DIR/rottencore:$ROTTEN_BIN_DIR/rottencore-ca"
# optional: export GITHUB_TOKEN=…  (session only)
# optional: export RA_API_KEY=… or store as Keychain account ra-build-api-key, or pipe on stdin at pair time

cd "$ROTTEN_CEREMONY_DIR"

# (1) Root ceremony + sign the SERVER's issuing CSR → root.cert.json + issuing.bundle.json
./mac-sign.sh root
# Copy issuing.bundle.json + root.cert.json back to the box/server; load the CA chain into ra-core.
# Confirm: curl -s https://api.rottenapplestore.org/v1/devhub/ca/chain  → issuing:true

# (2) Pair device + Mega cert (prints 8-char code; Josh approves under Dev > Devices within 10 min)
./mac-sign.sh pair

# (3) Latest-only sign → staging → ~/rottencore-signed.tgz (prints sha256)
./mac-sign.sh sign
```

Or `./mac-sign.sh all` once the CSR is present and the server can reach `issuing:true` before pair.

Each phase is **idempotent**, **stops on any error**, and never puts key material on argv.

## 3. Box verify + Mac cleanup

```bash
# box
sha256sum -c rottencore-signed.tgz.sha256   # or: echo "<sha>  rottencore-signed.tgz" | sha256sum -c
tar -xzf rottencore-signed.tgz              # → signed/ and ceremony/

# Mac — REQUIRED form (anything else exits non-zero and deletes nothing):
./mac-cleanup.sh --confirm '<64-hex-sha256-from-box>'
```

## 4. Publish (latest only; older → draft)

```bash
./publish.sh --dry-run
./publish.sh
# undo drafts: ./restore.sh --undraft
```

## Inventory

Latest **published** release per repo (Gendragoon included). Windows/Android deferred. Older releases drafted after publish when fully backed up.
