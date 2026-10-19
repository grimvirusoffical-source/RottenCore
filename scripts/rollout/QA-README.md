# Live signed rollout — QA Dev (phased, server-hosted issuing CA)

> ## ⚠ Run every phase in Terminal ON the Mac. Click **"Allow"**, NEVER **"Always Allow"**.
>
> Keychain reads go through `/usr/bin/security`, so the macOS access list sees `security` as the
> reader, not `rottencore`. Trusting our binaries with `-T` does not protect anything, and the items
> are **not** non-exportable (QA F2). The safeguard is the per-read prompt: each time macOS asks
> whether `security` may use a Rotten Core key, click **Allow**. **Always Allow** would add `security`
> to the item's access list, and from then on any process running as Josh could read the key without
> asking. If it gets clicked by mistake, stop and tell QA before going on.
>
> The phases refuse to run over SSH (`SSH_CONNECTION` set), because nobody would be there to see the prompt.
> A Security.framework (cgo) build, where our binary becomes the accessor, can't be cross-built from the
> Linux box (no macOS SDK or toolchain), so it stays future work.
>
> Expected prompts: **root** has one per root read (ceremony and sign-intermediate). **pair** has the
> device key, the Mega key, and the build key if it's stored. **sign** has one in total (`sign-batch`
> reads josh-mega once), plus github-token if it's stored.
>
> **Red-XAI Accounts full-access key:** `rottencore` asks for it at a hidden prompt on the terminal,
> once at **pair** and once at **sign**. Type or paste it each time. It is never stored (no Keychain
> item), and never goes to env, argv, files, logs or output. The phases refuse to run if any
> `*ACCOUNTS*KEY/TOKEN/SECRET` or `REDX_*KEY` variable is set. ra-core resolves who it belongs to. RottenCore then shows the
> **name, email and subject ra-core returned** and you type `yes` to go on.

Josh's plan:
- The issuing CA key lives on ra-core. The Mac holds only the root, device and Mega keys.
- mac-sign is phased.
- Latest releases only.
- No permanent signed copies stay on the Mac.
- The Mega cert's subject must equal, **byte for byte**, the subject ra-core returns for the Accounts key, both at pairing and at signing. It must also be for our Mega public key and chain to the ceremony root. `ROTTEN_DEV_ID` / `ROTTEN_TEAM_ID` are a further exact cross-check against ra-core's fields.

Hub: `https://api.rottenapplestore.org` (ra-core 0.2.0). Clients send `X-RA-Launcher: 0.2.0`.

## Prerequisites

- Josh at the Mac (`xlr1-mac`), with Terminal open locally.
- `ROTTEN_DEV_ID` is the **Red-XAI Accounts id** (OIDC sub). It must match `^rxa_[A-Z2-7]{26}$`. Josh's primary
  (grimvirusoffical@gmail.com) is `rxa_LVWECFKVPN6XMPISHYONVY6WUB`. Other accounts, such as support@, use their own rxa_ id.
- `ROTTEN_TEAM_ID` is the owner's own rxa_ id for an individual context (it must then equal `ROTTEN_DEV_ID`), or a team id
  matching `^rxt_[A-Z2-7]{26}$`. **PENDING:** the team format isn't final yet. The patterns live in `core/ids.go`
  (`TeamIDPatterns`) and `lib.sh` (`ROTTEN_TEAM_ID_PATTERNS`), and a test keeps the two in sync.
- Old `A<n>` / `T<n>` ids, lower-case ids, ids of the wrong length, and an rxa_ id in a team slot that isn't the owner are all refused.
- **GitHub token (required for phase-sign):** stored as Keychain account `github-token` (service
  `com.redx.rottencore.ca`), or typed at the hidden prompt. It is kept in an unexported shell variable and sent to curl as `-H @-` on stdin, never on argv.
  `publish.sh`/`restore.sh` (box) read `GITHUB_TOKEN`. They drop it from the environment before calling curl and send it on stdin.
- **Build API key (phase-pair):** stored as Keychain account `ra-build-api-key`, or typed at the hidden
  prompt `rottencore devhub-pair` shows. It never goes in argv or env, and phase-pair refuses to start if
  `RA_API_KEY` / `ROTTENCORE_BUILD_API_KEY` are set.
- **`issuing.csr.json` is NOT in the tgz (QA L5).** Grok Bot scps it from the box separately to
  `~/redx-ceremony/issuing.csr.json`. phase-root pins its public key to the box copy:
  `sha256:30af5d5eff2a398cba6e560cf9c00d51babe9775618e11c2f3db69d058379183` (QA M4). Any other key stops the phase.

## 1. Pack / copy to the Mac

The tgz holds:
- `bin/` (rottencore and rottencore-ca, darwin/arm64, `-trimpath -ldflags "-s -w"`, with `BUILD-INFO.txt`)
- the scripts
- `inventory.json`
- `tiers-ed25519.json`
- this README
- **`MANIFEST.json` + `MANIFEST.json.sha256`**, the box backup manifest (QA B3). phase-sign HARD-STOPS if the manifest is missing or its sha256 isn't the pinned
  `81c30f1041bc5501e4de6a00e93485799c84530e347988ce6b2ab0015a8de414`, and on any asset digest mismatch.

```bash
# on the box
ssh josh@xlr1-mac 'mkdir -p ~/redx-ceremony'      # QA L-d: the folder must exist before the CSR scp
scp /workspace/rollout/rottencore-mac-rollout.tgz josh@xlr1-mac:~/
scp /workspace/rollout/issuing.csr.json        josh@xlr1-mac:~/redx-ceremony/issuing.csr.json
```

On the Mac: `mkdir -p ~/redx-ceremony && tar -xzf ~/rottencore-mac-rollout.tgz -C ~/redx-ceremony`.

## 2. Phase commands (Terminal on the Mac)

```bash
export ROTTEN_CEREMONY_DIR="$HOME/redx-ceremony"
export ROTTEN_DEV_ID='rxa_LVWECFKVPN6XMPISHYONVY6WUB'   # Red-XAI Accounts id, required for pair
export ROTTEN_TEAM_ID='rxa_LVWECFKVPN6XMPISHYONVY6WUB'  # individual context (== dev); or rxt_… for a team (PENDING)
# Do NOT export the Accounts key. rottencore asks for it at a hidden prompt.
cd "$ROTTEN_CEREMONY_DIR"

# (1) Root ceremony + sign the SERVER's issuing CSR (pinned) → root.cert.json + issuing.bundle.json
./mac-sign.sh root
#     Check: ISSUING_CSR_FINGERPRINT and ISSUING_FINGERPRINT both = sha256:30af5d5e…058379183
#     Copy issuing.bundle.json + root.cert.json to the box/server; load the chain into ra-core.
#     Confirm: curl -s https://api.rottenapplestore.org/v1/devhub/ca/chain  → "issuing":true

# (2) Pair + Mega cert, all in Go (`rottencore devhub-pair`):
#     keys are generated in-process straight into the Keychain; prints the 8-char code;
#     Josh approves under Dev > Devices; Accounts key at the hidden prompt; ra-core's name/email/subject
#     shown → type yes; cert subject == ra-core subject byte for byte; chain verified to the root.
./mac-sign.sh pair

# (3) Latest-only: download → MANIFEST digest check (hard stop; a bad download is removed from staging)
#     → sign-batch (Accounts key prompt, ra-core identity == Mega cert subject, type yes, one josh-mega read)
#     → verify → ~/rottencore-signed.tgz
./mac-sign.sh sign
```

`./mac-sign.sh all` runs root, then pair, then sign. It's only useful once ra-core can report `issuing:true` between root and pair.

Each phase is **idempotent** and **stops on any error**. Pairing markers are set only after the store approves (QA L4).

## 3. Box verify + Mac cleanup

```bash
# box
sha256sum -c rottencore-signed.tgz.sha256
tar -xzf rottencore-signed.tgz              # → signed/ and ceremony/

# Mac. This is the REQUIRED form; anything else exits non-zero and deletes nothing (an upper-case hash is fine):
./mac-cleanup.sh --confirm '<64-hex-sha256-from-box>'
```

**Heads-up (QA L2):** cleanup deletes the staging tree, the local tgz, and the **whole**
`~/Rotten Apple Signed` folder (or `ROTTEN_SIGNED_DIR`) if it exists. Keychain items and the public
certs in `~/redx-ceremony` stay.

## 4. Publish (box; latest only, older releases → draft)

```bash
./publish.sh --dry-run
./publish.sh                # needs Josh's explicit go-ahead
# undo drafts: ./restore.sh --undraft
```

## Inventory

The latest **published** release for each repo, Gendragoon included. Windows and Android are deferred. Older releases become drafts after publish, and only once they're fully backed up.

## PENDING (Grok Bot)

- Header `X-RedX-Accounts-Key` (`devhub.AccountsKeyHeader`) and the signing-time path `/v1/devhub/account-status`
  (`devhub.AccountStatusPath`) are placeholders.
- The response shape is also a placeholder: `account: {name, email, subject}` in `/pairings/status` once approved, and in account-status.
- The subject layout is assumed to be `{name, teamId, devId}`. Only `core.SubjectIDs` / `core.SanityCheckSubject` assume it. The byte-for-byte rule (`core.EqualSubjectBytes`) does not depend on it.
- Team id format: `core.TeamIDPatterns` / `lib.sh ROTTEN_TEAM_ID_PATTERNS`.
