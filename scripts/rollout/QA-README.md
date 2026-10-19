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
> **Red-XAI Accounts key:** issued by **ra-core** (not by Red-XAI Accounts). Josh creates it on the
> **Dev page under API keys > Red-XAI Accounts key**. Format: `ra_sk_live_` + 43 base62 characters
> (`^ra_sk_live_[A-Za-z0-9]{43}$`). `rottencore` asks for it at a hidden prompt on the terminal (echo off),
> once at **pair** and once at **sign**. Type or paste it each time. Anything that is not exactly that format
> is refused without echoing it, and so is the build API key pasted by mistake. It is never stored (no Keychain
> item), and never goes to env, argv, files, logs or output. It is sent raw in `X-RedX-Accounts-Key` only on
> `pairings`, `challenge`, `certs` and `account-status`. The phases refuse to run if any
> `*ACCOUNTS*KEY/TOKEN/SECRET` or `REDX_*KEY` variable is set. ra-core resolves who it belongs to. RottenCore then shows the
> **name, email and subject ra-core returned** and you type `yes` to go on.
>
> Stops (no retry, nothing issued): `account.subject` is null, `cert.ready` is false, there is not exactly one
> context, account/cert/context disagree, `403 pairing_account_mismatch` (the pairing was started with a
> different account's key: delete `work/pairing.json`, pair again), `403 accounts_key_mismatch` (the
> Accounts key and the build key belong to different accounts), `409 rxa_link_required` (see below).
>
> **ra-core links need a verified email.** The Accounts key only works for a ra-core account linked to
> Red-XAI Accounts, and the link is matched against the **verified** Red-XAI Accounts email.
> `409 rxa_link_required` (or `account.rxaLinked=false` / `account.subject: null`) means: **verify the email in
> Red-XAI Accounts first**, then get the account linked, then run the phase again. Nothing is issued or signed meanwhile.
>
> **No redirects (QA D3).** RottenCore's HTTP clients that carry a key (dev hub, account-status, uploads,
> host API, GitHub with a token) never follow a redirect; any 3xx is a hard error that names only the status
> and the target host. The dev-hub base URL must be `https://`. The scripts' curl calls never use `-L`: the
> GitHub asset download handles GitHub's 302 itself and fetches the signed asset URL (GitHub asset host,
> https only) without the token.

Josh's plan:
- The issuing CA key lives on ra-core. The Mac holds only the root, device and Mega keys.
- mac-sign is phased.
- Latest releases only.
- No permanent signed copies stay on the Mac.
- The Mega cert's subject must equal, **byte for byte**, the subject ra-core returns for the Accounts key, both at pairing and at signing. It must also be for our Mega public key and chain to the ceremony root. **No hand-fed ids:** identity comes only from that ra-core subject, which you confirm by typing `yes`.

Hub: `https://api.rottenapplestore.org` (ra-core 0.2.0). Clients send `X-RA-Launcher: 0.2.0`.

## Prerequisites

- Josh at the Mac (`xlr1-mac`), with Terminal open locally.
- **Ids are NOT required.** Don't export anything to say who you are. ra-core returns the subject for the Accounts
  key, and the phases print its name, email and subject for you to confirm with `yes`.
- *Optional* extra cross-check: if `ROTTEN_DEV_ID` and/or `ROTTEN_TEAM_ID` are set, they're validated and ra-core's subject must
  also match them exactly, otherwise the run stops (fail closed). The phases print that this check is optional. Formats:
  - dev: `^rxa_[A-Z2-7]{26}$` (Red-XAI Accounts sub; Josh's primary is `rxa_LVWECFKVPN6XMPISHYONVY6WUB`)
  - team: the owner's rxa_ for an individual context (it must then equal the dev id), or `^rxt_[A-Z2-7]{26}$` (final, ra-core `rxa-cert-ids`). The patterns
    live in `core/ids.go` (`TeamIDPatterns`) and `lib.sh` (`ROTTEN_TEAM_ID_PATTERNS`), and a test keeps the two in sync.
  - Old `A<n>`/`T<n>` ids, lower-case ids, ids of the wrong length, and someone else's rxa_ in the team slot are refused.
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
  `ca16acf820c69848007aff6351bbe99fb528b51c73b4252b86f06783c128900d`, and on any asset digest mismatch.

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
# No ids to export: identity comes from ra-core's subject, which you confirm by typing yes.
# Optional extra cross-check only (fails closed on mismatch):
#   export ROTTEN_DEV_ID='rxa_…'   ROTTEN_TEAM_ID='rxa_… (individual) | rxt_…'
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

The latest **published** release for each repo, Gendragoon included. **The Mac signs only macOS and iOS builds**
(Josh's rule): every latest asset was classified by its content in the box backup (Mach-O, `.pkg` xar, `.dmg`
UDIF, `.app` zip, `.ipa`, macOS installer script), cross-checked against the filename
(`tools/classify-inventory.py`, box-only).

| Repo | Release | sign_on_mac |
|---|---|---|
| RedX | v0.4.5 | 8 |
| quick-launch | v1.0.0-beta.1 | 8 |
| RottenApple | v0.1.0-beta.1 | 2 (darwin tar.gz) |
| gendragoon-cloud-ssd | v0.18.0-rc.3 | 2 (`GenDragoon-Cloud-SSD-Mac-v0.18.0.zip`, `install-macos.py`) |
| Gendragoon-Releases | all-platforms-2026-10-19 | 0 (no Mac or iOS asset) |
| **Total** | | **20** |

- **Deferred (31), left exactly as published:** Linux (14) and browser extensions (5): no signing host yet;
  Windows (10) and Android (2): need the Windows host. Each entry in `inventory.json` `deferred` has its reason.
- **Untouched latest (7):** checksum files and metadata. `publish.sh` never deletes or re-uploads a deferred or
  untouched asset; a checksum file is only **merged** (the signed assets' lines may change, every other line is
  kept as published), and skipped when nothing changed.
- `gendragoon-cloud-ssd/Install.command` is a macOS installer launcher (it runs `install-macos.py`), but it is
  **not** in the signing set; flagged for Josh.
- `sign-batch` refuses the whole batch if any line is not macOS/iOS (exit 4, before any prompt or Keychain
  read); `phase-sign` and the MANIFEST (`action: sign_on_mac`) refuse it too.
- Older releases become drafts after publish, and only once they're fully backed up.

**Serialisation (QA L5):** the exact subject compare is on **bytes as served by the HTTP API** (Go
`json.Marshal` / `json.Encoder`, HTML-escaped: `A<B & C>` is `A\u003cB \u0026 C\u003e` on the wire). Signed
bytes (cert TBS, fingerprints) are escape-off on both sides (`rarxai` `tbs()` and `core.canonJSON`), so
`core.canonJSON` deliberately keeps `SetEscapeHTML(false)`; tests pin both.

## ra-core contract (final, RottenApple `rxa-cert-ids` @ 711171b)

- **Ids:** `devId` = the Red-XAI Accounts sub `^rxa_[A-Z2-7]{26}$`; `teamId` = the owner's rxa_ id for an
  individual developer account (== devId), or `^rxt_[A-Z2-7]{26}$` for a team (made once by ra-core, immutable;
  Red-XAI Accounts has no team entity). `ra-core account-status --email E` prints `certDevId`, `certTeamId` and
  `certSubject` on the server.
- **Subject layout:** `{"name":"<team name>","teamId":"…","devId":"…"}`, keys in that order, Go `encoding/json`
  bytes. Josh: `{"name":"Josh Franklinn","teamId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB","devId":"rxa_LVWECFKVPN6XMPISHYONVY6WUB"}`.
- **Header:** `X-RedX-Accounts-Key` (as `devhub.AccountsKeyHeader`). The key is a ra-core-issued "Red-XAI Accounts
  key" for the linked account: Dev page → API keys → *Red-XAI Accounts key* (`POST /v1/keys {"accounts":true}`,
  shown once, `ra_sk_live_…`, kind `accounts`, no API access of its own). No token exchange.
  - pairings: binds the pairing to that account (only it can approve); pairings/status: ignored on the request;
  - challenge / certs: the build key (`Authorization: Bearer $RA_API_KEY`) is still required; the Accounts key must
    be the same account's (`403 accounts_key_mismatch`);
  - account-status: the Accounts key alone.
- **Signing-time path:** `GET` or `POST /v1/devhub/account-status` (as `devhub.AccountStatusPath`).
- **Response:** `account: {id, sub, name, email, rxaLinked, subject}` in account-status and in `/pairings/status`
  once approved (when the pairing was started with the header). `subject` is a JSON object whose bytes equal the
  `subject` member of the certificate `POST /v1/devhub/certs` returns. `name` is the Red-XAI Accounts username.
  account-status also returns `cert {devId, teamId, subject, ready}` and `contexts` (exactly one: the key's team).
- **One Mega cert per request**, for the key's single developer context.
