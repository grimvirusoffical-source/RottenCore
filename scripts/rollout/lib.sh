# shellcheck shell=bash
# Shared helpers for phased mac-sign / cleanup. Sourced by phase-*.sh and mac-sign.sh.
# No key material on argv. GitHub token reaches curl via -H @- over stdin.

die() { echo "${0##*/}: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "${LOG:-/dev/stderr}" >&2; }

require_darwin() {
  [[ "$(uname -s)" == "Darwin" ]] || die "must run on Josh's Mac (got $(uname -s))"
}

# Absolute path only — refuse relative (QA B2).
require_abs() {
  local p="$1" what="${2:-path}"
  [[ "$p" == /* ]] || die "$what must be an absolute path (got '$p')"
}

done_p() { [[ -f "$MARKER_DIR/$1" ]]; }
mark() { mkdir -p "$MARKER_DIR"; date -u +%Y-%m-%dT%H:%M:%SZ > "$MARKER_DIR/$1"; }

keychain_has() {
  local label="$1"
  security find-generic-password -a "$label" -s "${KEYCHAIN_SERVICE:-com.redx.rottencore.ca}" >/dev/null 2>&1
}

# load_github_token — GitHub token for private release assets. Never argv, never exported.
# Order: an existing session GITHUB_TOKEN; else Keychain account github-token (one Allow prompt);
# else a hidden prompt on the terminal. Kept in an unexported shell variable.
load_github_token() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    GH_RELEASE_TOKEN="$GITHUB_TOKEN"
    unset GITHUB_TOKEN
    return 0
  fi
  if keychain_has github-token; then
    keychain_prompt_notice "github-token"
    GH_RELEASE_TOKEN=$(/usr/bin/security find-generic-password -a github-token -s "${KEYCHAIN_SERVICE:-com.redx.rottencore.ca}" -w) \
      || die "could not read github-token from the Keychain (click Allow)"
    return 0
  fi
  [[ -t 0 ]] || die "GitHub token required: store it as Keychain account github-token, or run in Terminal to be prompted"
  read -r -s -p "GitHub token (input hidden): " GH_RELEASE_TOKEN; echo >&2
  [[ -n "${GH_RELEASE_TOKEN:-}" ]] || die "no GitHub token entered"
}

# curl_github URL -o DEST — Authorization header via stdin, never argv (ps-safe).
curl_github() {
  local url="$1"; shift
  [[ -n "${GH_RELEASE_TOKEN:-}" ]] || die "GitHub token not loaded (load_github_token)"
  # -H @- reads the header line from stdin
  printf 'Authorization: Bearer %s\n' "$GH_RELEASE_TOKEN" | curl -sS -L --fail \
    -H @- \
    -H "Accept: application/octet-stream" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@" "$url"
}

# QA F2: Keychain reads are done by /usr/bin/security, so the item ACL cannot single out our binaries.
# Run every phase in Terminal ON the Mac and answer each prompt with "Allow" — NEVER "Always Allow".
require_mac_terminal() {
  if [[ -n "${SSH_CONNECTION:-}${SSH_TTY:-}${SSH_CLIENT:-}" ]]; then
    die "run this phase in Terminal ON the Mac, not over SSH: macOS must show the Keychain prompt so you can click Allow"
  fi
  [[ -t 1 ]] || die "run this phase in an interactive Terminal window on the Mac"
  cat >&2 <<'BANNER'
================================================================================
 Keychain prompts: macOS will ask to let "security" use a Rotten Core key.
 Click "Allow".  NEVER click "Always Allow" (it would let any process read
 the key silently from then on). If you clicked it by mistake, stop and tell
 QA: the item's access list must be reset before going on.
================================================================================
BANNER
}

keychain_prompt_notice() {
  echo ">> Keychain prompt for '$1' next: click Allow (never Always Allow)." >&2
}

# Pinned public values from the box (QA B3 / M4). Override only with values Grok Bot gives you.
BACKUP_MANIFEST_SHA256_PIN="${ROTTEN_MANIFEST_SHA256:-81c30f1041bc5501e4de6a00e93485799c84530e347988ce6b2ab0015a8de414}"
ISSUING_CSR_FP_PIN="${ROTTEN_ISSUING_CSR_FP:-sha256:30af5d5eff2a398cba6e560cf9c00d51babe9775618e11c2f3db69d058379183}"

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# pubkey_fp FILE JSONPATH — "sha256:<hex>" of a base64 publicKey (csr | chain0 | cert).
pubkey_fp() {
  python3 - "$1" "$2" <<'PY'
import base64, hashlib, json, sys
path, where = sys.argv[1:3]
j = json.load(open(path))
if where == "chain0":
    j = (j.get("chain") or [None])[0] if isinstance(j, dict) else j[0]
pk = j["publicKey"]
raw = base64.b64decode(pk) if isinstance(pk, str) else bytes(pk)
print("sha256:" + hashlib.sha256(raw).hexdigest())
PY
}

# require_backup_manifest — HARD STOP unless MANIFEST.json is present and matches the pinned sha256.
require_backup_manifest() {
  BACKUP_MANIFEST="${ROTTEN_BACKUPS:-$ROOT_DIR}/MANIFEST.json"
  require_abs "$BACKUP_MANIFEST" "backup MANIFEST"
  [[ -f "$BACKUP_MANIFEST" ]] || die "backup MANIFEST missing: $BACKUP_MANIFEST (it ships in the rollout tgz; re-extract it)"
  local got; got=$(sha256_of "$BACKUP_MANIFEST")
  [[ "$got" == "$BACKUP_MANIFEST_SHA256_PIN" ]] \
    || die "backup MANIFEST sha256 mismatch: got $got, pinned $BACKUP_MANIFEST_SHA256_PIN — STOP"
  log "backup MANIFEST ok ($got)"
}

# verify_backup_digest REPO TAG NAME FILE — compare sha256 to MANIFEST before signing.
verify_backup_digest() {
  local repo="$1" tag="$2" name="$3" file="$4"
  local man="${BACKUP_MANIFEST:?require_backup_manifest first}"
  [[ -f "$man" ]] || die "backup MANIFEST missing: $man"
  [[ -f "$file" ]] || die "file missing for digest check: $file"
  python3 - "$man" "$repo" "$tag" "$name" "$file" <<'PY' || die "digest check failed for $repo/$tag/$name — STOP"
import hashlib, json, sys, pathlib
man, repo, tag, name, path = sys.argv[1:6]
assets = json.load(open(man))["assets"]
want = None
for a in assets:
    if a["repo"]==repo and a["tag"]==tag and a["name"]==name:
        want = a["sha256"]; break
if not want:
    sys.exit(f"no MANIFEST entry for {repo}/{tag}/{name}")
hh = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        hh.update(chunk)
h = hh.hexdigest()
if h != want:
    sys.exit(f"digest mismatch for {repo}/{tag}/{name}: got {h}, want {want}")
print(f"digest ok {repo}/{tag}/{name}", flush=True)
PY
}

setup_rollout_env() {
  ROOT_DIR="${ROTTEN_CEREMONY_DIR:-$HOME/redx-ceremony}"
  require_abs "$ROOT_DIR" "ROTTEN_CEREMONY_DIR"
  BIN_DIR="${ROTTEN_BIN_DIR:-$ROOT_DIR/bin}"
  INVENTORY="${ROTTEN_INVENTORY:-$ROOT_DIR/inventory.json}"
  TIERS="${ROTTEN_TIERS:-$ROOT_DIR/tiers-ed25519.json}"
  MARKER_DIR="$ROOT_DIR/.done"
  LOG="$ROOT_DIR/mac-sign.log"
  ROTTENCORE="${BIN_DIR}/rottencore"
  ROTTENCORE_CA="${BIN_DIR}/rottencore-ca"
  KEYCHAIN_SERVICE="${ROTTEN_KEYCHAIN_SERVICE:-com.redx.rottencore.ca}"
  STAGING_DIR="$ROOT_DIR/staging-signed"
  TARBALL_OUT="${ROTTEN_SIGNED_TGZ:-$HOME/rottencore-signed.tgz}"
  require_abs "$TARBALL_OUT" "ROTTEN_SIGNED_TGZ"
  DEVHUB_URL="${RA_DEVHUB_URL:-https://api.rottenapplestore.org}"
  # QA F2: no -T trust list. Reads go through /usr/bin/security, so trusting our binaries would not help;
  # items are written with -T "" and every read prompts (click Allow, never Always Allow).
  unset ROTTEN_KEYCHAIN_TRUST
  mkdir -p "$ROOT_DIR" "$MARKER_DIR" "$ROOT_DIR/work" "$STAGING_DIR"
  touch "$LOG"
}
