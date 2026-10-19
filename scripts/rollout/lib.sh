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

# curl_github URL -o DEST — Authorization header via stdin, never argv (ps-safe).
curl_github() {
  local url="$1"; shift
  [[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN not set (needed for private release assets)"
  # -H @- reads the header line from stdin
  printf 'Authorization: Bearer %s\n' "$GITHUB_TOKEN" | curl -sS -L --fail \
    -H @- \
    -H "Accept: application/octet-stream" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@" "$url"
}

# verify_backup_digest REPO TAG NAME FILE — compare sha256 to MANIFEST before signing.
verify_backup_digest() {
  local repo="$1" tag="$2" name="$3" file="$4"
  local man="${ROTTEN_BACKUPS:-/workspace/release-backups}/MANIFEST.json"
  [[ -f "$man" ]] || die "backup MANIFEST missing: $man (run backup verify on the box first)"
  [[ -f "$file" ]] || die "file missing for digest check: $file"
  python3 - "$man" "$repo" "$tag" "$name" "$file" <<'PY'
import hashlib, json, sys, pathlib
man, repo, tag, name, path = sys.argv[1:6]
assets = json.load(open(man))["assets"]
want = None
for a in assets:
    if a["repo"]==repo and a["tag"]==tag and a["name"]==name:
        want = a["sha256"]; break
if not want:
    sys.exit(f"no MANIFEST entry for {repo}/{tag}/{name}")
h = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
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
  # Trust these binaries for Keychain Get without GUI (SSH-safe).
  export ROTTEN_KEYCHAIN_TRUST="${ROTTEN_KEYCHAIN_TRUST:-$ROTTENCORE:$ROTTENCORE_CA}"
  mkdir -p "$ROOT_DIR" "$MARKER_DIR" "$ROOT_DIR/work" "$STAGING_DIR"
  touch "$LOG"
}
