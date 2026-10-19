#!/usr/bin/env bash
# mac-cleanup.sh — delete Mac staging + legacy signed dirs AFTER the box has verified
# the signed tarball sha256. Keychain keys are NEVER touched.
#
# Usage (on the Mac, after Josh/parent confirms the box has the bytes):
#   ./mac-cleanup.sh                  # uses ~/redx-ceremony/signed-tarball.receipt
#   ./mac-cleanup.sh --confirm SHA256 # require this exact hash to match the receipt
set -euo pipefail

ROOT_DIR="${ROTTEN_CEREMONY_DIR:-$HOME/redx-ceremony}"
RECEIPT="$ROOT_DIR/signed-tarball.receipt"
LEGACY_SIGNED_DIR="${ROTTEN_SIGNED_DIR:-$HOME/Rotten Apple Signed}"

die() { echo "mac-cleanup: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

[[ "$(uname -s)" == "Darwin" ]] || die "must run on Josh's Mac"
[[ -f "$RECEIPT" ]] || die "receipt missing: $RECEIPT (mac-sign.sh must finish first)"

EXPECTED=""
if [[ "${1:-}" == "--confirm" ]]; then
  EXPECTED="${2:-}"
  [[ -n "$EXPECTED" ]] || die "--confirm needs the sha256 the box verified"
fi

# Parse receipt
TGZ=$(awk -F= '/^tarball=/{print substr($0,10)}' "$RECEIPT")
SHA=$(awk -F= '/^sha256=/{print substr($0,8)}' "$RECEIPT")
STAGING=$(awk -F= '/^staging=/{print substr($0,9)}' "$RECEIPT")
LEGACY=$(awk -F= '/^legacy_signed=/{print substr($0,16)}' "$RECEIPT")
[[ -n "$SHA" ]] || die "receipt has no sha256"
[[ -n "$STAGING" ]] || die "receipt has no staging path"

if [[ -n "$EXPECTED" && "$EXPECTED" != "$SHA" ]]; then
  die "box sha256 ($EXPECTED) does not match receipt ($SHA) — refusing to delete"
fi

log "receipt sha256=$SHA"
log "will remove staging=$STAGING"
log "will remove legacy=$LEGACY (if present)"
log "will remove tarball=$TGZ (optional local copy; Keychain untouched)"

# Safety: never touch Keychain
# Delete staging signed tree
if [[ -d "$STAGING" ]]; then
  rm -rf "$STAGING"
  log "deleted staging $STAGING"
else
  log "staging already gone"
fi

# Delete legacy permanent signed dir if it exists
if [[ -d "$LEGACY" ]]; then
  rm -rf "$LEGACY"
  log "deleted legacy signed dir $LEGACY"
fi
if [[ -d "$LEGACY_SIGNED_DIR" && "$LEGACY_SIGNED_DIR" != "$LEGACY" ]]; then
  rm -rf "$LEGACY_SIGNED_DIR"
  log "deleted ROTTEN_SIGNED_DIR $LEGACY_SIGNED_DIR"
fi

# Remove local tarball + .sha256 (box has the verified copy)
if [[ -n "$TGZ" && -f "$TGZ" ]]; then
  rm -f "$TGZ" "${TGZ}.sha256"
  log "deleted local tarball $TGZ"
fi

# Pack scratch
rm -rf "$ROOT_DIR/work/pack" "$ROOT_DIR/work/rottenapple-store" 2>/dev/null || true

# Mark cleaned so a second run is a no-op
date -u +%Y-%m-%dT%H:%M:%SZ > "$ROOT_DIR/.done/mac-cleanup"
log "mac-cleanup finished OK — Keychain keys retained; ceremony public certs in $ROOT_DIR kept"
