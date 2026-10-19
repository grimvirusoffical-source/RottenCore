#!/usr/bin/env bash
# mac-cleanup.sh — delete Mac staging + local tarball AFTER the box verified sha256.
# Keychain keys are NEVER touched.
#
# REQUIRED: exactly `./mac-cleanup.sh --confirm <64-hex-sha256>`
# Compares against `shasum -a 256` of the actual tarball (absolute path from receipt).
set -euo pipefail

die() { echo "mac-cleanup: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

[[ "$(uname -s)" == "Darwin" ]] || die "must run on Josh's Mac"

# B1: require exactly --confirm <64-hex>, nothing else
if [[ $# -ne 2 || "${1:-}" != "--confirm" ]]; then
  die "usage: $0 --confirm <64-hex-sha256>   (refusing to delete without an exact confirm)"
fi
EXPECTED="${2:-}"
[[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] || die "confirm value must be a 64-character hex sha256 (got '${EXPECTED:0:16}…' len=${#EXPECTED})"

ROOT_DIR="${ROTTEN_CEREMONY_DIR:-$HOME/redx-ceremony}"
[[ "$ROOT_DIR" == /* ]] || die "ROTTEN_CEREMONY_DIR must be absolute"
RECEIPT="$ROOT_DIR/signed-tarball.receipt"
[[ -f "$RECEIPT" ]] || die "receipt missing: $RECEIPT (phase-sign must finish first)"

# Parse receipt with sed (no off-by-one substr) — values must be absolute
TGZ=$(sed -n 's/^tarball=//p' "$RECEIPT" | head -n1)
SHA=$(sed -n 's/^sha256=//p' "$RECEIPT" | head -n1)
STAGING=$(sed -n 's/^staging=//p' "$RECEIPT" | head -n1)
LEGACY=$(sed -n 's/^legacy_signed=//p' "$RECEIPT" | head -n1)

[[ -n "$TGZ" && -n "$SHA" && -n "$STAGING" ]] || die "receipt incomplete"
[[ "$TGZ" == /* ]] || die "receipt tarball must be absolute (got '$TGZ')"
[[ "$STAGING" == /* ]] || die "receipt staging must be absolute (got '$STAGING')"
if [[ -n "$LEGACY" && "$LEGACY" != /* ]]; then
  die "receipt legacy_signed must be absolute (got '$LEGACY')"
fi

[[ -f "$TGZ" ]] || die "tarball missing: $TGZ"
ACTUAL=$(shasum -a 256 "$TGZ" | awk '{print $1}')
[[ "$ACTUAL" == "$SHA" ]] || die "receipt sha256 ($SHA) != shasum of tarball ($ACTUAL)"
[[ "$EXPECTED" == "$ACTUAL" ]] || die "box confirm ($EXPECTED) != tarball sha256 ($ACTUAL) — refusing to delete"

log "confirmed sha256=$ACTUAL"
log "deleting staging=$STAGING"
rm -rf "$STAGING"

if [[ -n "$LEGACY" && -d "$LEGACY" ]]; then
  log "deleting legacy=$LEGACY"
  rm -rf "$LEGACY"
fi
LEGACY_ENV="${ROTTEN_SIGNED_DIR:-}"
if [[ -n "$LEGACY_ENV" ]]; then
  [[ "$LEGACY_ENV" == /* ]] || die "ROTTEN_SIGNED_DIR must be absolute"
  if [[ -d "$LEGACY_ENV" && "$LEGACY_ENV" != "$LEGACY" ]]; then
    log "deleting ROTTEN_SIGNED_DIR=$LEGACY_ENV"
    rm -rf "$LEGACY_ENV"
  fi
fi

log "deleting tarball=$TGZ"
rm -f "$TGZ" "${TGZ}.sha256"

rm -rf "$ROOT_DIR/work/pack" 2>/dev/null || true
# Clear sign-* markers so a later phase-sign re-downloads if needed
if [[ -d "$ROOT_DIR/.done" ]]; then
  find "$ROOT_DIR/.done" -name 'sign-*' -type f -delete 2>/dev/null || true
fi
mkdir -p "$ROOT_DIR/.done"; date -u +%Y-%m-%dT%H:%M:%SZ > "$ROOT_DIR/.done/mac-cleanup"
log "mac-cleanup finished OK — Keychain untouched; public certs in $ROOT_DIR kept"
