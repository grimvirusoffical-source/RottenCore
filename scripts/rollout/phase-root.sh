#!/usr/bin/env bash
# phase-root: production root ceremony (Keychain) + sign the SERVER's issuing CSR.
# Issuing CA private key lives on ra-core — Grok Bot drops issuing.csr.json for the Mac to sign.
# Outputs: root.cert.json, issuing.bundle.json. Prints public fingerprints only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
require_darwin
setup_rollout_env

[[ -x "$ROTTENCORE_CA" ]] || die "rottencore-ca not at $ROTTENCORE_CA"
[[ -f "$TIERS" ]] || die "tiers missing: $TIERS"

CSR="${ROTTEN_ISSUING_CSR:-$ROOT_DIR/issuing.csr.json}"
# Also accept the box drop path if copied next to the script pack
[[ -f "$CSR" ]] || CSR="$HERE/issuing.csr.json"
[[ -f "$CSR" ]] || die "issuing.csr.json not found (expected at $ROOT_DIR/issuing.csr.json — Grok Bot runs issuing-csr on the server and copies it here)"

if ! done_p ceremony-root; then
  log "=== phase-root (a) production root ceremony ==="
  if keychain_has rottencore-root; then
    die "Keychain has rottencore-root but marker missing; refuse to re-generate"
  fi
  MIC_ARGS=()
  if [[ "${ROTTEN_MIC:-auto}" != "off" ]]; then
    MIC_ARGS=(--mic)
  fi
  "$ROTTENCORE_CA" ceremony-root \
    --production \
    --keychain --label rottencore-root \
    --alg ed25519 \
    --tiers "$TIERS" \
    "${MIC_ARGS[@]}" \
    --dir "$ROOT_DIR" \
    --out "$ROOT_DIR/root.cert.json"
  mark ceremony-root
else
  log "=== phase-root: root already done ==="
fi
[[ -f "$ROOT_DIR/root.cert.json" ]] || die "root.cert.json missing"

if ! done_p sign-issuing-csr; then
  log "=== phase-root (b) sign server issuing CSR (issuer key stays on ra-core) ==="
  "$ROTTENCORE_CA" sign-intermediate \
    --keychain --label rottencore-root \
    --dir "$ROOT_DIR" \
    --req "$CSR" \
    --alg ed25519 --tiers "$TIERS" \
    --out "$ROOT_DIR/issuing.bundle.json"
  mark sign-issuing-csr
else
  log "=== phase-root: issuing.bundle already signed ==="
fi
[[ -f "$ROOT_DIR/issuing.bundle.json" ]] || die "issuing.bundle.json missing"

ROOT_FP=$(python3 -c 'import json,base64,hashlib; c=json.load(open("'"$ROOT_DIR"'/root.cert.json")); pk=c["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print("sha256:"+hashlib.sha256(raw).hexdigest())')
ISS_FP=$(python3 -c 'import json,base64,hashlib; b=json.load(open("'"$ROOT_DIR"'/issuing.bundle.json")); chain=b.get("chain") or b; pk=chain[0]["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print("sha256:"+hashlib.sha256(raw).hexdigest())')

echo
echo "===== phase-root PUBLIC FINGERPRINTS ====="
echo "ROOT_FINGERPRINT=$ROOT_FP"
echo "ISSUING_FINGERPRINT=$ISS_FP"
echo "ROOT_CERT_JSON=$ROOT_DIR/root.cert.json"
echo "ISSUING_BUNDLE_JSON=$ROOT_DIR/issuing.bundle.json"
echo "NEXT: copy issuing.bundle.json + root.cert.json to the ra-core server; load the chain; then run phase-pair"
echo "===== END ====="
log "phase-root finished OK"
