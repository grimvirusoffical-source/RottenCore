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
require_mac_terminal

[[ -x "$ROTTENCORE_CA" ]] || die "rottencore-ca not at $ROTTENCORE_CA"
[[ -f "$TIERS" ]] || die "tiers missing: $TIERS"

# QA L5: the CSR is NOT in the rollout tgz. Grok Bot scps it separately to $ROOT_DIR/issuing.csr.json;
# its public key is pinned below (QA M4), so a swapped CSR stops the phase.
CSR="${ROTTEN_ISSUING_CSR:-$ROOT_DIR/issuing.csr.json}"
require_abs "$CSR" "ROTTEN_ISSUING_CSR"
[[ -f "$CSR" ]] || die "issuing.csr.json not found at $CSR (Grok Bot scps it from the box separately)"
CSR_FP=$(pubkey_fp "$CSR" csr) || die "cannot read the CSR public key"
echo "ISSUING_CSR_FINGERPRINT=$CSR_FP"
echo "ISSUING_CSR_PINNED     =$ISSUING_CSR_FP_PIN"
[[ "$CSR_FP" == "$ISSUING_CSR_FP_PIN" ]] || die "issuing CSR public key $CSR_FP does not match the box copy $ISSUING_CSR_FP_PIN — STOP, do not sign"

if ! done_p ceremony-root; then
  log "=== phase-root (a) production root ceremony ==="
  keychain_prompt_notice rottencore-root
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
    ${MIC_ARGS[@]+"${MIC_ARGS[@]}"} \
    --dir "$ROOT_DIR" \
    --out "$ROOT_DIR/root.cert.json"
  mark ceremony-root
else
  log "=== phase-root: root already done ==="
fi
[[ -f "$ROOT_DIR/root.cert.json" ]] || die "root.cert.json missing"

if ! done_p sign-issuing-csr; then
  log "=== phase-root (b) sign server issuing CSR (issuer key stays on ra-core) ==="
  # M4: re-check right before the root signs (the file could change between steps).
  [[ "$(pubkey_fp "$CSR" csr)" == "$ISSUING_CSR_FP_PIN" ]] || die "CSR changed after the pin check — STOP"
  keychain_prompt_notice rottencore-root
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

ROOT_FP=$(pubkey_fp "$ROOT_DIR/root.cert.json" cert)
ISS_FP=$(pubkey_fp "$ROOT_DIR/issuing.bundle.json" chain0)
# M4: the signed issuing certificate must carry exactly the pinned CSR public key.
[[ "$ISS_FP" == "$ISSUING_CSR_FP_PIN" ]] || die "signed issuing cert key $ISS_FP != pinned CSR key $ISSUING_CSR_FP_PIN — STOP, do not ship issuing.bundle.json"

echo
echo "===== phase-root PUBLIC FINGERPRINTS ====="
echo "ROOT_FINGERPRINT=$ROOT_FP"
echo "ISSUING_FINGERPRINT=$ISS_FP (matches pinned CSR key)"
echo "ROOT_CERT_JSON=$ROOT_DIR/root.cert.json"
echo "ISSUING_BUNDLE_JSON=$ROOT_DIR/issuing.bundle.json"
echo "NEXT: copy issuing.bundle.json + root.cert.json to the ra-core server; load the chain; then run phase-pair"
echo "===== END ====="
log "phase-root finished OK"
