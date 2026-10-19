#!/usr/bin/env bash
# phase-pair: once ra-core has the chain and Josh's account exists.
# Everything happens inside the Go binary (QA F1/M1): `rottencore devhub-pair`
#   - generates the device + Mega Ed25519 keys in-process and writes them straight into the Keychain
#     (private keys never leave the Go process except into the Keychain; no Python, no PyNaCl);
#   - POST /v1/devhub/pairings, prints the 8-char code, polls /pairings/status until APPROVED;
#   - challenge + /certs for the Mega key; subject devId/teamId must match EXACTLY (QA M3);
#   - verifies the issued chain to the ceremony root and writes josh-mega.bundle.json.
# Build API key: Keychain account ra-build-api-key, or hidden prompt / stdin. Never argv, never env.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
require_darwin
setup_rollout_env
require_mac_terminal

[[ -n "${ROTTEN_DEV_ID:-}" ]] || die "ROTTEN_DEV_ID is not set (exact cert subject devId, e.g. A<accountId>)"
[[ -n "${ROTTEN_TEAM_ID:-}" ]] || die "ROTTEN_TEAM_ID is not set (exact cert subject teamId, e.g. T<teamId>)"
[[ -x "$ROTTENCORE" ]] || die "rottencore not at $ROTTENCORE"
[[ -f "$ROOT_DIR/root.cert.json" ]] || die "root.cert.json missing — run phase-root first"
# Keep the build key out of the environment of everything we start.
if [[ -n "${RA_API_KEY:-}${ROTTENCORE_BUILD_API_KEY:-}" ]]; then
  die "unset RA_API_KEY / ROTTENCORE_BUILD_API_KEY: the build key must come from the Keychain (ra-build-api-key) or the prompt, never the environment"
fi

ROOT_HEX=$(python3 -c 'import json,base64,binascii,sys; c=json.load(open(sys.argv[1])); pk=c["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print(binascii.hexlify(raw).decode())' "$ROOT_DIR/root.cert.json")

export RA_DEVHUB_URL="$DEVHUB_URL"
BUNDLE="$ROOT_DIR/josh-mega.bundle.json"

if done_p mega-cert && [[ -f "$BUNDLE" ]]; then
  log "=== phase-pair: Mega cert already issued ($BUNDLE) ==="
else
  log "=== phase-pair: rottencore devhub-pair (Go; keys go straight into the Keychain) ==="
  keychain_prompt_notice "rottencore-device / josh-mega / ra-build-api-key"
  "$ROTTENCORE" devhub-pair \
    --dev "$ROTTEN_DEV_ID" --team "$ROTTEN_TEAM_ID" \
    --device-label rottencore-device --label josh-mega \
    --service "$KEYCHAIN_SERVICE" \
    --name "${ROTTEN_DEVICE_NAME:-xlr1-mac}" \
    --state "$ROOT_DIR/work/pairing.json" \
    --trust-root "$ROOT_HEX" \
    --out "$BUNDLE"
  # QA L4: markers only after the store approved the pairing and the cert verified.
  [[ -f "$ROOT_DIR/work/pairing.json.approved" ]] || die "pairing approval record missing"
  mark device-approved
  [[ -f "$BUNDLE" ]] || die "josh-mega.bundle.json was not written"
  mark mega-cert
fi

echo
echo "===== phase-pair OK ====="
echo "MEGA_BUNDLE_JSON=$BUNDLE"
echo "Device paired and Mega cert issued for dev=$ROTTEN_DEV_ID team=$ROTTEN_TEAM_ID (exact subject match)"
echo "NEXT: run phase-sign"
echo "===== END ====="
log "phase-pair finished OK"
