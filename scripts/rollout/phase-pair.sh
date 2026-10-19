#!/usr/bin/env bash
# phase-pair: once ra-core has the chain and Josh's account exists.
# Everything happens inside the Go binary (QA F1/M1): `rottencore devhub-pair`
#   - generates the device + Mega Ed25519 keys in-process and writes them straight into the Keychain
#     (private keys never leave the Go process except into the Keychain; no Python, no PyNaCl);
#   - POST /v1/devhub/pairings, prints the 8-char code, polls /pairings/status until APPROVED;
#   - Red-XAI Accounts full-access key typed at rottencore's hidden /dev/tty prompt (never stored, never env/argv),
#     sent to ra-core with the pairing and cert requests; ra-core resolves the account server-side;
#   - shows the server-returned name / email / subject and asks Josh to type yes;
#   - challenge + /certs for the Mega key; the cert subject must equal ra-core's subject BYTE FOR BYTE (QA M3);
#   - verifies the issued chain to the ceremony root and writes josh-mega.bundle.json.
# Build API key: Keychain account ra-build-api-key, or hidden prompt / stdin. Never argv, never env.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
require_darwin
setup_rollout_env
require_mac_terminal

# No hand-fed identity: the cert's subject comes from ra-core and Josh confirms it by typing yes.
# ROTTEN_DEV_ID / ROTTEN_TEAM_ID are NOT required; if set they are an optional extra cross-check.
CROSS_ARGS=()
optional_id_crosscheck
[[ -n "${ROTTEN_DEV_ID:-}" ]] && CROSS_ARGS+=(--dev "$ROTTEN_DEV_ID")
[[ -n "${ROTTEN_TEAM_ID:-}" ]] && CROSS_ARGS+=(--team "$ROTTEN_TEAM_ID")
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
  echo ">> You will also be asked for the Red-XAI Accounts full-access key (hidden; not stored) and to type yes." >&2
  "$ROTTENCORE" devhub-pair ${CROSS_ARGS[@]+"${CROSS_ARGS[@]}"} \
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
echo "Device paired; Mega cert subject == the ra-core subject you confirmed (byte for byte)"
echo "NEXT: run phase-sign"
echo "===== END ====="
log "phase-pair finished OK"
