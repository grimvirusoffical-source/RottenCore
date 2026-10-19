#!/usr/bin/env bash
# mac-sign.sh — dispatcher for phased Mac ceremony / pairing / signing.
# Issuing CA private key lives on ra-core (server). Mac only holds the root + device + Mega keys.
#
# Usage:
#   ./mac-sign.sh root|phase-root     # ceremony-root + sign issuing.csr.json
#   ./mac-sign.sh pair|phase-pair     # pair device + Mega cert (needs ROTTEN_DEV_ID/TEAM_ID)
#   ./mac-sign.sh sign|phase-sign     # latest-only sign → staging → tarball
#   ./mac-sign.sh all                 # root && pair && sign (stops on first error)
#
# Run in Terminal ON the Mac (not SSH). Keychain prompts: click "Allow", NEVER "Always Allow" (QA F2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-}"
case "$cmd" in
  root|phase-root) exec "$HERE/phase-root.sh" ;;
  pair|phase-pair) exec "$HERE/phase-pair.sh" ;;
  sign|phase-sign) exec "$HERE/phase-sign.sh" ;;
  all)
    "$HERE/phase-root.sh"
    "$HERE/phase-pair.sh"
    "$HERE/phase-sign.sh"
    ;;
  *)
    echo "usage: $0 root|pair|sign|all   (Terminal on the Mac; Keychain prompts: Allow, never Always Allow)" >&2
    echo "  root  — production root + sign server issuing CSR" >&2
    echo "  pair  — device pairing + Mega cert (ROTTEN_DEV_ID / ROTTEN_TEAM_ID required)" >&2
    echo "  sign  — latest-only sign, staging, tarball" >&2
    echo "  all   — root && pair && sign" >&2
    exit 2
    ;;
esac
