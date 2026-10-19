#!/usr/bin/env bash
# Harness for mac-cleanup.sh B1/B2 (runs on Linux too via stubbed uname).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Stub Darwin + shasum environment
export PATH="$TMP/bin:$PATH"
mkdir -p "$TMP/bin" "$TMP/home/redx-ceremony/staging-signed/x" "$TMP/home/Rotten Apple Signed"
cat > "$TMP/bin/uname" <<'U'; chmod +x "$TMP/bin/uname"
#!/bin/sh
echo Darwin
U

# Fake tarball + receipt with ABSOLUTE paths
TGZ="$TMP/home/rottencore-signed.tgz"
echo "signed-bytes" > "$TGZ"
SHA=$(shasum -a 256 "$TGZ" | awk '{print $1}')
echo "payload" > "$TMP/home/redx-ceremony/staging-signed/x/a.bin"
STAGING="$TMP/home/redx-ceremony/staging-signed"
LEGACY="$TMP/home/Rotten Apple Signed"
echo "old" > "$LEGACY/keep-me"
cat > "$TMP/home/redx-ceremony/signed-tarball.receipt" <<R
tarball=$TGZ
sha256=$SHA
staging=$STAGING
legacy_signed=$LEGACY
created_utc=2026-10-19T00:00:00Z
R

export ROTTEN_CEREMONY_DIR="$TMP/home/redx-ceremony"
CLEAN="$HERE/mac-cleanup.sh"
fail=0
run() { set +e; "$@" ; echo $? ; set -e; }

# B1: no args
ec=$(run "$CLEAN"); [[ "$ec" != "0" ]] || { echo "FAIL: no args should exit non-zero"; fail=1; }
[[ -d "$STAGING" ]] || { echo "FAIL: staging deleted without confirm"; fail=1; }

# B1: typo flag
ec=$(run "$CLEAN" --confrim "$SHA"); [[ "$ec" != "0" ]] || { echo "FAIL: typo accepted"; fail=1; }
[[ -d "$STAGING" ]] || { echo "FAIL: typo deleted staging"; fail=1; }

# B1: wrong hash
ec=$(run "$CLEAN" --confirm "$(printf 'a%.0s' {1..64})"); [[ "$ec" != "0" ]] || { echo "FAIL: wrong hash accepted"; fail=1; }

# B1: --confirm without value
ec=$(run "$CLEAN" --confirm); [[ "$ec" != "0" ]] || { echo "FAIL: empty confirm accepted"; fail=1; }

# B1+B2: correct confirm deletes staging + tarball + legacy
ec=$(run "$CLEAN" --confirm "$SHA"); [[ "$ec" == "0" ]] || { echo "FAIL: good confirm exit $ec"; fail=1; }
[[ ! -d "$STAGING" ]] || { echo "FAIL: staging not deleted"; fail=1; }
[[ ! -f "$TGZ" ]] || { echo "FAIL: tarball not deleted (B2)"; fail=1; }
[[ ! -d "$LEGACY" ]] || { echo "FAIL: legacy not deleted"; fail=1; }

# Relative path in receipt must be refused
echo "signed" > "$TGZ"
SHA2=$(shasum -a 256 "$TGZ" | awk '{print $1}')
mkdir -p "$STAGING"
cat > "$TMP/home/redx-ceremony/signed-tarball.receipt" <<R
tarball=relative/rottencore-signed.tgz
sha256=$SHA2
staging=$STAGING
legacy_signed=$LEGACY
R
ec=$(run "$CLEAN" --confirm "$SHA2"); [[ "$ec" != "0" ]] || { echo "FAIL: relative tarball accepted"; fail=1; }

if [[ "$fail" -eq 0 ]]; then
  echo "test-mac-cleanup: ALL PASS"
  exit 0
fi
echo "test-mac-cleanup: FAILED"
exit 1
