#!/usr/bin/env bash
# mac-sign.sh — run on Josh's Mac (xlr1-mac) over Tailscale by QA Dev.
# Idempotent. Never exports a private key. Stops on first error (including keygen).
# Key material stays in the macOS Keychain: every ceremony/sign step uses
#   rottencore-ca / rottencore --keychain --label <name>
# and never passes a private key (or `security … -w`) on argv or in the environment.
#
# Signed artifacts go to a TEMPORARY staging dir, then into one tarball for the box.
# Staging and ~/Rotten Apple Signed are NOT deleted here — QA runs mac-cleanup.sh
# only after the box has verified the tarball sha256.
#
# Required env (no hardcoded Josh account ids):
#   ROTTEN_DEV_ID   developer id for the Mega cert subject (from Red-XAI Accounts)
#   ROTTEN_TEAM_ID  team id for the Mega cert subject
set -euo pipefail

ROOT_DIR="${ROTTEN_CEREMONY_DIR:-$HOME/redx-ceremony}"
# Legacy path kept only so mac-cleanup.sh can wipe leftovers; signing writes to STAGING_DIR.
LEGACY_SIGNED_DIR="${ROTTEN_SIGNED_DIR:-$HOME/Rotten Apple Signed}"
BIN_DIR="${ROTTEN_BIN_DIR:-$HOME/redx-ceremony/bin}"
INVENTORY="${ROTTEN_INVENTORY:-$ROOT_DIR/inventory.json}"
TIERS="${ROTTEN_TIERS:-$ROOT_DIR/tiers-ed25519.json}"
MARKER_DIR="$ROOT_DIR/.done"
LOG="$ROOT_DIR/mac-sign.log"
ROTTENCORE="${BIN_DIR}/rottencore"
ROTTENCORE_CA="${BIN_DIR}/rottencore-ca"
KEYCHAIN_SERVICE="${ROTTEN_KEYCHAIN_SERVICE:-com.redx.rottencore.ca}"
STAGING_DIR="$ROOT_DIR/staging-signed"
TARBALL_OUT="${ROTTEN_SIGNED_TGZ:-$HOME/rottencore-signed.tgz}"

die() { echo "mac-sign: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG" >&2; }
done_p() { [[ -f "$MARKER_DIR/$1" ]]; }
mark() { mkdir -p "$MARKER_DIR"; date -u +%Y-%m-%dT%H:%M:%SZ > "$MARKER_DIR/$1"; }

# keychain_has LABEL — true if a RottenCore CA key with that account label already exists.
# Used so re-runs skip keygen without hiding real keygen failures behind `|| true`.
keychain_has() {
  local label="$1"
  security find-generic-password -a "$label" -s "$KEYCHAIN_SERVICE" >/dev/null 2>&1
}

[[ "$(uname -s)" == "Darwin" ]] || die "must run on Josh's Mac (got $(uname -s))"
command -v curl >/dev/null || die "curl missing"
command -v python3 >/dev/null || die "python3 missing"
command -v security >/dev/null || die "security(1) missing"
command -v shasum >/dev/null || die "shasum missing"
[[ -x "$ROTTENCORE" ]] || die "rottencore not at $ROTTENCORE"
[[ -x "$ROTTENCORE_CA" ]] || die "rottencore-ca not at $ROTTENCORE_CA"
[[ -f "$INVENTORY" ]] || die "inventory.json not at $INVENTORY"
[[ -f "$TIERS" ]] || die "tiers-ed25519.json not at $TIERS"

# Mega cert subject — must come from the live Red-XAI Accounts row (no hardcoded josh / T-josh).
[[ -n "${ROTTEN_DEV_ID:-}" ]] || die "ROTTEN_DEV_ID is not set (developer id from Red-XAI Accounts)"
[[ -n "${ROTTEN_TEAM_ID:-}" ]] || die "ROTTEN_TEAM_ID is not set (team id from Red-XAI Accounts)"

mkdir -p "$ROOT_DIR" "$STAGING_DIR" "$MARKER_DIR" "$ROOT_DIR/downloads" "$ROOT_DIR/work"
cd "$ROOT_DIR"
touch "$LOG"
log "ROTTEN_DEV_ID=$ROTTEN_DEV_ID ROTTEN_TEAM_ID=$ROTTEN_TEAM_ID staging=$STAGING_DIR"

# ---- helpers (python) ----
py_root_hex() {
  python3 -c 'import json,base64,binascii; c=json.load(open("root.cert.json")); pk=c["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print(binascii.hexlify(raw).decode())'
}
py_fp_from_cert() {
  python3 -c 'import json,base64,hashlib,sys; c=json.load(open(sys.argv[1])); pk=c["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print("sha256:"+hashlib.sha256(raw).hexdigest())' "$1"
}
py_fp_from_bundle_leaf() {
  python3 -c 'import json,base64,hashlib,sys; b=json.load(open(sys.argv[1])); chain=b.get("chain") or b; pk=chain[0]["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print("sha256:"+hashlib.sha256(raw).hexdigest())' "$1"
}

# ========== (a) production root ceremony ==========
if ! done_p ceremony-root; then
  log "=== (a) production root ceremony ==="
  if keychain_has rottencore-root; then
    die "Keychain already has label rottencore-root but ceremony-root marker is missing; refuse to re-generate. Restore the marker or delete the Keychain item deliberately."
  fi
  MIC_ARGS=()
  if [[ "${ROTTEN_MIC:-auto}" != "off" ]]; then
    MIC_ARGS=(--mic)
    log "microphone noise: enabled (optional; HKDF-mixed, never alone)"
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
  log "=== (a) root ceremony already done; skipping ==="
fi
[[ -f "$ROOT_DIR/root.cert.json" ]] || die "root.cert.json missing"
ROOT_HEX=$(py_root_hex)
ROOT_FP=$(py_fp_from_cert "$ROOT_DIR/root.cert.json")
log "root fingerprint (public): $ROOT_FP"

# ========== (b) issuing CA ==========
if ! done_p issuing-ca; then
  log "=== (b) issuing CA (Keychain label rottencore-issuing) ==="
  if keychain_has rottencore-issuing; then
    die "Keychain already has label rottencore-issuing but issuing-ca marker is missing; refuse to re-generate."
  fi
  "$ROTTENCORE_CA" issuing-csr \
    --keychain --label rottencore-issuing \
    --dir "$ROOT_DIR" --alg ed25519 --tiers "$TIERS" \
    --out "$ROOT_DIR/issuing.csr.json"
  "$ROTTENCORE_CA" sign-intermediate \
    --keychain --label rottencore-root \
    --dir "$ROOT_DIR" \
    --req "$ROOT_DIR/issuing.csr.json" \
    --alg ed25519 --tiers "$TIERS" \
    --out "$ROOT_DIR/issuing.bundle.json"
  mark issuing-ca
else
  log "=== (b) issuing CA already done; skipping ==="
fi
[[ -f "$ROOT_DIR/issuing.bundle.json" ]] || die "issuing.bundle.json missing"

# ========== (c) Mega developer cert ==========
if ! done_p mega-cert; then
  log "=== (c) Mega developer certificate (dev=$ROTTEN_DEV_ID team=$ROTTEN_TEAM_ID) ==="
  if keychain_has josh-mega; then
    log "Mega key already in Keychain (label josh-mega); skipping keygen"
  else
    log "generating Mega key in Keychain (label josh-mega)"
    "$ROTTENCORE_CA" keygen \
      --keychain --label josh-mega --alg ed25519 --tiers "$TIERS" --dir "$ROOT_DIR"
  fi
  "$ROTTENCORE_CA" request \
    --keychain --label josh-mega \
    --name "Josh Franklinn (Mega)" \
    --kind developer \
    --out "$ROOT_DIR/josh-mega.csr.json"
  "$ROTTENCORE_CA" issue \
    --keychain --label rottencore-issuing \
    --dir "$ROOT_DIR" \
    --req "$ROOT_DIR/josh-mega.csr.json" \
    --dev "$ROTTEN_DEV_ID" --team "$ROTTEN_TEAM_ID" --role developer --mega \
    --name "Josh Franklinn (Mega)" \
    --tiers "$TIERS" \
    --out "$ROOT_DIR/josh-mega.bundle.json"
  mark mega-cert
else
  log "=== (c) Mega cert already done; skipping ==="
fi
[[ -f "$ROOT_DIR/josh-mega.bundle.json" ]] || die "josh-mega.bundle.json missing"
MEGA_FP=$(py_fp_from_bundle_leaf "$ROOT_DIR/josh-mega.bundle.json")
log "Mega cert fingerprint (public): $MEGA_FP"

# ========== (d) device registration (local, migratable) ==========
if ! done_p device-register; then
  log "=== (d) register Mac device for Mega account (local store) ==="
  set +e
  STATUS=$("$ROTTENCORE" device status --json 2>/dev/null)
  set -e
  ALREADY=$(printf '%s' "$STATUS" | python3 -c 'import json,sys
try:
 j=json.load(sys.stdin); r=j.get("result") or j
 print("1" if r.get("approved") else "0")
except Exception:
 print("0")')
  if [[ "$ALREADY" != "1" ]]; then
    OUT=$("$ROTTENCORE" device register --json)
    DEV_ID=$(printf '%s' "$OUT" | python3 -c 'import json,sys; j=json.load(sys.stdin); r=j.get("result") or j; print(r.get("id") or "")')
    [[ -n "$DEV_ID" ]] || die "device register did not return an id"
    log "locally approving device $DEV_ID under team $ROTTEN_TEAM_ID (Mega)"
    "$ROTTENCORE" device approve "$DEV_ID" --team "$ROTTEN_TEAM_ID"
  else
    log "device already approved"
  fi
  mark device-register
else
  log "=== (d) device already registered; skipping ==="
fi

# ========== download / sign helpers ==========
app_meta() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys, re
repo, tag, asset, cat = sys.argv[1:5]
app_map = {
  "RottenApple": "com.redx.rottenapple",
  "quick-launch": "com.redx.quicklaunch",
  "RottenCore": "com.redx.rottencore",
  "RedX": "com.redx.redx",
  "gendragoon-cloud-ssd": "com.redx.gendragoon",
  "gendragoon-apps": "com.redx.gendragoon",
  "Gendragoon-Releases": "com.redx.gendragoon",
}
app = app_map.get(repo, "com.redx." + repo.lower().replace("_","-"))
ver = (tag or "0.0.0").lstrip("v")
if ver.startswith("untagged-"):
  ver = "0.0.0-untagged"
n = asset.lower()
if cat == "extension":
  plat = "extensions"
elif cat == "ios":
  plat = "ios"
elif cat == "linux":
  plat = "linux"
elif cat == "mac":
  if "arm64" in n or "universal" in n:
    plat = "macos-arm64"
  else:
    plat = "macos-intel"
else:
  plat = ""
print(app); print(ver); print(plat)
PY
}

download_asset() {
  local repo="$1" tag="$2" name="$3" url="$4" dest="$5"
  if [[ -f "$dest" ]]; then
    log "already have $dest"
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  log "download $repo/$tag/$name"
  local aid=""
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    aid=$(python3 - "$INVENTORY" "$repo" "$tag" "$name" <<'PY'
import json,sys
inv=json.load(open(sys.argv[1]))
repo,tag,name=sys.argv[2:5]
for r in inv["repos"].get(repo,{}).get("releases",[]):
  if (r.get("tag") or r.get("name"))==tag:
    for a in r["assets"]:
      if a["name"]==name:
        print(a["id"]); raise SystemExit
PY
)
  fi
  if [[ -n "$aid" ]]; then
    curl -sS -L --fail \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/octet-stream" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -o "$dest.partial" \
      "https://api.github.com/repos/grimvirusoffical-source/${repo}/releases/assets/${aid}"
  else
    curl -sS -L --fail -o "$dest.partial" "$url"
  fi
  mv "$dest.partial" "$dest"
}

sign_one() {
  local path="$1" app="$2" ver="$3" plat="$4"
  local rasig="${path}.rasig"
  if [[ -f "$rasig" ]]; then
    log "already signed: $(basename "$path")"
  else
    log "sign $(basename "$path") ($app $ver $plat)"
    local args=(sign "$path" --keychain --label josh-mega --bundle "$ROOT_DIR/josh-mega.bundle.json" --app "$app" --app-version "$ver")
    [[ -n "$plat" ]] && args+=(--platform "$plat")
    "$ROTTENCORE" "${args[@]}"
  fi
  "$ROTTENCORE" verify-signature "$path" "$rasig" --trust-root "$ROOT_HEX" \
    || die "verify-signature failed for $path"
}

# ========== (e) Rotten Apple Mac store: two copies in staging ==========
if ! done_p rottenapple-store; then
  log "=== (e) Rotten Apple Mac store (download x2, sign one, delete unsigned) ==="
  RA_NAME=$(python3 - "$INVENTORY" <<'PY'
import json,sys
inv=json.load(open(sys.argv[1]))
assets=[]
for r in inv["repos"].get("RottenApple",{}).get("releases",[]):
  for a in r["assets"]:
    if a["category"]=="mac" and "darwin" in a["name"].lower():
      assets.append((a["name"], a["browser_download_url"], r.get("tag") or r.get("name")))
assets.sort(key=lambda x: (0 if "arm64" in x[0] else 1, x[0]))
if not assets:
  raise SystemExit("no RottenApple mac/darwin asset")
print(assets[0][0])
PY
)
  RA_URL=$(python3 - "$INVENTORY" <<'PY'
import json,sys
inv=json.load(open(sys.argv[1]))
assets=[]
for r in inv["repos"].get("RottenApple",{}).get("releases",[]):
  for a in r["assets"]:
    if a["category"]=="mac" and "darwin" in a["name"].lower():
      assets.append((a["name"], a["browser_download_url"], r.get("tag") or r.get("name")))
assets.sort(key=lambda x: (0 if "arm64" in x[0] else 1, x[0]))
print(assets[0][1])
PY
)
  RA_TAG=$(python3 - "$INVENTORY" <<'PY'
import json,sys
inv=json.load(open(sys.argv[1]))
assets=[]
for r in inv["repos"].get("RottenApple",{}).get("releases",[]):
  for a in r["assets"]:
    if a["category"]=="mac" and "darwin" in a["name"].lower():
      assets.append((a["name"], a["browser_download_url"], r.get("tag") or r.get("name")))
assets.sort(key=lambda x: (0 if "arm64" in x[0] else 1, x[0]))
print(assets[0][2])
PY
)
  STORE_DIR="$ROOT_DIR/work/rottenapple-store"
  mkdir -p "$STORE_DIR"
  download_asset "RottenApple" "$RA_TAG" "$RA_NAME" "$RA_URL" "$STORE_DIR/unsigned-$RA_NAME"
  cp -f "$STORE_DIR/unsigned-$RA_NAME" "$STORE_DIR/signed-$RA_NAME"
  META_APP=$(app_meta "RottenApple" "$RA_TAG" "$RA_NAME" "mac" | sed -n '1p')
  META_VER=$(app_meta "RottenApple" "$RA_TAG" "$RA_NAME" "mac" | sed -n '2p')
  META_PLAT=$(app_meta "RottenApple" "$RA_TAG" "$RA_NAME" "mac" | sed -n '3p')
  sign_one "$STORE_DIR/signed-$RA_NAME" "$META_APP" "$META_VER" "$META_PLAT"
  rm -f "$STORE_DIR/unsigned-$RA_NAME"
  log "deleted unsigned copy"
  DEST="$STAGING_DIR/RottenApple/$RA_TAG"
  mkdir -p "$DEST"
  cp -f "$STORE_DIR/signed-$RA_NAME" "$DEST/$RA_NAME"
  cp -f "$STORE_DIR/signed-$RA_NAME.rasig" "$DEST/$RA_NAME.rasig"
  mark rottenapple-store
else
  log "=== (e) Rotten Apple store already signed; skipping ==="
fi

# ========== (f) every Mac / iOS / Linux / extension asset (latest-only inventory) ==========
log "=== (f) sign every Mac/iOS/Linux/extension asset (staging) ==="
python3 - "$INVENTORY" <<'PY' > "$ROOT_DIR/work/sign-list.tsv"
import json,sys
inv=json.load(open(sys.argv[1]))
for a in inv["sign_on_mac"]:
  print("\t".join([a["repo"], a["tag"], a["asset"], a["url"], a["category"], str(a["size"])]))
PY

while IFS=$'\t' read -r REPO TAG ASSET URL CAT SIZE; do
  [[ -z "${REPO:-}" ]] && continue
  MARK="sign-$(printf '%s' "$REPO/$TAG/$ASSET" | tr '/ ' '__')"
  if done_p "$MARK"; then
    log "skip (done): $REPO/$TAG/$ASSET"
    continue
  fi
  DEST_DIR="$STAGING_DIR/$REPO/$TAG"
  mkdir -p "$DEST_DIR"
  LOCAL="$DEST_DIR/$ASSET"
  download_asset "$REPO" "$TAG" "$ASSET" "$URL" "$LOCAL"
  META_APP=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '1p')
  META_VER=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '2p')
  META_PLAT=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '3p')
  sign_one "$LOCAL" "$META_APP" "$META_VER" "$META_PLAT"
  [[ -f "$LOCAL.rasig" ]] || die "missing rasig for $LOCAL"
  mark "$MARK"
done < "$ROOT_DIR/work/sign-list.tsv"

# ========== (g) regenerate SHA256SUMS per release in staging ==========
log "=== (g) regenerate SHA256SUMS per release ==="
find "$STAGING_DIR" -mindepth 2 -maxdepth 2 -type d | while read -r d; do
  log "SHA256SUMS in $d"
  python3 - "$d" <<'PY'
import hashlib, pathlib, sys
d = pathlib.Path(sys.argv[1])
lines = []
for f in sorted(d.iterdir()):
  if not f.is_file(): continue
  if f.name == "SHA256SUMS" or f.name.endswith(".rasig"): continue
  h = hashlib.sha256(f.read_bytes()).hexdigest()
  lines.append(f"{h}  {f.name}")
(d / "SHA256SUMS").write_text("\n".join(lines) + ("\n" if lines else ""))
print(f"  {len(lines)} files")
PY
done

# ========== (h) pack tarball for the box (no Mac copies kept after cleanup) ==========
log "=== (h) pack signed staging + public certs into $TARBALL_OUT ==="
# Layout inside the tarball matches what publish.sh / QA-README expect after extract on the box:
#   signed/<repo>/<tag>/…   plus public ceremony JSON next to it under ceremony/
PACK_ROOT="$ROOT_DIR/work/pack"
rm -rf "$PACK_ROOT"
mkdir -p "$PACK_ROOT/signed" "$PACK_ROOT/ceremony"
# Copy staging tree under signed/
cp -R "$STAGING_DIR/." "$PACK_ROOT/signed/"
cp -f "$ROOT_DIR/root.cert.json" "$PACK_ROOT/ceremony/"
cp -f "$ROOT_DIR/issuing.bundle.json" "$PACK_ROOT/ceremony/"
cp -f "$ROOT_DIR/josh-mega.bundle.json" "$PACK_ROOT/ceremony/"
cp -f "$LOG" "$PACK_ROOT/ceremony/mac-sign.log" 2>/dev/null || true
# Also keep a "Rotten Apple Signed" alias path for docs that still mention it
mkdir -p "$PACK_ROOT/Rotten Apple Signed"
cp -R "$STAGING_DIR/." "$PACK_ROOT/Rotten Apple Signed/"
(
  cd "$PACK_ROOT"
  tar -czf "$TARBALL_OUT" signed ceremony "Rotten Apple Signed"
)
TGZ_SHA=$(shasum -a 256 "$TARBALL_OUT" | awk '{print $1}')
echo "$TGZ_SHA" > "${TARBALL_OUT}.sha256"
# Receipt for mac-cleanup.sh — do NOT delete until the box verifies this hash
cat > "$ROOT_DIR/signed-tarball.receipt" <<RECEIPT
tarball=$TARBALL_OUT
sha256=$TGZ_SHA
staging=$STAGING_DIR
legacy_signed=$LEGACY_SIGNED_DIR
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RECEIPT
log "tarball sha256=$TGZ_SHA"
log "receipt written to $ROOT_DIR/signed-tarball.receipt"
log "DO NOT delete staging yet — copy the tarball to the box, verify sha256 there, then run mac-cleanup.sh"

# ========== (i) public fingerprints only ==========
echo
echo "===== PUBLIC FINGERPRINTS (safe to share) ====="
echo "ROOT_FINGERPRINT=$ROOT_FP"
echo "MEGA_FINGERPRINT=$MEGA_FP"
echo "ROOT_PUBLIC_KEY_HEX=$ROOT_HEX"
echo "ROOT_CERT_JSON=$ROOT_DIR/root.cert.json"
echo "MEGA_BUNDLE_JSON=$ROOT_DIR/josh-mega.bundle.json"
echo "ISSUING_BUNDLE_JSON=$ROOT_DIR/issuing.bundle.json"
echo "SIGNED_TARBALL=$TARBALL_OUT"
echo "SIGNED_TARBALL_SHA256=$TGZ_SHA"
echo "STAGING_DIR=$STAGING_DIR"
echo "===== END ====="
echo
echo "NEXT: scp $TARBALL_OUT to the box; on the box run:"
echo "  sha256sum -c <(echo \"$TGZ_SHA  rottencore-signed.tgz\")"
echo "After the box confirms the hash, run:  ./mac-cleanup.sh"
log "mac-sign.sh finished OK (staging retained until mac-cleanup.sh)"
