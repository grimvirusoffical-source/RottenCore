#!/usr/bin/env bash
# phase-sign: latest-only download → digest check vs backup MANIFEST → sign → staging → tarball.
# Does NOT delete staging (mac-cleanup.sh after box verifies sha256).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
require_darwin
setup_rollout_env

[[ -x "$ROTTENCORE" ]] || die "rottencore not at $ROTTENCORE"
[[ -f "$INVENTORY" ]] || die "inventory missing: $INVENTORY"
[[ -f "$ROOT_DIR/josh-mega.bundle.json" ]] || die "josh-mega.bundle.json missing — run phase-pair first"
[[ -f "$ROOT_DIR/root.cert.json" ]] || die "root.cert.json missing — run phase-root first"

ROOT_HEX=$(python3 -c 'import json,base64,binascii; c=json.load(open("'"$ROOT_DIR"'/root.cert.json")); pk=c["publicKey"]; raw=base64.b64decode(pk) if isinstance(pk,str) else bytes(pk); print(binascii.hexlify(raw).decode())')

app_meta() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
repo, tag, asset, cat = sys.argv[1:5]
app_map = {
  "RottenApple": "com.redx.rottenapple", "quick-launch": "com.redx.quicklaunch",
  "RottenCore": "com.redx.rottencore", "RedX": "com.redx.redx",
  "gendragoon-cloud-ssd": "com.redx.gendragoon", "gendragoon-apps": "com.redx.gendragoon",
  "Gendragoon-Releases": "com.redx.gendragoon",
}
app = app_map.get(repo, "com.redx." + repo.lower().replace("_","-"))
ver = (tag or "0.0.0").lstrip("v")
if ver.startswith("untagged-"): ver = "0.0.0-untagged"
n = asset.lower()
if cat == "extension": plat = "extensions"
elif cat == "ios": plat = "ios"
elif cat == "linux": plat = "linux"
elif cat == "mac":
  plat = "macos-arm64" if ("arm64" in n or "universal" in n) else "macos-intel"
else: plat = ""
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
  local aid
  aid=$(python3 - "$INVENTORY" "$repo" "$tag" "$name" <<'PY'
import json,sys
inv=json.load(open(sys.argv[1])); repo,tag,name=sys.argv[2:5]
for r in inv["repos"].get(repo,{}).get("releases",[]):
  if (r.get("tag") or r.get("name"))==tag:
    for a in r["assets"]:
      if a["name"]==name: print(a["id"]); raise SystemExit
PY
)
  [[ -n "$aid" ]] || die "no asset id for $repo/$tag/$name"
  curl_github "https://api.github.com/repos/grimvirusoffical-source/${repo}/releases/assets/${aid}" \
    -o "$dest.partial"
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

log "=== phase-sign: latest-only assets ==="
python3 - "$INVENTORY" <<'PY' > "$ROOT_DIR/work/sign-list.tsv"
import json,sys
inv=json.load(open(sys.argv[1]))
for a in inv["sign_on_mac"]:
  print("\t".join([a["repo"], a["tag"], a["asset"], a.get("url",""), a["category"], str(a.get("size",0))]))
PY

while IFS=$'\t' read -r REPO TAG ASSET URL CAT SIZE; do
  [[ -z "${REPO:-}" ]] && continue
  MARK="sign-$(printf '%s' "$REPO/$TAG/$ASSET" | tr '/ ' '__')"
  if done_p "$MARK"; then
    # After cleanup, markers without files must re-sign — check staging file exists
    if [[ -f "$STAGING_DIR/$REPO/$TAG/$ASSET.rasig" ]]; then
      log "skip (done): $REPO/$TAG/$ASSET"
      continue
    fi
    log "marker present but staging file missing — re-signing $REPO/$TAG/$ASSET"
  fi
  DEST_DIR="$STAGING_DIR/$REPO/$TAG"
  mkdir -p "$DEST_DIR"
  LOCAL="$DEST_DIR/$ASSET"
  download_asset "$REPO" "$TAG" "$ASSET" "$URL" "$LOCAL"
  # Integrity vs box backup MANIFEST before signing
  if [[ -f "${ROTTEN_BACKUPS:-/workspace/release-backups}/MANIFEST.json" ]]; then
    verify_backup_digest "$REPO" "$TAG" "$ASSET" "$LOCAL"
  else
    log "WARN: no ROTTEN_BACKUPS MANIFEST on this Mac — skipping digest check (box should have verified)"
  fi
  META_APP=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '1p')
  META_VER=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '2p')
  META_PLAT=$(app_meta "$REPO" "$TAG" "$ASSET" "$CAT" | sed -n '3p')
  sign_one "$LOCAL" "$META_APP" "$META_VER" "$META_PLAT"
  [[ -f "$LOCAL.rasig" ]] || die "missing rasig for $LOCAL"
  mark "$MARK"
done < "$ROOT_DIR/work/sign-list.tsv"

log "=== SHA256SUMS ==="
find "$STAGING_DIR" -mindepth 2 -maxdepth 2 -type d | while read -r d; do
  python3 - "$d" <<'PY'
import hashlib, pathlib, sys
d = pathlib.Path(sys.argv[1])
lines = []
for f in sorted(d.iterdir()):
  if not f.is_file() or f.name == "SHA256SUMS" or f.name.endswith(".rasig"): continue
  lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
(d / "SHA256SUMS").write_text("\n".join(lines) + ("\n" if lines else ""))
print(d, len(lines), "files")
PY
done

log "=== pack tarball (signed/ + ceremony/ only — no duplicate tree) ==="
PACK_ROOT="$ROOT_DIR/work/pack"
rm -rf "$PACK_ROOT"
mkdir -p "$PACK_ROOT/signed" "$PACK_ROOT/ceremony"
cp -R "$STAGING_DIR/." "$PACK_ROOT/signed/"
cp -f "$ROOT_DIR/root.cert.json" "$PACK_ROOT/ceremony/"
cp -f "$ROOT_DIR/issuing.bundle.json" "$PACK_ROOT/ceremony/" 2>/dev/null || true
cp -f "$ROOT_DIR/josh-mega.bundle.json" "$PACK_ROOT/ceremony/"
cp -f "$LOG" "$PACK_ROOT/ceremony/mac-sign.log" 2>/dev/null || true
(
  cd "$PACK_ROOT"
  tar -czf "$TARBALL_OUT" signed ceremony
)
TGZ_SHA=$(shasum -a 256 "$TARBALL_OUT" | awk '{print $1}')
echo "$TGZ_SHA  $(basename "$TARBALL_OUT")" > "${TARBALL_OUT}.sha256"
# Receipt with correct absolute paths (QA B2)
cat > "$ROOT_DIR/signed-tarball.receipt" <<RECEIPT
tarball=$TARBALL_OUT
sha256=$TGZ_SHA
staging=$STAGING_DIR
legacy_signed=${ROTTEN_SIGNED_DIR:-$HOME/Rotten Apple Signed}
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RECEIPT
require_abs "$TARBALL_OUT" "tarball"
require_abs "$STAGING_DIR" "staging"

echo
echo "===== phase-sign OK ====="
echo "SIGNED_TARBALL=$TARBALL_OUT"
echo "SIGNED_TARBALL_SHA256=$TGZ_SHA"
echo "STAGING_DIR=$STAGING_DIR"
echo "NEXT: scp tarball to box; sha256sum -c; then mac-cleanup.sh --confirm $TGZ_SHA"
echo "===== END ====="
log "phase-sign finished OK"
