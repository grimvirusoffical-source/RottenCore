#!/usr/bin/env bash
# publish.sh — run on the box AFTER signed files land in /workspace/rollout/signed/<repo>/<tag>/.
# Replaces each asset in place on GitHub (EXACT original filename and label), uploads .rasig sidecars,
# replaces SHA256SUMS. Then converts every OTHER (older) release in those repos to a draft — only when
# every asset of that release is fully backed up under /workspace/release-backups (sha256 verified).
# Git tags are left alone. --dry-run prints the plan without changing GitHub.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
INVENTORY="${ROTTEN_INVENTORY:-$ROOT/inventory.json}"
SIGNED="${ROTTEN_SIGNED_IN:-$ROOT/signed}"
BACKUP="${ROTTEN_BACKUPS:-/workspace/release-backups}"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR" "$ROOT/work"
LOG="$LOG_DIR/publish-$(date -u +%Y%m%dT%H%M%SZ).log"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

die() { echo "publish: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG" >&2; }

[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN not set"
[[ -f "$INVENTORY" ]] || die "inventory missing: $INVENTORY"
[[ -f "$BACKUP/MANIFEST.json" ]] || die "backup MANIFEST.json missing: $BACKUP/MANIFEST.json"
command -v curl >/dev/null || die "curl missing"
command -v python3 >/dev/null || die "python3 missing"

OWNER=grimvirusoffical-source
API=https://api.github.com

log "publish starting dry_run=$DRY_RUN signed=$SIGNED"

PLAN=$ROOT/work/publish-plan.json

python3 - "$INVENTORY" "$SIGNED" "$BACKUP" "$PLAN" <<'PY'
import hashlib, json, pathlib, sys

inv = json.load(open(sys.argv[1]))
signed_root = pathlib.Path(sys.argv[2])
backup = pathlib.Path(sys.argv[3])
manifest = json.load(open(backup / "MANIFEST.json"))
by_key = {(a["repo"], a["tag"], a["name"]): a for a in manifest["assets"]}

plan = {
    "replacements": [], "rasigs": [], "sums": [], "missing_signed": [],
    "skipped_deferred": inv.get("deferred_windows_android", []),
    "convert_to_draft": [], "convert_to_draft_blocked": [],
    "flagged_newer_drafts": inv.get("flagged_newer_drafts", []),
}

rel_index = {}
for repo, data in inv["repos"].items():
    for r in data["releases"]:
        tag = r.get("tag") or r.get("name")
        rel_index[(repo, tag)] = r

touched = set()

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

for a in inv.get("sign_on_mac", []):
    repo, tag, name = a["repo"], a["tag"], a["asset"]
    local = signed_root / repo / tag / name
    rasig = pathlib.Path(str(local) + ".rasig")
    if not local.exists():
        plan["missing_signed"].append({"repo": repo, "tag": tag, "asset": name, "expected": str(local)})
        continue
    rel = rel_index.get((repo, tag))
    if not rel:
        plan["missing_signed"].append({"repo": repo, "tag": tag, "asset": name, "error": "release not in inventory"})
        continue
    match = next((x for x in rel["assets"] if x["name"] == name), None)
    if not match:
        plan["missing_signed"].append({"repo": repo, "tag": tag, "asset": name, "error": "asset not on release"})
        continue
    plan["replacements"].append({
        "repo": repo, "tag": tag, "release_id": rel["id"],
        "name": name, "asset_id": match["id"], "label": match.get("label") or "",
        "local": str(local), "size": local.stat().st_size,
    })
    if rasig.exists():
        plan["rasigs"].append({
            "repo": repo, "tag": tag, "release_id": rel["id"],
            "name": name + ".rasig", "local": str(rasig), "size": rasig.stat().st_size,
            "label": (match.get("label") or "") + " (signature)" if match.get("label") else "RottenCore signature",
        })
    touched.add((repo, tag))

for repo, tag in sorted(touched):
    rel = rel_index[(repo, tag)]
    sums_local = signed_root / repo / tag / "SHA256SUMS"
    if not sums_local.exists():
        alt = signed_root / repo / tag / "SHA256SUMS.txt"
        if alt.exists():
            sums_local = alt
    if not sums_local.exists():
        continue
    existing = None
    for x in rel["assets"]:
        if x.get("category") == "checksum" or x["name"] in ("SHA256SUMS", "SHA256SUMS.txt", "CHECKSUMS"):
            existing = x
            break
    plan["sums"].append({
        "repo": repo, "tag": tag, "release_id": rel["id"],
        "name": existing["name"] if existing else "SHA256SUMS",
        "asset_id": existing["id"] if existing else None,
        "label": (existing.get("label") if existing else None) or "",
        "local": str(sums_local), "size": sums_local.stat().st_size,
    })

# Draft conversion candidates from inventory (older published releases).
# Full inventory (all releases) may be at inventory.full.json for asset lists.
full_path = pathlib.Path(sys.argv[1]).with_name("inventory.full.json")
full = json.load(open(full_path)) if full_path.exists() else inv
candidates = inv.get("full_releases_for_draft_conversion") or []
for c in candidates:
    repo, tag, rid = c["repo"], c["tag"], c["release_id"]
    rel = None
    for r in full["repos"].get(repo, {}).get("releases", []):
        if (r.get("tag") or r.get("name")) == tag:
            rel = r
            break
    if not rel:
        plan["convert_to_draft_blocked"].append({**c, "reason": "release not in inventory.full.json"})
        continue
    missing = []
    for a in rel.get("assets") or []:
        key = (repo, tag, a["name"])
        path = backup / repo / tag / a["name"]
        m = by_key.get(key)
        if not path.is_file() or not m:
            missing.append(a["name"])
            continue
        if sha256(path) != m["sha256"]:
            missing.append(a["name"] + " (sha256 mismatch)")
    if missing:
        plan["convert_to_draft_blocked"].append({**c, "reason": "backup incomplete", "missing": missing})
    else:
        plan["convert_to_draft"].append({
            "repo": repo, "tag": tag, "release_id": rid,
            "assets_verified": len(rel.get("assets") or []),
            "note": "git tag left alone; reversible via restore.sh --undraft",
        })

json.dump(plan, open(sys.argv[4], "w"), indent=2)
print(
    f"plan: {len(plan['replacements'])} replacements, {len(plan['rasigs'])} rasigs, "
    f"{len(plan['sums'])} sums, {len(plan['missing_signed'])} missing, "
    f"{len(plan['convert_to_draft'])} → draft, {len(plan['convert_to_draft_blocked'])} draft-blocked"
)
PY

log "plan written to $PLAN"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(json.dumps({k:(len(v) if isinstance(v,list) else v) for k,v in p.items()}, indent=2))' "$PLAN" | tee -a "$LOG"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY RUN — no GitHub changes. Full plan: $PLAN"
  python3 - "$PLAN" <<'PY' | tee -a "$LOG"
import json,sys
p=json.load(open(sys.argv[1]))
print("\n=== DRY-RUN SUMMARY ===")
print(f"Would REPLACE {len(p['replacements'])} assets (exact name + label):")
for r in p["replacements"][:30]:
  print(f"  {r['repo']}/{r['tag']}/{r['name']}  (id={r['asset_id']}, label={r['label']!r}, local_size={r['size']})")
if len(p["replacements"])>30: print(f"  ... and {len(p['replacements'])-30} more")
print(f"Would UPLOAD {len(p['rasigs'])} .rasig sidecars")
print(f"Would REPLACE/UPLOAD {len(p['sums'])} SHA256SUMS")
print(f"Missing signed copies: {len(p['missing_signed'])}")
for m in p["missing_signed"][:10]:
  print(f"  MISSING {m}")
print(f"Deferred (untouched): {len(p['skipped_deferred'])} windows/android")
print(f"\nWould CONVERT TO DRAFT {len(p['convert_to_draft'])} older releases (tags kept):")
for c in p["convert_to_draft"]:
  print(f"  {c['repo']}/{c['tag']}  release_id={c['release_id']}  assets_verified={c['assets_verified']}")
if p["convert_to_draft_blocked"]:
  print(f"BLOCKED from draft conversion ({len(p['convert_to_draft_blocked'])}):")
  for c in p["convert_to_draft_blocked"]:
    print(f"  {c}")
if p.get("flagged_newer_drafts"):
  print("Flagged newer drafts (not signed; newest published used):")
  for f in p["flagged_newer_drafts"]:
    print(f"  {f}")
print("=== END DRY-RUN ===")
PY
  exit 0
fi

# ---- live publish ----
python3 - "$PLAN" "$OWNER" "$API" "$LOG" <<'PY'
import json, os, sys, subprocess, urllib.parse, time

plan = json.load(open(sys.argv[1]))
owner, api, log_path = sys.argv[2], sys.argv[3], sys.argv[4]
token = os.environ["GITHUB_TOKEN"]
headers = [
  "-H", f"Authorization: Bearer {token}",
  "-H", "Accept: application/vnd.github+json",
  "-H", "X-GitHub-Api-Version: 2022-11-28",
]

def log(msg):
  line = time.strftime("[%Y-%m-%dT%H:%M:%SZ] ", time.gmtime()) + msg
  print(line, flush=True)
  open(log_path, "a").write(line + "\n")

def curl(args, check=True):
  r = subprocess.run(["curl", "-sS", *args], capture_output=True, text=True)
  if check and r.returncode != 0:
    raise SystemExit(f"curl failed: {r.stderr}\n{r.stdout}")
  return r

def delete_asset_repo(repo, asset_id):
  url = f"{api}/repos/{owner}/{repo}/releases/assets/{asset_id}"
  r = curl(["-X", "DELETE", *headers, "-o", "/dev/null", "-w", "%{http_code}", url], check=False)
  code = r.stdout.strip()
  if code not in ("204", "404"):
    raise SystemExit(f"delete asset {asset_id} returned {code}: {r.stderr}")
  log(f"deleted asset id={asset_id} http={code}")

def upload(repo, release_id, name, label, path):
  q = urllib.parse.urlencode({"name": name, "label": label} if label else {"name": name})
  url = f"https://uploads.github.com/repos/{owner}/{repo}/releases/{release_id}/assets?{q}"
  r = curl([
    "-X", "POST", *headers,
    "-H", "Content-Type: application/octet-stream",
    "--data-binary", f"@{path}",
    url,
  ])
  data = json.loads(r.stdout)
  if "id" not in data:
    raise SystemExit(f"upload failed for {name}: {r.stdout[:500]}")
  log(f"uploaded {repo}/{name} -> asset id={data['id']} size={data.get('size')}")
  return data

for item in plan["replacements"]:
  log(f"REPLACE {item['repo']}/{item['tag']}/{item['name']}")
  delete_asset_repo(item["repo"], item["asset_id"])
  upload(item["repo"], item["release_id"], item["name"], item["label"], item["local"])

for item in plan["rasigs"]:
  log(f"UPLOAD rasig {item['repo']}/{item['tag']}/{item['name']}")
  r = curl([*headers, f"{api}/repos/{owner}/{item['repo']}/releases/{item['release_id']}/assets?per_page=100"])
  assets = json.loads(r.stdout)
  for a in assets:
    if a["name"] == item["name"]:
      delete_asset_repo(item["repo"], a["id"])
      break
  upload(item["repo"], item["release_id"], item["name"], item["label"], item["local"])

for item in plan["sums"]:
  log(f"SUMS {item['repo']}/{item['tag']}/{item['name']}")
  if item.get("asset_id"):
    delete_asset_repo(item["repo"], item["asset_id"])
  upload(item["repo"], item["release_id"], item["name"], item["label"], item["local"])

# Convert older releases to draft (reversible; tags untouched)
for item in plan["convert_to_draft"]:
  log(f"DRAFT {item['repo']}/{item['tag']} release_id={item['release_id']}")
  url = f"{api}/repos/{owner}/{item['repo']}/releases/{item['release_id']}"
  r = curl(["-X", "PATCH", *headers, "-H", "Content-Type: application/json",
            "--data", json.dumps({"draft": True}), url])
  data = json.loads(r.stdout)
  if not data.get("draft"):
    raise SystemExit(f"failed to convert to draft: {r.stdout[:400]}")
  log(f"  now draft=true (tag kept)")

log("publish finished OK")
print(json.dumps({
  "ok": True,
  "replacements": len(plan["replacements"]),
  "rasigs": len(plan["rasigs"]),
  "sums": len(plan["sums"]),
  "converted_to_draft": len(plan["convert_to_draft"]),
}))
PY
