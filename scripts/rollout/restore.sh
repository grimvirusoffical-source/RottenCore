#!/usr/bin/env bash
# restore.sh — put /workspace/release-backups/ originals back onto GitHub releases, and/or
# republish releases that publish.sh converted to draft (--undraft).
# Uses MANIFEST.json written by the backup step. --dry-run prints the plan only.
#
# Usage:
#   ./restore.sh [--dry-run]              # restore asset bytes from backups
#   ./restore.sh --undraft [--dry-run]    # set draft=false on releases listed in
#                                         # work/publish-plan.json convert_to_draft (or
#                                         # ROTTEN_UNDRAFT_LIST / work/latest-only-report.json)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKUP="${ROTTEN_BACKUPS:-/workspace/release-backups}"
INVENTORY="${ROTTEN_INVENTORY:-$ROOT/inventory.json}"
MANIFEST="$BACKUP/MANIFEST.json"
DRY_RUN=0
UNDRAFT=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --undraft) UNDRAFT=1 ;;
    *) echo "restore: unknown arg $arg" >&2; exit 2 ;;
  esac
done

die() { echo "restore: ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN not set"
[[ -f "$MANIFEST" ]] || die "backup manifest missing: $MANIFEST"
[[ -f "$INVENTORY" ]] || die "inventory missing: $INVENTORY"

OWNER=grimvirusoffical-source
API=https://api.github.com

if [[ "$UNDRAFT" == "1" ]]; then
  python3 - "$ROOT" "$OWNER" "$API" "$DRY_RUN" <<'PY'
import json, os, sys, subprocess, time
from pathlib import Path

root, owner, api, dry = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4] == "1"
token = os.environ["GITHUB_TOKEN"]
headers = ["-H", f"Authorization: Bearer {token}", "-H", "Accept: application/vnd.github+json",
           "-H", "X-GitHub-Api-Version: 2022-11-28", "-H", "Content-Type: application/json"]

candidates = []
plan = root / "work" / "publish-plan.json"
report = root / "work" / "latest-only-report.json"
if plan.exists():
    p = json.load(open(plan))
    candidates = p.get("convert_to_draft") or []
elif report.exists():
    candidates = json.load(open(report)).get("will_become_drafts") or []
else:
    raise SystemExit("no publish-plan.json or latest-only-report.json — nothing to undraft")

print(f"undraft plan: {len(candidates)} releases (dry_run={dry})", flush=True)
for c in candidates:
    print(f"  {c['repo']}/{c['tag']} release_id={c['release_id']}", flush=True)
if dry:
    raise SystemExit(0)

for c in candidates:
    url = f"{api}/repos/{owner}/{c['repo']}/releases/{c['release_id']}"
    r = subprocess.run(["curl", "-sS", "-X", "PATCH", *headers, "--data", json.dumps({"draft": False}), url],
                       capture_output=True, text=True)
    data = json.loads(r.stdout)
    if data.get("draft") is not False and data.get("draft") != False:
        # GitHub may return draft:false
        if data.get("draft"):
            raise SystemExit(f"undraft failed for {c}: {r.stdout[:400]}")
    print(f"UNDRAFT {c['repo']}/{c['tag']} draft={data.get('draft')}", flush=True)

print("undraft finished OK", flush=True)
PY
  exit 0
fi

python3 - "$MANIFEST" "$INVENTORY" "$OWNER" "$API" "$DRY_RUN" <<'PY'
import json, os, sys, subprocess, urllib.parse, time

manifest = json.load(open(sys.argv[1]))
inv = json.load(open(sys.argv[2]))
owner, api, dry = sys.argv[3], sys.argv[4], sys.argv[5] == "1"
token = os.environ["GITHUB_TOKEN"]
headers = ["-H", f"Authorization: Bearer {token}", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]

# Prefer full inventory for older releases that were drafted
from pathlib import Path
full_path = Path(sys.argv[2]).with_name("inventory.full.json")
if full_path.exists():
    inv = json.load(open(full_path))

index = {}
for repo, data in inv["repos"].items():
  for r in data["releases"]:
    tag = r.get("tag") or r.get("name")
    for a in r["assets"]:
      index[(repo, tag, a["name"])] = {"release_id": r["id"], "asset_id": a["id"], "label": a.get("label") or ""}

def curl(args):
  r = subprocess.run(["curl", "-sS", *args], capture_output=True, text=True)
  if r.returncode != 0:
    raise SystemExit(r.stderr or r.stdout)
  return r

actions = []
for a in manifest["assets"]:
  key = (a["repo"], a["tag"], a["name"])
  meta = index.get(key)
  if not meta:
    print(f"WARN: {key} not in inventory; skip", flush=True)
    continue
  actions.append({**a, **meta})

print(f"restore plan: {len(actions)} assets (dry_run={dry})", flush=True)
if dry:
  for a in actions[:30]:
    print(f"  would restore {a['repo']}/{a['tag']}/{a['name']} from {a['path']}")
  if len(actions) > 30:
    print(f"  ... and {len(actions)-30} more")
  raise SystemExit(0)

for a in actions:
  print(f"RESTORE {a['repo']}/{a['tag']}/{a['name']}", flush=True)
  url = f"{api}/repos/{owner}/{a['repo']}/releases/assets/{a['asset_id']}"
  r = subprocess.run(["curl", "-sS", "-X", "DELETE", *headers, "-o", "/dev/null", "-w", "%{http_code}", url], capture_output=True, text=True)
  if r.stdout.strip() not in ("204", "404"):
    raise SystemExit(f"delete failed: {r.stdout} {r.stderr}")
  q = urllib.parse.urlencode({"name": a["name"], "label": a["label"]} if a["label"] else {"name": a["name"]})
  up = f"https://uploads.github.com/repos/{owner}/{a['repo']}/releases/{a['release_id']}/assets?{q}"
  r = subprocess.run(["curl", "-sS", "-X", "POST", *headers, "-H", "Content-Type: application/octet-stream",
                      "--data-binary", f"@{a['path']}", up], capture_output=True, text=True)
  data = json.loads(r.stdout)
  if "id" not in data:
    raise SystemExit(f"upload failed: {r.stdout[:400]}")
  print(f"  restored id={data['id']}", flush=True)

print("restore finished OK", flush=True)
PY
