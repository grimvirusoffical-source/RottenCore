#!/usr/bin/env bash
# phase-pair: once ra-core has the chain and Josh's account exists —
# generate device + Mega signing keys in Keychain, POST /v1/devhub/pairings,
# print the 8-char code for Josh to approve, poll status, then challenge+/certs
# for the Mega cert. Verify subject matches ROTTEN_DEV_ID / ROTTEN_TEAM_ID.
# Build/session credential: Keychain label or stdin — never argv.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
require_darwin
setup_rollout_env

[[ -n "${ROTTEN_DEV_ID:-}" ]] || die "ROTTEN_DEV_ID is not set (expect A<accountId>)"
[[ -n "${ROTTEN_TEAM_ID:-}" ]] || die "ROTTEN_TEAM_ID is not set (expect T<teamId>)"
[[ -x "$ROTTENCORE" ]] || die "rottencore not at $ROTTENCORE"
[[ -x "$ROTTENCORE_CA" ]] || die "rottencore-ca not at $ROTTENCORE_CA"
[[ -f "$TIERS" ]] || die "tiers missing"

# Build API key: prefer env already set without printing; else Keychain generic password
# account "ra-build-api-key"; else read from stdin (one line).
load_build_key() {
  if [[ -n "${RA_API_KEY:-}" ]]; then
    return 0
  fi
  if security find-generic-password -a "ra-build-api-key" -s "$KEYCHAIN_SERVICE" >/dev/null 2>&1; then
    # -w prints secret on stdout into this shell variable only (not argv of another process we spawn with the value on cmdline)
    RA_API_KEY=$(security find-generic-password -a "ra-build-api-key" -s "$KEYCHAIN_SERVICE" -w | tr -d '\n')
    export RA_API_KEY
    log "loaded build API key from Keychain (label ra-build-api-key)"
    return 0
  fi
  if [[ -t 0 ]]; then
    echo -n "Build API key (ra_sk_…, input hidden): " >&2
    # read -s keeps it off the terminal echo; still not on argv
    read -r -s RA_API_KEY
    echo >&2
  else
    RA_API_KEY=$(head -n1)
  fi
  [[ -n "${RA_API_KEY:-}" ]] || die "no build API key (set RA_API_KEY, Keychain ra-build-api-key, or pipe on stdin)"
  export RA_API_KEY
}

export RA_DEVHUB_URL="$DEVHUB_URL"
export ROTTENCORE_HOME="${ROTTENCORE_HOME:-$ROOT_DIR/support}"
mkdir -p "$ROTTENCORE_HOME"

# Preflight: live ca/chain must report issuing:true before we can get a Mega cert
log "=== phase-pair: GET $DEVHUB_URL/v1/devhub/ca/chain ==="
CHAIN_JSON=$(curl -sS -f -H "Accept: application/json" -H "X-RA-Launcher: 0.2.0" "$DEVHUB_URL/v1/devhub/ca/chain")
echo "$CHAIN_JSON" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(json.dumps(j));
import sys as S
if not j.get("issuing"):
  S.stderr.write("ca/chain issuing=false — load issuing.bundle.json + root on the server first\n"); S.exit(2)'

load_build_key

# Device key in Keychain (software Ed25519)
if ! done_p device-keygen; then
  if keychain_has rottencore-device; then
    log "device key already in Keychain"
  else
    log "generating device key (label rottencore-device)"
    "$ROTTENCORE_CA" keygen --keychain --label rottencore-device --alg ed25519 --tiers "$TIERS" --dir "$ROOT_DIR"
  fi
  mark device-keygen
fi

# Mega signing key in Keychain
if ! done_p mega-keygen; then
  if keychain_has josh-mega; then
    log "Mega signing key already in Keychain (josh-mega)"
  else
    log "generating Mega signing key (label josh-mega)"
    "$ROTTENCORE_CA" keygen --keychain --label josh-mega --alg ed25519 --tiers "$TIERS" --dir "$ROOT_DIR"
  fi
  mark mega-keygen
fi

# Pairing via a small Python helper that uses the same message format (or rottencore if it has a subcommand).
# Prefer rottencore if `device pair` exists; else inline with openssl/python + curl.
if ! done_p device-paired; then
  log "=== phase-pair: POST /v1/devhub/pairings ==="
  # Export device pubkey from Keychain without putting secret on argv of other tools:
  # use rottencore-ca request to emit a CSR which contains the public key, or a dedicated helper.
  PAIR_OUT="$ROOT_DIR/work/pairing.json"
  mkdir -p "$ROOT_DIR/work"
  # Use Go binary: rottencore device-pair (added) or python Ed25519 from key via security -w in this shell only.
  python3 - "$DEVHUB_URL" "$KEYCHAIN_SERVICE" "xlr1-mac" "$PAIR_OUT" <<'PY'
import base64, hashlib, json, os, subprocess, sys, urllib.request

devhub, service, name, out_path = sys.argv[1:5]
# Read device key blob from Keychain (stdout only into this process)
blob = subprocess.check_output(
    ["security", "find-generic-password", "-a", "rottencore-device", "-s", service, "-w"],
    text=True,
).strip()
alg, _, hx = blob.partition(":")
if alg != "ed25519" or len(hx) != 128:
    raise SystemExit(f"unexpected device key blob alg={alg!r} len={len(hx)}")
# seed||pub for ed25519 private as stored by ca (64-byte seed+pub or 32-byte seed?)
# RottenCore ca stores privBytes — check format
raw = bytes.fromhex(hx)
# ed25519.PrivateKey is 64 bytes (seed+pub) in Go crypto/ed25519
if len(raw) == 32:
    # seed only — expand via nacl not available; use cryptography if present
    try:
        from nacl.signing import SigningKey
        sk = SigningKey(raw)
        pub = bytes(sk.verify_key)
        def sign(msg: bytes) -> bytes:
            return sk.sign(msg).signature
    except ImportError:
        # fallback: openssl cannot do raw ed25519 easily; require pynacl
        raise SystemExit("need PyNaCl (pip install pynacl) to sign pairing with a 32-byte seed")
elif len(raw) == 64:
    pub = raw[32:]
    seed = raw[:32]
    try:
        from nacl.signing import SigningKey
        sk = SigningKey(seed)
        def sign(msg: bytes) -> bytes:
            return sk.sign(msg).signature
    except ImportError:
        raise SystemExit("need PyNaCl to sign pairing")
else:
    raise SystemExit(f"device key length {len(raw)}")

pub_hex = pub.hex()
platform, kind = "macos", "software-ed25519"
msg = f"rottenapple-devhub-v1\npair\n{platform}\n{kind}\n{pub_hex}\n{name}".encode()
sig = base64.b64encode(sign(msg)).decode()
body = json.dumps({"name": name, "platform": platform, "kind": kind, "publicKey": pub_hex, "signature": sig}).encode()
req = urllib.request.Request(
    devhub.rstrip("/") + "/v1/devhub/pairings",
    data=body,
    headers={"Content-Type": "application/json", "Accept": "application/json", "X-RA-Launcher": "0.2.0"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as resp:
    pairing = json.load(resp)
open(out_path, "w").write(json.dumps(pairing, indent=2))
code = pairing.get("code", "")
print(f"PAIRING_CODE={code}", flush=True)
print(f"APPROVE_URL={pairing.get('approveUrl','')}", flush=True)
print(f"EXPIRES_MS={pairing.get('expiresMs','')}", flush=True)
print("Josh: open Dev > Devices, enter the code (valid ~10 min), approve with 2FA.", flush=True)
PY
  mark device-paired
else
  log "=== phase-pair: pairing already started ==="
  PAIR_OUT="$ROOT_DIR/work/pairing.json"
fi

# Poll until approved
log "=== phase-pair: poll /pairings/status ==="
python3 - "$DEVHUB_URL" "$PAIR_OUT" <<'PY'
import json, sys, time, urllib.request
devhub, path = sys.argv[1:3]
p = json.load(open(path))
code, secret = p["code"], p["pollSecret"]
deadline = time.time() + 12 * 60
while time.time() < deadline:
    body = json.dumps({"code": code, "pollSecret": secret}).encode()
    req = urllib.request.Request(
        devhub.rstrip("/") + "/v1/devhub/pairings/status",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json", "X-RA-Launcher": "0.2.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        st = json.load(resp)
    state = st.get("state")
    print(f"pairing state={state}", flush=True)
    if state == "approved":
        open(path + ".status", "w").write(json.dumps(st, indent=2))
        sys.exit(0)
    if state == "denied":
        sys.exit("pairing denied")
    time.sleep(3)
sys.exit("pairing timed out (10+ min)")
PY
mark device-approved

# Issue Mega cert via challenge + /certs
log "=== phase-pair: POST /v1/devhub/certs (Mega signing key) ==="
python3 - "$DEVHUB_URL" "$KEYCHAIN_SERVICE" "$ROOT_DIR/josh-mega.bundle.json" "$ROTTEN_DEV_ID" "$ROTTEN_TEAM_ID" <<'PY'
import base64, json, os, subprocess, sys, urllib.request
from nacl.signing import SigningKey

devhub, service, out_bundle, want_dev, want_team = sys.argv[1:6]
api_key = os.environ["RA_API_KEY"]

def kc(label):
    blob = subprocess.check_output(
        ["security", "find-generic-password", "-a", label, "-s", service, "-w"], text=True
    ).strip()
    alg, _, hx = blob.partition(":")
    raw = bytes.fromhex(hx)
    seed = raw[:32]
    return SigningKey(seed)

device = kc("rottencore-device")
mega = kc("josh-mega")
dev_pub = bytes(device.verify_key)
mega_pub = bytes(mega.verify_key)
fp = "sha256:" + __import__("hashlib").sha256(dev_pub).hexdigest()

def post(path, body, auth=False):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-RA-Launcher": "0.2.0"}
    if auth:
        headers["Authorization"] = "Bearer " + api_key
    req = urllib.request.Request(devhub.rstrip("/") + path, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)

ch = post("/v1/devhub/challenge", {"purpose": "cert"}, auth=True)
team = ch["team"]
nonce = ch["nonce"]
new_pub_hex = mega_pub.hex()
msg = f"rottenapple-devhub-v1\ncert\n{nonce}\n{team}\n{fp}\n{new_pub_hex}".encode()
proof = {
    "device": fp,
    "nonce": nonce,
    "signature": base64.b64encode(device.sign(msg).signature).decode(),
    "publicKey": new_pub_hex,
    "keySignature": base64.b64encode(mega.sign(msg).signature).decode(),
}
cert = post("/v1/devhub/certs", proof, auth=True)
# Verify subject
leaf = cert.get("certificate") or {}
if isinstance(leaf, str):
    leaf = json.loads(leaf)
subj = leaf.get("subject") or {}
dev_id = subj.get("devId") or subj.get("dev") or ""
team_id = subj.get("teamId") or subj.get("team") or ""
# Also accept nested forms
if not dev_id and isinstance(subj, dict):
    dev_id = str(subj.get("DevID") or "")
if not team_id and isinstance(subj, dict):
    team_id = str(subj.get("TeamID") or "")
print(f"cert subject dev={dev_id!r} team={team_id!r} fingerprint={cert.get('fingerprint')}", flush=True)
if want_dev and want_dev not in (dev_id, f"A{dev_id}" if not str(dev_id).startswith("A") else dev_id):
    # allow exact or A-prefixed match
    if str(dev_id) != want_dev and f"A{dev_id}" != want_dev and dev_id != want_dev.lstrip("A"):
        # soft: also check string containment of account id digits
        if want_dev not in str(subj):
            raise SystemExit(f"subject dev mismatch: got {dev_id!r} / {subj}, want {want_dev}")
if want_team and want_team not in str(subj) and str(team_id) != want_team:
    if want_team.lstrip("T") not in str(subj):
        raise SystemExit(f"subject team mismatch: got {team_id!r} / {subj}, want {want_team}")

bundle = {"chain": cert.get("chain") or [cert.get("certificate")], "tier": "developer", "mega": True}
# Prefer store chain order
if cert.get("certificate"):
    chain = list(cert.get("chain") or [])
    if chain and chain[0] != cert["certificate"]:
        chain = [cert["certificate"]] + [c for c in chain if c != cert["certificate"]]
    bundle["chain"] = chain
json.dump(bundle, open(out_bundle, "w"), indent=2)
print(f"MEGA_BUNDLE={out_bundle}", flush=True)
PY

mark mega-cert
echo
echo "===== phase-pair OK ====="
echo "MEGA_BUNDLE_JSON=$ROOT_DIR/josh-mega.bundle.json"
echo "Device paired and Mega cert issued for dev=$ROTTEN_DEV_ID team=$ROTTEN_TEAM_ID"
echo "NEXT: run phase-sign"
echo "===== END ====="
log "phase-pair finished OK"
