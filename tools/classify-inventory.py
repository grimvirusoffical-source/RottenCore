#!/usr/bin/env python3
"""Box-side: classify every latest-release asset by its CONTENT (backup copy) and filename, and rewrite
inventory.json / inventory.md / MANIFEST.json so only macOS and iOS assets are sign_on_mac (Josh: a Mac
signs only Mac and iOS builds). Not shipped in the rollout tgz.

usage: classify-inventory.py ROLLOUT_DIR BACKUPS_DIR
"""
import gzip, hashlib, io, json, os, sys, tarfile, zipfile, datetime

SIGN = {"mac", "ios"}
DEFER_REASON = {
    "linux": ("no Linux signing host yet", "linux-host"),
    "extension": ("no browser-extension signing host yet", "extension-host"),
    "windows": ("needs the Windows signing host", "windows-host"),
    "android": ("needs the Windows signing host (Android toolchain)", "windows-host"),
}
MACHO = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe")


def name_category(n):
    l = n.lower()
    if l in ("sha256sums", "sha256sums.txt", "checksums", "sha256.txt"): return "checksum"
    if l.endswith(".ipa") or "-ios" in l: return "ios"
    if "extension" in l: return "extension"
    if any(k in l for k in ("windows", "win32", ".exe", ".msi")): return "windows"
    if l.endswith((".apk", ".aab")) or "android" in l: return "android"
    if any(k in l for k in ("linux", ".deb", ".rpm", ".appimage")): return "linux"
    if any(k in l for k in ("darwin", "macos", "-mac-", ".dmg", ".pkg")): return "mac"
    return "other"


def content_category(path):
    with open(path, "rb") as f:
        head = f.read(4096)
        f.seek(max(0, os.path.getsize(path) - 512)); tail = f.read(512)
    if head[:4] in MACHO: return "mac", "Mach-O"
    if head[:4] == b"xar!": return "mac", "xar (.pkg)"
    if tail[:4] == b"koly": return "mac", "UDIF (.dmg)"
    if head[:4] == b"\x7fELF": return "linux", "ELF"
    if head[:8] == b"!<arch>\n": return "linux", "ar (.deb)"
    if head[:2] == b"MZ": return "windows", "PE"
    if head[:2] == b"\x1f\x8b":
        try:
            with tarfile.open(path, "r:gz") as t:
                kinds = set()
                for m in t:
                    if m.isfile() and m.size > 4:
                        b = t.extractfile(m).read(4)
                        if b in MACHO: kinds.add("mac")
                        elif b == b"\x7fELF": kinds.add("linux")
                if kinds == {"mac"}: return "mac", "tar.gz of Mach-O"
                if kinds == {"linux"}: return "linux", "tar.gz of ELF"
                return "other", f"tar.gz {sorted(kinds)}"
        except tarfile.TarError:
            return "other", "gzip"
    if head[:2] == b"PK":
        z = zipfile.ZipFile(path); names = z.namelist()
        if any(n.startswith("Payload/") and ".app/" in n for n in names): return "ios", "zip with Payload/*.app (ipa)"
        if any(".app/Contents/MacOS/" in n for n in names): return "mac", "zip with .app/Contents/MacOS"
        if "AndroidManifest.xml" in names or any(n.startswith("base/manifest/") for n in names): return "android", "Android package"
        if "manifest.json" in names and b"manifest_version" in z.read("manifest.json"): return "extension", "WebExtension"
        if any(n.lower().endswith((".exe", ".dll")) for n in names): return "windows", "zip with PE"
        return "other", "zip"
    if head.startswith(b"#!") or path.endswith((".py", ".command", ".sh")):
        t = head.decode("utf-8", "replace")
        mac = any(k in t for k in ("macOS", "/Library/", "Gatekeeper", "darwin"))
        return ("mac-script" if mac else "other"), "script"
    return "other", "data"


def main():
    rollout, backups = sys.argv[1], sys.argv[2]
    inv_p, man_p = os.path.join(rollout, "inventory.json"), os.path.join(rollout, "MANIFEST.json")
    inv, man = json.load(open(inv_p)), json.load(open(man_p))
    by_key = {(a["repo"], a["tag"], a["name"]): a for a in man["assets"]}
    sign, deferred, untouched, problems = [], [], [], []
    counts = {}
    for repo, data in inv["repos"].items():
        for rel in data.get("releases", []):
            tag = rel.get("tag") or rel.get("name")
            for a in rel["assets"]:
                p = os.path.join(backups, repo, tag, a["name"])
                m = by_key.get((repo, tag, a["name"]))
                if not os.path.isfile(p) or not m:
                    problems.append(f"{repo}/{tag}/{a['name']}: no backup / MANIFEST entry"); continue
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
                if h != m["sha256"]:
                    problems.append(f"{repo}/{tag}/{a['name']}: backup sha256 != MANIFEST"); continue
                nc = name_category(a["name"]); cc, why = content_category(p)
                cat = cc
                if cc == "mac-script":
                    # macOS installer script (install-macos.py, Install.command launcher): Mac-only, signed on the Mac
                    cat = "mac"
                elif cc == "other":
                    cat = nc  # content inconclusive (source zip, text): the filename decides
                if cc not in ("other", "mac-script") and nc not in ("other", cc):
                    problems.append(f"{repo}/{tag}/{a['name']}: filename says {nc}, content says {cc} ({why})")
                a["category"] = cat
                entry = {"repo": repo, "tag": tag, "draft": rel.get("draft", False), "prerelease": rel.get("prerelease", False),
                         "asset": a["name"], "asset_id": a["id"], "size": a["size"], "url": a.get("browser_download_url", ""),
                         "category": cat, "label": a.get("label", ""), "evidence": why}
                counts[cat] = counts.get(cat, 0) + 1
                if cat in SIGN:
                    entry["platform"] = "ios" if cat == "ios" else "macos"
                    sign.append(entry); m["action"] = "sign_on_mac"; m.pop("reason", None)
                elif cat in DEFER_REASON:
                    entry["reason"], entry["needs"] = DEFER_REASON[cat]
                    deferred.append(entry); m["action"] = "deferred"; m["reason"] = entry["reason"]
                else:
                    entry["reason"] = ("checksum file: merged, never dropped, by publish.sh" if cat == "checksum"
                                       else "not a build (metadata/installer helper): left as published")
                    untouched.append(entry); m["action"] = "untouched"; m["reason"] = entry["reason"]
                m["category"] = cat
    if problems:
        sys.exit("STOP:\n  " + "\n  ".join(problems))
    for a in man["assets"]:
        a.setdefault("action", "older_release")
    inv.pop("deferred_windows_android", None)
    inv["sign_on_mac"], inv["deferred"], inv["untouched_latest"] = sign, deferred, untouched
    inv["counts"] = dict(sorted(counts.items()))
    inv["sign_policy"] = "a Mac signs only macOS and iOS builds; Linux/extensions: no signing host yet; Windows/Android: Windows host"
    inv["classified_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    man["classified_at"] = inv["classified_at"]
    json.dump(inv, open(inv_p, "w"), indent=2); open(inv_p, "a").write("\n")
    json.dump(man, open(man_p, "w"), indent=1); open(man_p, "a").write("\n")
    md = ["# Inventory (latest published only)", f"Classified: {inv['classified_at']} (by content of the box backups)", "",
          f"Sign on Mac (macOS/iOS only): {len(sign)}  |  Deferred: {len(deferred)}  |  Untouched (checksums/metadata): {len(untouched)}", ""]
    for repo, data in inv["repos"].items():
        rels = data.get("releases", [])
        if not rels:
            md += [f"## {repo}", "", "_(no releases)_", ""]; continue
        tag = rels[0].get("tag") or rels[0].get("name")
        md.append(f"## {repo} → `{tag}`")
        for title, lst in (("sign_on_mac", sign), ("deferred", deferred), ("untouched", untouched)):
            items = [e for e in lst if e["repo"] == repo]
            md.append(f"- {title}: {len(items)}")
            for e in items:
                md.append(f"  - `{e['asset']}` ({e['category']}; {e.get('reason') or e['evidence']})")
        md.append("")
    md.append("## Will convert to draft after publish (reversible; tags kept)")
    for c in inv.get("full_releases_for_draft_conversion", []):
        md.append(f"- {c['repo']}/{c['tag']} (release_id={c['release_id']}, assets={c['asset_count']})")
    open(os.path.join(rollout, "inventory.md"), "w").write("\n".join(md) + "\n")
    per = {}
    for e in sign: per[e["repo"]] = per.get(e["repo"], 0) + 1
    print(json.dumps({"sign_on_mac": len(sign), "per_repo": per, "deferred": len(deferred), "untouched": len(untouched), "counts": inv["counts"]}))


if __name__ == "__main__":
    main()
