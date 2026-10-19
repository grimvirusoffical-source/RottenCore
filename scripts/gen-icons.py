import os, struct, json
from PIL import Image

ROOT = "/workspace/wt-rottencore-m1"
SRC = {
    "rotten-core":  "/workspace/icons/rotten-core-source.jpg",
    "poison-apple": "/workspace/icons/poison-apple-source.jpg",
}

def square_master(src):
    im = Image.open(src).convert("RGBA")
    w, h = im.size
    s = min(w, h)
    left = (w - s) // 2
    top = (h - s) // 2
    im = im.crop((left, top, left + s, top + s))
    return im.resize((1024, 1024), Image.LANCZOS)

def write_icns(master, path):
    # OSType -> size; PNG-encoded entries (supported by modern macOS)
    entries = [
        ("icp4", 16), ("icp5", 32), ("icp6", 64),
        ("ic07", 128), ("ic08", 256), ("ic09", 512), ("ic10", 1024),
        ("ic11", 32), ("ic12", 64), ("ic13", 256), ("ic14", 512),
    ]
    import io
    blobs = b""
    for ostype, sz in entries:
        buf = io.BytesIO()
        master.resize((sz, sz), Image.LANCZOS).save(buf, format="PNG")
        data = buf.getvalue()
        blobs += ostype.encode("ascii") + struct.pack(">I", len(data) + 8) + data
    total = len(blobs) + 8
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", total) + blobs)

# macOS AppIcon.appiconset spec: (size_pt, scale)
APPICON = [(16,1),(16,2),(32,1),(32,2),(128,1),(128,2),(256,1),(256,2),(512,1),(512,2)]

def write_appiconset(master, outdir):
    os.makedirs(outdir, exist_ok=True)
    images = []
    for pt, scale in APPICON:
        px = pt * scale
        name = f"icon_{pt}x{pt}@{scale}x.png"
        master.resize((px, px), Image.LANCZOS).save(os.path.join(outdir, name))
        images.append({"size": f"{pt}x{pt}", "idiom": "mac", "filename": name, "scale": f"{scale}x"})
    contents = {"images": images, "info": {"version": 1, "author": "rottencore"}}
    with open(os.path.join(outdir, "Contents.json"), "w") as f:
        json.dump(contents, f, indent=2)

LINUX = [16,32,48,64,128,256,512]
EXT = [16,32,48,128]
ICO = [16,24,32,48,64,128,256]

for product, src in SRC.items():
    master = square_master(src)
    base = os.path.join(ROOT, "assets", "icons", product)
    os.makedirs(base, exist_ok=True)
    master.save(os.path.join(base, "icon-1024.png"))
    # macOS
    write_icns(master, os.path.join(base, "AppIcon.icns"))
    write_appiconset(master, os.path.join(base, "AppIcon.appiconset"))
    # Windows .ico (multi-size)
    master.save(os.path.join(base, "AppIcon.ico"), format="ICO",
                sizes=[(s, s) for s in ICO])
    # Linux PNGs
    ld = os.path.join(base, "linux"); os.makedirs(ld, exist_ok=True)
    for s in LINUX:
        master.resize((s, s), Image.LANCZOS).save(os.path.join(ld, f"icon-{s}.png"))
    # Browser extension PNGs
    ed = os.path.join(base, "extension"); os.makedirs(ed, exist_ok=True)
    for s in EXT:
        master.resize((s, s), Image.LANCZOS).save(os.path.join(ed, f"icon-{s}.png"))
    print(product, "done ->", base)

print("OK")
