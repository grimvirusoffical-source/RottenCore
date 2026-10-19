# App icons

Full icon sets for **Rotten Core** (black apple) and **Poison Apple** (toxic green apple), generated from the
16:9 source art by center-cropping to a square around the rounded-square icon and resizing (see
`scripts/gen-icons.py`).

```
assets/icons/<product>/
  icon-1024.png                 master
  AppIcon.icns                  macOS (PNG-backed: 16..1024 incl. @2x)
  AppIcon.appiconset/           Xcode asset catalog (16,32,128,256,512 @1x and @2x) + Contents.json
  AppIcon.ico                   Windows (16,24,32,48,64,128,256)
  linux/icon-{16,32,48,64,128,256,512}.png
  extension/icon-{16,32,48,128}.png
```
`<product>` is `rotten-core` or `poison-apple`.

## Wiring
- **Rotten Core app (SwiftPM):** `apple/Sources/RottenCoreInstaller/Resources/Assets.xcassets/AppIcon.appiconset`
  (the asset catalog) and `Resources/AppIcon.icns`, declared in `apple/Package.swift`.
- **Poison Apple app (launcher, rotten-apple repo):** its desktop target points at
  `assets/icons/poison-apple/*` (wired on the Poison Apple feature branch).
- **Builder packaging:** `builder.IconForPlatform(root, product, platform)` picks the right file per target
  (`.icns` for Mac/iOS, `.ico` for Windows, 512px PNG for Linux/Android, 128px PNG for extensions) and the
  pipeline records it on each `Artifact.IconPath` so the dmg/exe/AppImage/zip step embeds it.

Regenerate with `python3 scripts/gen-icons.py` (Pillow) after updating the source art.
