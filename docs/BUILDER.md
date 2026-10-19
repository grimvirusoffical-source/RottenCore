# Builder & QuickLaunch hand-off

Rotten Core's builder takes a build request, builds each target in Josh's order, labels and names every
output, signs it (`.rasig`), writes `SHA256SUMS`, and (optionally) hands the set to the uploader — all behind
the shared loading screen (`core.Progress`, real progress only). **Nothing is encrypted**; packaging goes
through the `builder.package` ENCRYPTION-HOOK (no-op by default).

## Signing-device policy (host split)
A Mac builds and signs **only Mac and iOS** assets; a Windows machine **only Windows and Android**. Linux and
browser-extension assets are host-neutral. `builder.CanSignOn`, `builder.SplitForHost`, `builder.SignFile`
and `Builder.Run` enforce this; `rottencore sign`/`build` refuse a foreign target (exit 4) and name the
device it needs. Global order: Mac arm64 → Mac Intel → Windows → Linux → extensions → Android → iOS; each
host runs its own slice.

## Build request schema (`rottencore.build-request/v1`)
```json
{
  "schema": "rottencore.build-request/v1",
  "id": "quicklaunch-1-0-0-beta",
  "requestedBy": "quicklaunch",
  "createdMs": 1760000000000,
  "project": { "name": "QuickLaunch", "id": "com.redx.quicklaunch", "version": "1.0.0",
               "channel": "beta", "dir": "/path/to/quicklaunch" },
  "targets": [
    { "platform": "macos-arm64", "command": ["make", "dmg-arm64"], "artifact": "dist/QuickLaunch.dmg" },
    { "platform": "ios",         "prebuilt": "dist/QuickLaunch.ipa" }
  ],
  "upload": { "store": "ra-core" }
}
```
- `platform` ∈ `macos-arm64, macos-intel, windows, linux, extensions, android, ios`.
- Each target has a `command` (run in `project.dir`, leaving the file at `artifact`) **or** a `prebuilt`
  path.
- Label/filename are derived: `QuickLaunch Beta 1.0.0 (Mac, M1 chip)` →
  `quicklaunch-1.0.0-beta-macos-arm64.dmg`. Every platform gets a distinct filename.

## QuickLaunch hand-off
QuickLaunch does **not** build; Rotten Core does. In QuickLaunch's build screen:
1. **Detect Rotten Core.** Present if `/Applications/Rotten Core.app` exists or `rottencore` is on `PATH`.
   If absent, show **"You must have Rotten Core to build"** with a download link and stop.
2. **Hand off.** Write the request to Rotten Core's inbox
   `<support dir>/build-requests/<id>.json` (`builder.InboxPath`) and open
   `rottencore://build?id=<id>`. Rotten Core reads the request, builds, signs and (if `upload` is set)
   uploads, showing the shared loading screen.
3. **CLI equivalent:** `rottencore build <request.json> --key dev.key.json --bundle dev.bundle.json`.

The URL scheme (`rottencore://build?id=…` / `?request=<path>`) and the inbox file are the two hand-off
transports; a local IPC socket can replace the URL scheme later without changing the request schema.

## Outputs
Per artifact: the renamed file, a `<file>.rasig` detached signature (CryptoKit-compatible), an entry in
`SHA256SUMS`. `rottencore sign` can also sign a single already-built file and regenerate `SHA256SUMS`.
