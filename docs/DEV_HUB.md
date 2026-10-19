# Dev account hub (client)

Everything a developer needs lives under their **Rotten Apple dev account**: the registered **device**, the
**build API key**, the **team or individual** build context, and each app's **SDK selection**. Grok Bot is
building the server side in ra-core on branch `dev-hub` (`docs/DEV_HUB_API.md`). Until those endpoints are
live, Rotten Core uses **local, file-backed** stand-ins behind interfaces; the migration is a one-line swap.

## 1. Device registration
Rotten Core generates a **device key** on this machine (it never leaves), shows a **pairing code**, and the
developer approves it in the store dashboard. The store records the device **platform**:

| device | may build & sign |
|---|---|
| Mac | Mac and iOS (plus Linux / browser-extensions) |
| Windows PC | Windows and Android (plus Linux / browser-extensions) |

```
rottencore device register            # generates the key, prints the pairing code
rottencore device approve <id> --team T-josh   # (local stand-in for the dashboard approval)
rottencore device status
```
`devhub.DeviceService` is the interface; `LocalDeviceService` (a JSON file at
`<support dir>/devhub/device.json`) is the default. Dev certs are issued only to keys on a **registered
device** and are meant to carry that device's platform; the platform tie-in is enforced today through the
registered-device record and the signed **build manifest** (below) and through the host split in
`rottencore sign` / the builder. (Encoding the platform directly into the certificate subject is a
coordinated change with the store's `rarxai.Cert` format — tracked as an open question.)

## 2. Build API key
Building and uploading — in Rotten Core and in the QuickLaunch hand-off — require a **build API key**.
Without one, Rotten Core shows exactly:

> Create a build API key in your Rotten Apple dev account.

(`devhub.ErrNoBuildKey`). The key is part of the build context and is never logged.

## 3. Team or individual
A build runs in the context of the developer's **team** or **individual** account
(`devhub.BuildContext.TeamID` / `Individual`, shown as `AccountLabel()`), recorded in the signed build
manifest.

## 4. SDKs
Each app's SDK selection comes from the store (`SDKSelection{Selected, Unlocked}`): what the developer chose
for the app and what the account's level has unlocked (see the store's `docs/SDK_LEVELS.md`). The builder
embeds the build's SDK list in the **signed build manifest** (`rottencore.build-manifest/v1`) and **refuses**
an SDK that is declared but not both **selected and unlocked**. **Owners and admins are exempt**
(`BuildContext.Exempt()`), which the manifest records (`sdkExempt`).

## Build manifest
`builder` writes `build-manifest.json` per build set: account, device platform, the validated SDK list and
each artifact's sha256, signed by the developer key under `ROTTENCORE-BUILDMANIFEST-v1\0`. `VerifyBuildManifest`
checks it against a chain policy. This is what lets the store confirm a build came from an approved device
under an allowed SDK set.

## Migration to the dev-hub API
The local files are a documented stand-in, not the source of trust. When `docs/DEV_HUB_API.md` is live:
1. Implement `HTTPDeviceService` (ra-core device endpoints) and `HTTPContextProvider` (build key → team or
   individual context, SDK selection) against that doc.
2. Swap the constructors in `cmd/rottencore` (`deviceService()`, `contextProvider()`) to the HTTP versions,
   keyed by the configured dev account; keep the local files as an offline cache.
3. No caller changes: `DeviceService`, `ContextProvider` and `BuildContext` stay the same, so the builder,
   `rottencore sign`/`build` and the QuickLaunch hand-off are unaffected.
Device approval moves from `device approve` (local) to the dashboard; registration and `status` stay.
