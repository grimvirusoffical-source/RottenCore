# RottenCore

One installer for every Red-XAI app on macOS. RottenCore finds out where an app came from (the Rotten Apple
store or a GitHub release), checks its SHA-256, tells you whether it is trusted, installs `.app`, `.dmg`,
`.pkg` and `.zip` files, keeps track of what it installed, checks for updates and uninstalls cleanly.

* **Trusted** means the Rotten Apple store signed this exact file. Everything else shows
  *"RottenCore doesn't trust this app: it isn't from the Rotten Apple store."* and installs only if you accept.
* A file that does not match its published checksum is never installed.
* Store packages (`.rarxai`) are handed to the Rotten Apple launcher, which does the store's checks.

Specification: [docs/ROTTENCORE.md](docs/ROTTENCORE.md). Example integration: [examples/redx](examples/redx).

## Get it

From [Releases](https://github.com/grimvirusoffical-source/RottenCore/releases): `RottenCore-Installer-<v>-macos-universal.dmg`
(drag to Applications) or `.pkg` (also installs the `rottencore` command in /usr/local/bin), or the CLI alone.
Check the download against `SHA256SUMS`. macOS 12 or later, Apple silicon and Intel.

v0.1.0 is **not signed with a Developer ID and not notarized**. macOS will warn the first time: right-click the
app, choose Open, then Open again.

```sh
rottencore install github:grimvirusoffical-source/RedX --accept-untrusted
rottencore list
rottencore check-updates
rottencore uninstall com.redx.app
```

## Build

```sh
go test ./...                 # engine, anywhere
scripts/build-macos.sh        # on a Mac: universal CLI, app, dmg, pkg, SHA256SUMS in dist/
ROTTENCORE_BIN=$PWD/dist/rottencore-0.1.0-macos-universal swift test --package-path apple
```

## About

RottenCore is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.

See [LICENSE](LICENSE).
