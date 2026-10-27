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

# owner session (ROTTENCORE_ACCESS_TOKEN, or a keyring token from Quick Login).
# The password is prompted, never an argument.
rottencore sign --lifetime --without-launcher --platform macos ./RedX.zip
```

## Installer, signer, and background agent

RottenCore signs a Red-XAI app, seals that signature with Red-SecretsXAI, and on this computer watches for the sealed file, checks it, and installs it. It does not fork or change Red-SecretsXAI. The cipher stays in the `red-xai-encrypt` package (`encrypt_text`, `decrypt_text`, `encrypt_file`, `decrypt_file`, `mode="password"`). Call sites are `internal/sign/redsecrets.go`. A text seal starts with `RXAI2.`. A file seal is a red-X PNG named `<artifact>.Red_SecretXAI`.

First run on this computer:

```sh
scripts/first-run.sh
# or, with rottencore already on PATH:
rottencore login          # Quick Login in the browser; tokens go to the OS keyring only if the server sets remember_device
rottencore daemon install # launch at login (LaunchAgent, user systemd, or the Windows Startup folder)
```

The Mac app's Settings **Quick Login** button runs the same `login` command. **Sign In** stays "coming soon" until the OIDC browser loop is registered. **Sign Out** stops the signing agent and runs `logout`, which drops the keyring tokens for this app.

Signing:

```sh
rottencore whoami
rottencore dev-cert       # one random ed25519 key for this account; ciphertext in the keyring, public half local only
rottencore sign --developer --with-launcher --platform macos ./RedX.zip
rottencore open ./RedX.zip   # detect .Red_SecretXAI or .rotten_core_signed, decrypt, verify, install
```

`--developer` requires the Rotten Apple launcher and does not use the owner lifetime key. `--lifetime` is the owner path from section 11 of the spec. A file that is not sealed this way is not installed by `open`. A source other than the Rotten Apple store still shows the not-trusted warning.

The daemon (`rottencore daemon`) ticks every 60 seconds, watches `~/Downloads` for `.Red_SecretXAI` and `.rotten_core_signed` names, and records update checks. It does not decrypt, and it does not install. It replaces itself when RSS exceeds 64 MiB, uptime exceeds 12 hours, or a pass has not finished within 3 minutes. Launchd and systemd set `ROTTENCORE_DAEMON_SUPERVISED=1` and restart that exit. Installed apps, the keyring, and the support folder stay in place.

Update checks prefer the newest stable GitHub release (`/releases/latest`, drafts and prereleases skipped) and the Rotten Apple store listing (`https://api.rottenapplestore.org`). A version that is not newer is not installed. There is no separate red-xai.com catalog feed in this repo.

macOS install still uses the existing engine (`/Applications`, or `~/Applications` with `--user`). Verifying a carrier works on Linux and Windows; placing a `.app` with `ditto` does not. Windows and Linux launch-at-login files are written by `daemon install`.

Tokens and developer-key ciphertext use the OS keyring (macOS Keychain, Windows DPAPI, Linux secret-service via `secret-tool`). They are not written as plaintext files. The secret is passed on stdin, never as an argument.

Accounts calls, and what is not available yet, are listed in [docs/ROTTENCORE.md](docs/ROTTENCORE.md) sections 11–15.

## Build

```sh
go test ./...                 # engine, anywhere
scripts/build-macos.sh        # on a Mac: universal CLI, app, dmg, pkg, SHA256SUMS in dist/
ROTTENCORE_BIN=$PWD/dist/rottencore-0.1.0-macos-universal swift test --package-path apple
```

## About

RottenCore is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.

See [LICENSE](LICENSE).
