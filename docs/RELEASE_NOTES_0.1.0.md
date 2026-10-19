First release of RottenCore, the one installer for every Red-XAI app on macOS.

**Downloads** (macOS 12 or later, universal: Apple silicon and Intel)
- `RottenCore-Installer-0.1.0-macos-universal.dmg`: drag RottenCore Installer to Applications.
- `RottenCore-Installer-0.1.0-macos-universal.pkg`: installs the app in /Applications and the `rottencore` command in /usr/local/bin.
- `rottencore-0.1.0-macos-universal` (and `.tar.gz`): the command line only.
- `SHA256SUMS`: check your download with `shasum -a 256 -c SHA256SUMS`.

**What it does**
- Works out where an app came from (embedded `rottencore.json`, a sidecar manifest, the download URL), checks the file's SHA-256 against the store or the GitHub release's `SHA256SUMS`, and installs `.app`, `.dmg`, `.pkg` and `.zip` files.
- Keeps a list of what it installed, checks GitHub Releases for updates, and uninstalls (apps to the Trash; package files by receipt, never system files).
- Store packages (`.rarxai`) are handed to the Rotten Apple launcher, which does the store's checks.
- Dark mode by default, with light and system options. No telemetry.

**Please read**
- **Not signed with a Developer ID and not notarized.** The app is ad-hoc signed and the package is unsigned. macOS will warn the first time: right-click the app, choose Open, then Open again.
- **No app is "trusted" yet.** Trust needs the Rotten Apple store's signing key, which Red-XAI has not provisioned. Until a RottenCore release pins it, every app (including RedX and RottenCore itself) shows "RottenCore doesn't trust this app: it isn't from the Rotten Apple store." and installs only if you accept. A checksum mismatch is always refused.
- **Red-XAI Accounts sign-in is a stub** ("coming soon"): Red-XAI Accounts is not live yet.
- The Rotten Apple store (api.rottenapplestore.org) is not live yet, so store search shows nothing.
- Tested by CI on a GitHub macOS 14 (Apple silicon) runner: engine tests, Swift tests, and installing RottenCore and RedX v0.4.3 from their dmgs and RottenCore from its pkg. The Intel slice is built but was not run on an Intel Mac, and the app window was not clicked through by a person.

RottenCore is developed and maintained by Red-XAI LLC. Red-XAI LLC is wholly owned by GRIM-VIRUS, an independent recording artist who leads development under the alias MainDirectory. © Red-XAI LLC. All rights reserved.
