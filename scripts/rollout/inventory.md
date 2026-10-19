# Inventory (latest published only)
Classified: 2026-10-19T23:18:15Z (by content of the box backups)

Sign on Mac (macOS/iOS only): 20  |  Deferred: 31  |  Untouched (checksums/metadata): 7

## RottenApple → `v0.1.0-beta.1`
- sign_on_mac: 2
  - `rotten-apple-0.1.0-darwin-amd64.tar.gz` (mac; tar.gz of Mach-O)
  - `rotten-apple-0.1.0-darwin-arm64.tar.gz` (mac; tar.gz of Mach-O)
- deferred: 5
  - `rotten-apple-0.1.0-linux-amd64.tar.gz` (linux; no Linux signing host yet)
  - `rotten-apple-0.1.0-linux-arm64.tar.gz` (linux; no Linux signing host yet)
  - `rotten-apple-0.1.0-windows-amd64.zip` (windows; needs the Windows signing host)
  - `rotten-apple-0.1.0-windows-arm64.zip` (windows; needs the Windows signing host)
  - `rotten-apple-extension-0.1.0.zip` (extension; no browser-extension signing host yet)
- untouched: 1
  - `SHA256SUMS` (checksum; checksum file: merged, never dropped, by publish.sh)

## quick-launch → `v1.0.0-beta.1`
- sign_on_mac: 8
  - `QuickLaunch-1.0.0-beta.1-darwin-arm64.dmg` (mac; UDIF (.dmg))
  - `QuickLaunch-1.0.0-beta.1-darwin-arm64.pkg` (mac; xar (.pkg))
  - `QuickLaunch-1.0.0-beta.1-darwin-arm64.zip` (mac; zip with .app/Contents/MacOS)
  - `QuickLaunch-1.0.0-beta.1-darwin-x64.dmg` (mac; UDIF (.dmg))
  - `QuickLaunch-1.0.0-beta.1-darwin-x64.pkg` (mac; xar (.pkg))
  - `QuickLaunch-1.0.0-beta.1-darwin-x64.zip` (mac; zip with .app/Contents/MacOS)
  - `quicklaunch-cli-1.0.0-beta.1-darwin-amd64` (mac; Mach-O)
  - `quicklaunch-cli-1.0.0-beta.1-darwin-arm64` (mac; Mach-O)
- deferred: 5
  - `QuickLaunch-1.0.0-beta.1-linux-x64.tar.gz` (linux; no Linux signing host yet)
  - `QuickLaunch-1.0.0-beta.1-win32-x64.zip` (windows; needs the Windows signing host)
  - `quicklaunch-cli-1.0.0-beta.1-linux-amd64` (linux; no Linux signing host yet)
  - `quicklaunch-cli-1.0.0-beta.1-linux-arm64` (linux; no Linux signing host yet)
  - `quicklaunch-cli-1.0.0-beta.1-windows-amd64.exe` (windows; needs the Windows signing host)
- untouched: 1
  - `SHA256SUMS.txt` (checksum; checksum file: merged, never dropped, by publish.sh)

## RottenCore

_(no releases)_

## RedX → `v0.4.5`
- sign_on_mac: 8
  - `redx-0.4.5-darwin-amd64.tar.gz` (mac; tar.gz of Mach-O)
  - `redx-0.4.5-darwin-arm64.tar.gz` (mac; tar.gz of Mach-O)
  - `redx-0.4.5-macos-amd64.dmg` (mac; UDIF (.dmg))
  - `redx-0.4.5-macos-amd64.pkg` (mac; xar (.pkg))
  - `redx-0.4.5-macos-arm64.dmg` (mac; UDIF (.dmg))
  - `redx-0.4.5-macos-arm64.pkg` (mac; xar (.pkg))
  - `redx-0.4.5-macos-universal.dmg` (mac; UDIF (.dmg))
  - `redx-0.4.5-macos-universal.pkg` (mac; xar (.pkg))
- deferred: 10
  - `redx-0.4.5-linux-amd64.tar.gz` (linux; no Linux signing host yet)
  - `redx-0.4.5-linux-arm64.tar.gz` (linux; no Linux signing host yet)
  - `redx-0.4.5-linux-armv7.tar.gz` (linux; no Linux signing host yet)
  - `redx-0.4.5-windows-amd64-setup.exe` (windows; needs the Windows signing host)
  - `redx-0.4.5-windows-amd64.zip` (windows; needs the Windows signing host)
  - `redx-0.4.5-windows-arm64-setup.exe` (windows; needs the Windows signing host)
  - `redx-0.4.5-windows-arm64.zip` (windows; needs the Windows signing host)
  - `redx_0.4.5_amd64.deb` (linux; no Linux signing host yet)
  - `redx_0.4.5_arm64.deb` (linux; no Linux signing host yet)
  - `redx_0.4.5_armhf.deb` (linux; no Linux signing host yet)
- untouched: 1
  - `SHA256SUMS` (checksum; checksum file: merged, never dropped, by publish.sh)

## gendragoon-cloud-ssd → `v0.18.0-rc.3`
- sign_on_mac: 2
  - `GenDragoon-Cloud-SSD-Mac-v0.18.0.zip` (mac; zip with .app/Contents/MacOS)
  - `install-macos.py` (mac; script)
- deferred: 0
- untouched: 3
  - `Install.command` (other; not a build (metadata/installer helper): left as published; NOTE macOS installer script, not in the Mac signing set (flagged for Josh))
  - `package-status.json` (other; not a build (metadata/installer helper): left as published)
  - `sha256.txt` (checksum; checksum file: merged, never dropped, by publish.sh)

## gendragoon-apps

_(no releases)_

## Gendragoon-Releases → `all-platforms-2026-10-19`
- sign_on_mac: 0
- deferred: 11
  - `GenDragoon-Android-0.17.0-build20-DEBUG-signed.apk` (android; needs the Windows signing host (Android toolchain))
  - `GenDragoon-Android-0.17.0-build20-release-UNSIGNED-placeholder-support.aab` (android; needs the Windows signing host (Android toolchain))
  - `GenDragoon-Cloud-SSD-0.1.0-linux-amd64.deb` (linux; no Linux signing host yet)
  - `GenDragoon-Cloud-SSD-0.1.0-linux-x64.tar.gz` (linux; no Linux signing host yet)
  - `GenDragoon-Cloud-SSD-0.1.0-linux-x86_64.AppImage` (linux; no Linux signing host yet)
  - `GenDragoon-Cloud-SSD-Windows-x64-unpacked-UNSIGNED-0.1.0.zip` (windows; needs the Windows signing host)
  - `GenDragoon-Desktop-Companion-Windows-Linux-source.zip` (windows; needs the Windows signing host)
  - `GenDragoon-Extension-chrome-0.2.0.zip` (extension; no browser-extension signing host yet)
  - `GenDragoon-Extension-edge-0.2.0.zip` (extension; no browser-extension signing host yet)
  - `GenDragoon-Extension-firefox-0.2.0.zip` (extension; no browser-extension signing host yet)
  - `GenDragoon-Extension-opera-0.2.0.zip` (extension; no browser-extension signing host yet)
- untouched: 1
  - `SHA256SUMS` (checksum; checksum file: merged, never dropped, by publish.sh)

## Will convert to draft after publish (reversible; tags kept)
- RedX/v0.4.4 (release_id=417264728, assets=19)
- RedX/v0.4.3 (release_id=417113027, assets=19)
- RedX/v0.3.0 (release_id=416983016, assets=8)
- gendragoon-cloud-ssd/v0.18.0-rc.1 (release_id=416146269, assets=5)
- gendragoon-cloud-ssd/v0.17.0-rc.1 (release_id=416042125, assets=6)
- gendragoon-cloud-ssd/v0.4.0 (release_id=412134581, assets=2)
- Gendragoon-Releases/desktop-companion-windows-linux-source-ce5665f (release_id=416897274, assets=2)
- Gendragoon-Releases/windows-x64-v0.1.0-unpacked (release_id=416897219, assets=2)
- Gendragoon-Releases/android-v0.17.0-build20-debug (release_id=416897202, assets=2)
