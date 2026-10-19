# Example: RedX ships with RottenCore

RedX's macOS build (`deploy/macos/build-macos.sh` in the RedX repository) makes `RedX.app`, a `.dmg`
(RedX.app + an Applications link + "READ ME FIRST.txt") and a component `.pkg` (`com.redx.pkg`: RedX.app in
/Applications, `redx` and `redxd` in /usr/local/bin). Its GitHub releases carry `SHA256SUMS`.

**Nothing in the RedX repository was changed.** This is the proposed integration; RedX Dev applies it in a
RedX PR when the owner says so.

## Works today, with no change to RedX

```sh
rottencore install github:grimvirusoffical-source/RedX --accept-untrusted
```

RottenCore reads the latest release, picks `redx-<v>-macos-universal.dmg` (or `.pkg` with an earlier `.pkg`
install), checks it against the release's `SHA256SUMS`, mounts it, copies RedX.app to /Applications, runs
the codesign check (RedX is ad-hoc signed: valid, not notarized) and records it for updates from GitHub
Releases. A RedX dmg downloaded in a browser is also recognised from its download URL (kMDItemWhereFroms).
CI runs this against the real RedX v0.4.3 release on a macOS runner.

GitHub builds are **not trusted** (only the Rotten Apple store can make an app trusted), so the person sees
"RottenCore doesn't trust this app: it isn't from the Rotten Apple store." and must accept it.

## With the embedded manifest (proposed RedX change)

1. Put `rottencore.json` (this folder; version, tag and pattern filled by the build) in
   `RedX.app/Contents/Resources/rottencore.json` **and** at the root of the dmg.
2. For the `.pkg`, wrap the component package so the manifest travels in its Resources:
   build the product pkg, then `pkgutil --expand` it, copy `rottencore.json` into its
   `Resources/`, and `pkgutil --flatten` it back (sign afterwards with `productsign`).
   RottenCore also finds the manifest inside the app the pkg carries, as a fallback.
3. Optionally put `RottenCore Installer.app` in the dmg next to RedX.app so people can double-click it;
   RottenCore ignores itself when it looks for the app to install, and `install.bundle` names RedX.app.

Patch for `deploy/macos/build-macos.sh` (sketch, not applied):

```sh
  MF="$W/rottencore.json"
  sed -e "s/0.4.3/${VERSION}/g" "$ROOT/deploy/macos/rottencore.json" > "$MF"
  cp "$MF" "$APP/Contents/Resources/rottencore.json"
  # ... before hdiutil create:
  cp "$MF" "$STAGE/rottencore.json"
  # ... pkg: build the component as before into $W/component.pkg, then
  mkdir -p "$W/res" && cp "$MF" "$W/res/"
  productbuild --synthesize --package "$W/component.pkg" "$W/dist.xml"
  productbuild --distribution "$W/dist.xml" --package-path "$W" "$W/product.pkg"
  pkgutil --expand "$W/product.pkg" "$W/x" && mkdir -p "$W/x/Resources" && cp "$MF" "$W/x/Resources/"
  pkgutil --flatten "$W/x" "$OUT/${NAME}.pkg"
```

The app's bundle id is `com.redx.app` and the package id `com.redx.pkg`, so RottenCore's uninstall removes
both the app and the CLI files the package put in /usr/local/bin (pkgutil receipt), then forgets the receipt.

## Getting store trust

RedX becomes "trusted" only when it is published through the Rotten Apple store and the store signs an
attestation for the exact file (docs/ROTTENCORE.md §Trust). That needs the production store signing key,
which Red-XAI has not provisioned yet.
