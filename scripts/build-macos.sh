#!/bin/bash
# Builds RottenCore on macOS: the universal `rottencore` CLI, the universal RottenCore Installer.app
# (CLI embedded), a .dmg, a .pkg, a CLI tarball and SHA256SUMS in dist/.
# Signing: MACOS_SIGN_IDENTITY (a Developer ID Application identity in the keychain) and
# PKG_SIGN_IDENTITY (Developer ID Installer) are used only when set; otherwise the app is ad-hoc signed
# and the package is unsigned. No identity, password or key is ever stored in this repository.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^const Version = "\(.*\)"/\1/p' core/version.go)
OUT=dist
APP="RottenCore Installer.app"
rm -rf "$OUT" build && mkdir -p "$OUT" build

echo "== rottencore $VERSION (arm64 + x86_64)"
for a in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=$a go build -trimpath -ldflags "-s -w" -o build/rottencore-$a ./cmd/rottencore
done
lipo -create -output build/rottencore build/rottencore-arm64 build/rottencore-amd64
lipo -info build/rottencore

echo "== RottenCore Installer (Swift, universal)"
swift build -c release --package-path apple --arch arm64 --arch x86_64 --product RottenCoreInstaller
BIN=$(swift build -c release --package-path apple --arch arm64 --arch x86_64 --show-bin-path)/RottenCoreInstaller
lipo -info "$BIN"

mkdir -p "build/$APP/Contents/MacOS" "build/$APP/Contents/Resources"
cp "$BIN" "build/$APP/Contents/MacOS/RottenCoreInstaller"
cp build/rottencore "build/$APP/Contents/Resources/rottencore"
cp packaging/rottencore.json "build/$APP/Contents/Resources/rottencore.json"
sed "s/@VERSION@/$VERSION/g" packaging/Info.plist > "build/$APP/Contents/Info.plist"
if [ -f packaging/AppIcon.icns ]; then cp packaging/AppIcon.icns "build/$APP/Contents/Resources/AppIcon.icns"; fi
plutil -lint "build/$APP/Contents/Info.plist"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp -s "$MACOS_SIGN_IDENTITY" "build/$APP/Contents/Resources/rottencore"
  codesign --force --options runtime --timestamp -s "$MACOS_SIGN_IDENTITY" "build/$APP"
  SIGNED="Developer ID"
else
  codesign --force -s - "build/$APP/Contents/Resources/rottencore"
  codesign --force -s - "build/$APP"
  SIGNED="ad-hoc (not Developer ID, not notarized)"
fi
codesign --verify --strict --verbose=2 "build/$APP"
echo "app signature: $SIGNED"

echo "== dmg"
mkdir -p build/dmg && cp -R "build/$APP" build/dmg/ && ln -s /Applications build/dmg/Applications
cp packaging/rottencore.json build/dmg/rottencore.json
hdiutil create -volname "RottenCore Installer" -srcfolder build/dmg -format UDZO -ov "$OUT/RottenCore-Installer-$VERSION-macos-universal.dmg"

echo "== pkg"
mkdir -p build/pkgroot/Applications build/pkgroot/usr/local/bin build/pkgres
cp -R "build/$APP" build/pkgroot/Applications/
cp build/rottencore build/pkgroot/usr/local/bin/rottencore
cp packaging/rottencore.json build/pkgres/rottencore.json
pkgbuild --analyze --root build/pkgroot build/component.plist
plutil -replace 0.BundleIsRelocatable -bool NO build/component.plist
pkgbuild --root build/pkgroot --component-plist build/component.plist --identifier com.redxai.rottencore.pkg \
  --version "$VERSION" --install-location / build/rottencore-component.pkg
PKG="$OUT/RottenCore-Installer-$VERSION-macos-universal.pkg"
# productbuild's --resources does not reliably carry arbitrary files, so add the manifest
# to the product's Resources directly (expand, copy, flatten), then sign if asked.
productbuild --synthesize --package build/rottencore-component.pkg build/distribution.xml
productbuild --distribution build/distribution.xml --package-path build build/unsigned.pkg
rm -rf build/pkgx
pkgutil --expand build/unsigned.pkg build/pkgx
mkdir -p build/pkgx/Resources
cp build/pkgres/rottencore.json build/pkgx/Resources/rottencore.json
rm -f build/flat.pkg
pkgutil --flatten build/pkgx build/flat.pkg
if [ -n "${PKG_SIGN_IDENTITY:-}" ]; then
  productsign --sign "$PKG_SIGN_IDENTITY" build/flat.pkg "$PKG"
else
  cp build/flat.pkg "$PKG"
fi
xar -tf "$PKG"
xar -tf "$PKG" | grep -q '^Resources/rottencore.json$' || { echo "rottencore.json missing from the pkg"; exit 1; }
pkgutil --check-signature "$PKG" || true

echo "== cli"
cp build/rottencore "$OUT/rottencore-$VERSION-macos-universal"
tar -C build -czf "$OUT/rottencore-$VERSION-macos-universal.tar.gz" rottencore
(cd "$OUT" && shasum -a 256 RottenCore-Installer-* rottencore-* > SHA256SUMS && cat SHA256SUMS)
