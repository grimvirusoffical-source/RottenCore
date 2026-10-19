import Foundation

// AppIconInfo points at the Rotten Core app icon bundled with this target. The asset catalog's "AppIcon"
// (black apple) is the app's icon on macOS; AppIcon.icns is available for a packaging step that sets
// CFBundleIconFile when SwiftPM does not synthesize the bundle icon.
enum AppIconInfo {
    static let assetName = "AppIcon"
    static var icnsURL: URL? { Bundle.module.url(forResource: "AppIcon", withExtension: "icns") }
}
