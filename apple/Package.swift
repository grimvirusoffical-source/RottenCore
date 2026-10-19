// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "RottenCore",
    platforms: [.macOS(.v12)],
    products: [
        // Apps embed RottenCoreKit plus the `rottencore` binary (Contents/Resources/rottencore).
        .library(name: "RottenCoreKit", targets: ["RottenCoreKit"]),
        .executable(name: "RottenCoreInstaller", targets: ["RottenCoreInstaller"]),
    ],
    targets: [
        .target(name: "RottenCoreKit"),
        .executableTarget(
            name: "RottenCoreInstaller",
            dependencies: ["RottenCoreKit"],
            exclude: ["Resources/Info.plist"], // URL types live in packaging/Info.plist (build-macos.sh); SwiftPM forbids Info.plist as a resource (QA v2 N1).
            resources: [
                // Rotten Core app icon (black apple). Xcode processes the asset catalog into the AppIcon;
                // AppIcon.icns is also copied so a SwiftPM package step can set CFBundleIconFile.
                .process("Resources/Assets.xcassets"),
                .copy("Resources/AppIcon.icns"),
            ]
        ),
        .testTarget(name: "RottenCoreKitTests", dependencies: ["RottenCoreKit"]),
    ]
)
