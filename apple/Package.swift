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
        .executableTarget(name: "RottenCoreInstaller", dependencies: ["RottenCoreKit"]),
        .testTarget(name: "RottenCoreKitTests", dependencies: ["RottenCoreKit"]),
    ]
)
