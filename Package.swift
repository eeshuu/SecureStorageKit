// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureStorageKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .macCatalyst(.v15),
    ],
    products: [
        .library(name: "SecureStorageKit", targets: ["SecureStorageKit"]),
    ],
    targets: [
        .target(name: "SecureStorageKit"),
        .testTarget(name: "SecureStorageKitTests", dependencies: ["SecureStorageKit"]),
    ],
    swiftLanguageModes: [.v6]
)
