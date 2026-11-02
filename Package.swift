// swift-tools-version: 6.2
// AzaKit: the aza client library for iOS and macOS apps, from swift/. scripts/build-swift.sh
// builds the XCFramework into swift/Generated and the bindings into swift/Sources/AzaKit, and
// this package uses that local build when there is one. Everyone else gets the XCFramework
// released with this version (scripts/release-swift.sh).
import Foundation
import PackageDescription

let local = "swift/Generated/AzaKitFFI.xcframework"
let ffi: Target = FileManager.default.fileExists(atPath: "\(Context.packageDirectory)/\(local)")
    ? .binaryTarget(name: "AzaKitFFI", path: local)
    : .binaryTarget(
        name: "AzaKitFFI",
        url: "https://github.com/plarza/protocol/releases/download/0.2.0/AzaKitFFI.xcframework.zip",
        checksum: "8f9367e48db207576c478a2d41f5b46b28bae9e54a79c1c3c8854938ed8bef1d"
    )

let package = Package(
    name: "AzaKit",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [.library(name: "AzaKit", targets: ["AzaKit"])],
    targets: [
        ffi,
        .target(
            name: "AzaKit",
            dependencies: ["AzaKitFFI"],
            path: "swift/Sources/AzaKit",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]
        ),
        .testTarget(name: "AzaKitTests", dependencies: ["AzaKit"], path: "swift/Tests/AzaKitTests"),
    ]
)
