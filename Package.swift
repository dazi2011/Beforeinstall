// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "BeforeInstall",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "BeforeInstall", targets: ["BeforeInstall"])
    ],
    targets: [
        .executableTarget(
            name: "BeforeInstall",
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("AppKit"),
                .linkedFramework("UniformTypeIdentifiers")
            ]
        )
    ]
)
