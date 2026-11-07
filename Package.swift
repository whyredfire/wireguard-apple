// swift-tools-version:6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// Copied into the app bundle by scripts/build.sh.
let appLocalizations = [
    "Base", "ca", "de", "es", "fa", "fi", "fr", "id", "it", "ja",
    "ko", "pa", "pl", "ro", "ru", "sl", "tr", "zh-Hans", "zh-Hant"
]

let package = Package(
    name: "WireGuard",
    platforms: [
        .macOS(.v26)
    ],
    targets: [
        .target(
            name: "WireGuardKit",
            dependencies: ["WireGuardKitC"]
        ),
        .target(
            name: "WireGuardKitC",
            publicHeadersPath: "."
        ),
        .target(
            name: "RingLogger",
            exclude: ["test_ringlogger.c"],
            publicHeadersPath: "."
        ),
        .target(
            name: "Highlighter",
            publicHeadersPath: "."
        ),
        .target(
            name: "Minizip",
            exclude: ["MiniZip64_info.txt"],
            publicHeadersPath: ".",
            linkerSettings: [.linkedLibrary("z")]
        ),
        .executableTarget(
            name: "WireGuard",
            dependencies: ["WireGuardKit", "RingLogger", "Highlighter", "Minizip"],
            path: "Sources/WireGuardApp",
            exclude: appLocalizations.map { "\($0).lproj" } + [
                "UI/macOS/Resources",
                "UI/macOS/Info.plist"
            ]
        )
    ],
    swiftLanguageModes: [.v5]
)
