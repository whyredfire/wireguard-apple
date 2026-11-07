// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// WireGuardKitCore and WireGuardKit share Sources/WireGuardKit.
let wireGuardKitCoreSources = [
    "DNSServer.swift",
    "Endpoint.swift",
    "InterfaceConfiguration.swift",
    "IPAddressRange.swift",
    "PeerConfiguration.swift",
    "PrivateKey.swift",
    "TunnelConfiguration.swift"
]
let wireGuardKitAdapterSources = [
    "Array+ConcurrentMap.swift",
    "DNSResolver.swift",
    "Exports.swift",
    "IPAddress+AddrInfo.swift",
    "PacketTunnelSettingsGenerator.swift",
    "WireGuardAdapter.swift"
]

// Copied into the app bundle by scripts/build.sh.
let appLocalizations = [
    "Base", "ca", "de", "es", "fa", "fi", "fr", "id", "it", "ja",
    "ko", "pa", "pl", "ro", "ru", "sl", "tr", "zh-Hans", "zh-Hant"
]

let package = Package(
    name: "WireGuardKit",
    platforms: [
        .macOS(.v13),
        .iOS(.v15)
    ],
    products: [
        .library(name: "WireGuardKit", targets: ["WireGuardKit"]),
        .executable(name: "WireGuard", targets: ["WireGuard"]),
        .executable(name: "WireGuardNetworkExtension", targets: ["WireGuardNetworkExtension"]),
        .executable(name: "WireGuardLoginItemHelper", targets: ["WireGuardLoginItemHelper"])
    ],
    dependencies: [],
    targets: [
        // MARK: WireGuardKit

        // The configuration model, without wireguard-go, for the app.
        .target(
            name: "WireGuardKitCore",
            dependencies: ["WireGuardKitC"],
            path: "Sources/WireGuardKit",
            exclude: wireGuardKitAdapterSources,
            sources: wireGuardKitCoreSources
        ),
        .target(
            name: "WireGuardKit",
            dependencies: ["WireGuardKitCore", "WireGuardKitGo", "WireGuardKitC"],
            path: "Sources/WireGuardKit",
            exclude: wireGuardKitCoreSources,
            sources: wireGuardKitAdapterSources
        ),
        .target(
            name: "WireGuardKitC",
            dependencies: [],
            publicHeadersPath: "."
        ),
        // libwg-go.a is built by the Makefile; see scripts/build.sh.
        .target(
            name: "WireGuardKitGo",
            dependencies: [],
            exclude: [
                "goruntime-boottime-over-monotonic.diff",
                "go.mod",
                "go.sum",
                "api-apple.go",
                "Makefile"
            ],
            publicHeadersPath: ".",
            linkerSettings: [.linkedLibrary("wg-go")]
        ),

        // MARK: macOS app

        .target(
            name: "WireGuardShared",
            dependencies: ["WireGuardKitCore", "RingLogger"],
            path: "Sources/Shared"
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
        .systemLibrary(name: "LibProc"),
        .executableTarget(
            name: "WireGuard",
            dependencies: ["WireGuardKitCore", "WireGuardShared", "RingLogger", "Highlighter", "Minizip", "LibProc"],
            path: "Sources/WireGuardApp",
            exclude: appLocalizations.map { "\($0).lproj" } + [
                "UI/macOS/Resources",
                "UI/macOS/Info.plist",
                "UI/macOS/WireGuard.entitlements"
            ]
        ),
        .executableTarget(
            name: "WireGuardNetworkExtension",
            dependencies: ["WireGuardKit", "WireGuardShared"],
            path: "Sources/WireGuardNetworkExtension",
            exclude: [
                "Info.plist",
                "WireGuardNetworkExtension_macOS.entitlements"
            ]
        ),
        .executableTarget(
            name: "WireGuardLoginItemHelper",
            exclude: [
                "Info.plist",
                "LoginItemHelper.entitlements"
            ]
        )
    ]
)
