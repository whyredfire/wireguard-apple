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

let package = Package(
    name: "WireGuardKit",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(name: "WireGuardKit", targets: ["WireGuardKit"])
    ],
    dependencies: [],
    targets: [
        // Tunnel configuration model: no dependency on wireguard-go, so the
        // app can use it without linking the Go runtime.
        .target(
            name: "WireGuardKitCore",
            dependencies: ["WireGuardKitC"],
            path: "Sources/WireGuardKit",
            exclude: wireGuardKitAdapterSources,
            sources: wireGuardKitCoreSources
        ),
        // The tunnel adapter driving wireguard-go. Re-exports WireGuardKitCore.
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
        )
    ]
)
