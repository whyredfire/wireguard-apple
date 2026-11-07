// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

enum ZipExporterError: WireGuardAppError {
    case noTunnelsToExport

    var alertText: AlertText {
        return (tr("alertNoTunnelsToExportTitle"), tr("alertNoTunnelsToExportMessage"))
    }
}

@MainActor
enum ZipExporter {
    static func exportConfigFiles(tunnelConfigurations: [TunnelConfiguration], to url: URL) async throws(ZipArchiveError) {
        var files: [(fileName: String, contents: Data)] = []
        var lastTunnelName = ""
        for tunnelConfiguration in tunnelConfigurations {
            let name = tunnelConfiguration.name ?? "untitled"
            if name.isEmpty || name == lastTunnelName { continue }
            files.append((fileName: "\(name).conf", contents: Data(tunnelConfiguration.asWgQuickConfig().utf8)))
            lastTunnelName = name
        }
        try await archive(files, to: url)
    }

    @concurrent
    private static func archive(_ files: [(fileName: String, contents: Data)], to url: URL) async throws(ZipArchiveError) {
        try ZipArchive.archive(inputs: files, to: url)
    }
}
