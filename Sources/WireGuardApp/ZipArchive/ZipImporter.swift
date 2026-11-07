// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

@MainActor
enum ZipImporter {
    static func importConfigFiles(from url: URL) async throws(ZipArchiveError) -> [TunnelConfiguration?] {
        let files = try await unarchive(url)
        var configs: [TunnelConfiguration?] = Array(repeating: nil, count: files.count)
        for (index, file) in files.enumerated() {
            if index > 0 && file == files[index - 1] {
                continue
            }
            guard let fileContents = String(data: file.contents, encoding: .utf8) else { continue }
            configs[index] = try? TunnelConfiguration(fromWgQuickConfig: fileContents, called: file.fileBaseName)
        }
        return configs
    }

    @concurrent
    private static func unarchive(_ url: URL) async throws(ZipArchiveError) -> [(fileBaseName: String, contents: Data)] {
        var files = try ZipArchive.unarchive(url: url, requiredFileExtensions: ["conf"])
        for (index, file) in files.enumerated().reversed() {
            let trimmedName = file.fileBaseName.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedName.isEmpty {
                files.remove(at: index)
            } else {
                files[index].fileBaseName = trimmedName
            }
        }
        if files.isEmpty {
            throw .noTunnelsInZipArchive
        }
        return files.sorted { TunnelsManager.tunnelNameIsLessThan($0.fileBaseName, $1.fileBaseName) }
    }
}
