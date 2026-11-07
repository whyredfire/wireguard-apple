// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

extension FileManager {
    static var logFileURL: URL? {
        let directory = URL.applicationSupportDirectory.appending(path: Bundle.main.bundleIdentifier!)
        guard (try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)) != nil else { return nil }
        return directory.appending(path: "log.bin")
    }
}
