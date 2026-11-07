// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Reads the app's log, from where the previous read stopped.
actor LogViewHelper {
    struct LogEntry: Sendable {
        let timestamp: String
        let message: String

        func text() -> String {
            return timestamp + " " + message
        }
    }

    private static let formatOptions: ISO8601DateFormatter.Options = [
        .withYear, .withMonth, .withDay, .withTime,
        .withDashSeparatorInDate, .withColonSeparatorInTime, .withSpaceBetweenDateAndTime,
        .withFractionalSeconds
    ]

    private let log: OpaquePointer
    private var cursor: UInt32 = UINT32_MAX

    init?(logFilePath: String?) {
        guard let logFilePath, let log = open_log(logFilePath) else { return nil }
        self.log = log
    }

    isolated deinit {
        close_log(log)
    }

    func fetchNewEntries() -> [LogEntry] {
        final class Entries {
            var entries: [LogEntry] = []
        }
        let entries = Entries()
        cursor = view_lines_from_cursor(log, cursor, Unmanaged.passUnretained(entries).toOpaque()) { cString, timestamp, context in
            guard let context else { return }
            let message = cString.map { String(cString: $0) } ?? ""
            let date = Date(timeIntervalSince1970: Double(timestamp) / 1_000_000_000)
            let dateString = ISO8601DateFormatter.string(from: date, timeZone: .current, formatOptions: LogViewHelper.formatOptions)
            Unmanaged<Entries>.fromOpaque(context).takeUnretainedValue().entries.append(LogEntry(timestamp: dateString, message: message))
        }
        return entries.entries
    }
}
