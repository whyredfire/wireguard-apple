// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

public class LogViewHelper {
    var log: OpaquePointer
    var cursor: UInt32 = UINT32_MAX
    static let formatOptions: ISO8601DateFormatter.Options = [
        .withYear, .withMonth, .withDay, .withTime,
        .withDashSeparatorInDate, .withColonSeparatorInTime, .withSpaceBetweenDateAndTime,
        .withFractionalSeconds
    ]

    struct LogEntry {
        let timestamp: String
        let message: String

        func text() -> String {
            return timestamp + " " + message
        }
    }

    class LogEntries {
        var entries: [LogEntry] = []
    }

    init?(logFilePath: String?) {
        guard let logFilePath = logFilePath else { return nil }
        guard let log = open_log(logFilePath) else { return nil }
        self.log = log
    }

    deinit {
        close_log(self.log)
    }

    func fetchLogEntriesSinceLastFetch(completion: @escaping ([LogViewHelper.LogEntry]) -> Void) {
        let logEntries = LogEntries()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let newCursor = view_lines_from_cursor(self.log, self.cursor, Unmanaged.passUnretained(logEntries).toOpaque()) { cStr, timestamp, ctx in
                let message = cStr != nil ? String(cString: cStr!) : ""
                let date = Date(timeIntervalSince1970: Double(timestamp) / 1000000000)
                let dateString = ISO8601DateFormatter.string(from: date, timeZone: TimeZone.current, formatOptions: LogViewHelper.formatOptions)
                if let ctx = ctx {
                    Unmanaged<LogEntries>.fromOpaque(ctx).takeUnretainedValue().entries.append(LogEntry(timestamp: dateString, message: message))
                }
            }
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.cursor = newCursor
                completion(logEntries.entries)
            }
        }
    }
}
