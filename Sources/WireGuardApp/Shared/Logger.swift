// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import os

/// The app's log, kept in a ring buffer file for the log view.
final class Logger: @unchecked Sendable { // The ring logger is thread-safe, and the log is never reassigned.
    static let global: Logger? = FileManager.logFileURL.flatMap { try? Logger(tagged: "APP", withFilePath: $0.path(percentEncoded: false)) }

    enum LoggerError: Error {
        case openFailure
    }

    private let log: OpaquePointer
    private let tag: String

    init(tagged tag: String, withFilePath filePath: String) throws {
        guard let log = open_log(filePath) else { throw LoggerError.openFailure }
        self.log = log
        self.tag = tag
    }

    deinit {
        close_log(log)
    }

    func log(message: String) {
        write_msg_to_log(log, tag, message.trimmingCharacters(in: .newlines))
    }

    func writeLog(to targetFile: String) -> Bool {
        return write_log_to_file(targetFile, log) == 0
    }
}

private let systemLog = os.Logger(subsystem: Bundle.main.bundleIdentifier ?? "WireGuard", category: "app")

func wg_log(_ type: OSLogType, staticMessage msg: StaticString) {
    wg_log(type, message: "\(msg)")
}

func wg_log(_ type: OSLogType, message msg: String) {
    systemLog.log(level: type, "\(msg, privacy: .public)")
    Logger.global?.log(message: msg)
}
