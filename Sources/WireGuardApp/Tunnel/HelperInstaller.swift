// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Security

enum HelperInstallerError: LocalizedError {
    case missingResource(String)
    case cancelled
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .missingResource(let name): "The app bundle is missing \(name)."
        case .cancelled: "The installation of the WireGuard helper was cancelled."
        case .failed(let output): "The installation of the WireGuard helper failed: \(output)"
        }
    }
}

/// Installs the helper as a LaunchDaemon by running the bundled script as root.
/// The helper only accepts connections from this user, running this app.
enum HelperInstaller {
    static let label = "dev.whyredfire.wireguard.helper"

    static func install() async throws {
        let tool = Bundle.main.bundleURL.appending(path: "Contents/Library/LaunchServices/\(label)")
        guard FileManager.default.fileExists(atPath: tool.path(percentEncoded: false)) else {
            throw HelperInstallerError.missingResource(label)
        }
        guard let script = Bundle.main.url(forResource: "helper-tool", withExtension: "sh") else {
            throw HelperInstallerError.missingResource("helper-tool.sh")
        }
        let arguments = ["/bin/sh", script.path(percentEncoded: false), "install", tool.path(percentEncoded: false),
                         String(getuid()), try designatedRequirement()]
        let command = arguments.map(\.shellQuoted).joined(separator: " ")
        let prompt = "WireGuard needs to install a helper to run tunnels."

        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/osascript")
        process.arguments = ["-e", "do shell script \(command.appleScriptQuoted) with prompt \(prompt.appleScriptQuoted) with administrator privileges"]
        let errorPipe = Pipe()
        process.standardError = errorPipe
        try await process.runUntilExit()
        guard process.terminationStatus == 0 else {
            let output = String(decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw output.contains("-128") ? HelperInstallerError.cancelled : HelperInstallerError.failed(output)
        }
    }

    private static func designatedRequirement() throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var requirement: SecRequirement?
        var text: CFString?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text else {
            throw HelperInstallerError.failed("Unable to read the app's code signature.")
        }
        return text as String
    }
}

private extension Process {
    func runUntilExit() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            terminationHandler = { _ in continuation.resume() }
            do {
                try run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

private extension String {
    var shellQuoted: String {
        "'" + replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }

    var appleScriptQuoted: String {
        "\"" + replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
