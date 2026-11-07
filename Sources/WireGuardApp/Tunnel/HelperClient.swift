// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

enum HelperError: LocalizedError {
    case unavailable(Error)
    case disconnected
    case outdated
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let error): "The WireGuard helper is unavailable: \(error.localizedDescription)"
        case .disconnected: "The connection to the WireGuard helper was lost."
        case .outdated: "The WireGuard helper is outdated."
        case .failed(let message): message
        }
    }
}

/// Talks to the root helper over its Unix socket, with JSON requests and
/// responses, one per line, answered in order.
actor HelperClient {
    static let socketPath = "/var/run/dev.whyredfire.wireguard.helper.sock"
    static let version = "2"

    struct Response: Decodable, Sendable {
        var error: String?
        var version: String?
        var interface: String?
        var runtime: String?
        var log: [LogLine]?
        var cursor: Int?
    }

    struct LogLine: Decodable, Sendable {
        var time: String
        var message: String
    }

    private let fd: Int32
    private let handle: FileHandle
    private var pending: [CheckedContinuation<Response, Error>] = []
    private var isConnected = true
    private var isEstablished = false

    /// Connects to the helper; once established, `onDisconnect` is called when the helper closes the connection.
    init(onDisconnect: @escaping @Sendable () -> Void) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HelperError.unavailable(POSIXError(.init(rawValue: errno) ?? .EIO)) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { path in
            Self.socketPath.utf8CString.withUnsafeBytes { path.copyMemory(from: $0) }
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EIO)
            Darwin.close(fd)
            throw HelperError.unavailable(error)
        }
        self.fd = fd
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        let lines = Self.readLines(from: fd)
        Task { await receive(lines, onDisconnect: onDisconnect) }
    }

    /// Reads lines on a thread of their own, as reading blocks.
    private static func readLines(from fd: Int32) -> AsyncStream<Data> {
        let (lines, continuation) = AsyncStream.makeStream(of: Data.self)
        Thread.detachNewThread {
            var buffer = Data()
            var chunk = [UInt8](repeating: 0, count: 4096)
            while case let count = read(fd, &chunk, chunk.count), count > 0 {
                buffer.append(contentsOf: chunk[..<count])
                while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                    continuation.yield(buffer[..<newline])
                    buffer.removeSubrange(...newline)
                }
            }
            continuation.finish()
        }
        return lines
    }

    /// Arms `onDisconnect`, unless the connection is already gone.
    private func establish() throws {
        guard isConnected else { throw HelperError.disconnected }
        isEstablished = true
    }

    private func close() {
        shutdown(fd, SHUT_RDWR)
    }

    /// Connects to the helper. If allowed, installs the bundled helper first
    /// when it is missing, outdated or doesn't accept this app.
    static func connect(canInstall: Bool, onDisconnect: @escaping @Sendable () -> Void) async throws -> HelperClient {
        do {
            let client = try HelperClient(onDisconnect: onDisconnect)
            do {
                guard try await client.request("version").version == version else { throw HelperError.outdated }
                try await client.establish()
            } catch {
                await client.close()
                throw error
            }
            return client
        } catch where canInstall {
            try await HelperInstaller.install()
            for _ in 0..<25 {
                if let client = try? await connect(canInstall: false, onDisconnect: onDisconnect) {
                    return client
                }
                try await Task.sleep(for: .milliseconds(200))
            }
            return try await connect(canInstall: false, onDisconnect: onDisconnect)
        }
    }

    @discardableResult
    func request(_ op: String, name: String? = nil, config: HelperTunnelConfig? = nil, cursor: Int? = nil) async throws -> Response {
        struct Request: Encodable {
            var op: String
            var name: String?
            var config: HelperTunnelConfig?
            var cursor: Int?
        }
        guard isConnected else { throw HelperError.disconnected }
        var line = try JSONEncoder().encode(Request(op: op, name: name, config: config, cursor: cursor))
        line.append(UInt8(ascii: "\n"))
        let response = try await withCheckedThrowingContinuation { continuation in
            pending.append(continuation)
            do {
                try handle.write(contentsOf: line)
            } catch {
                pending.removeLast()
                continuation.resume(throwing: HelperError.disconnected)
            }
        }
        if let error = response.error {
            throw HelperError.failed(error)
        }
        return response
    }

    private func receive(_ lines: AsyncStream<Data>, onDisconnect: @Sendable () -> Void) async {
        for await line in lines {
            guard !pending.isEmpty else { continue }
            let continuation = pending.removeFirst()
            do {
                continuation.resume(returning: try JSONDecoder().decode(Response.self, from: line))
            } catch {
                continuation.resume(throwing: HelperError.failed("Invalid response from the WireGuard helper."))
            }
        }
        isConnected = false
        pending.forEach { $0.resume(throwing: HelperError.disconnected) }
        pending.removeAll()
        if isEstablished {
            onDisconnect()
        }
    }
}

/// A tunnel's configuration in the form the helper takes.
struct HelperTunnelConfig: Encodable, Sendable {
    struct Peer: Encodable {
        var publicKey: String
        var presharedKey: String?
        var endpoint: String?
        var allowedIPs: [String]
        var persistentKeepalive: UInt16?
    }

    var name: String
    var privateKey: String
    var listenPort: UInt16?
    var mtu: UInt16?
    var addresses: [String]
    var dns: [String]
    var dnsSearch: [String]
    var splitDNS: Bool
    var peers: [Peer]

    init(_ configuration: TunnelConfiguration, name: String, isSplitDNSEnabled: Bool) {
        let interface = configuration.interface
        self.name = name
        privateKey = interface.privateKey.hexKey
        listenPort = interface.listenPort
        mtu = interface.mtu
        addresses = interface.addresses.map(\.stringRepresentation)
        dns = interface.dns.map(\.stringRepresentation)
        dnsSearch = interface.dnsSearch
        splitDNS = isSplitDNSEnabled
        peers = configuration.peers.map { peer in
            Peer(publicKey: peer.publicKey.hexKey,
                 presharedKey: peer.preSharedKey?.hexKey,
                 endpoint: peer.endpoint?.stringRepresentation,
                 allowedIPs: peer.allowedIPs.map(\.stringRepresentation),
                 persistentKeepalive: peer.persistentKeepAlive)
        }
    }
}
