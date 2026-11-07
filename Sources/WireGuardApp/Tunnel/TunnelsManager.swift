// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Observation

@MainActor
protocol TunnelsManagerListDelegate: AnyObject {
    func tunnelAdded(at index: Int)
    func tunnelModified(at index: Int)
    func tunnelMoved(from oldIndex: Int, to newIndex: Int)
    func tunnelRemoved(at index: Int, tunnel: TunnelContainer)
}

@MainActor
protocol TunnelsManagerActivationDelegate: AnyObject {
    func tunnelActivationFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationError)
    func tunnelActivationSucceeded(tunnel: TunnelContainer)
}

/// Keeps the tunnels in the keychain and runs them through the root helper.
@MainActor
class TunnelsManager {
    private var tunnels: [TunnelContainer]
    weak var tunnelsListDelegate: TunnelsManagerListDelegate?
    weak var activationDelegate: TunnelsManagerActivationDelegate?
    fileprivate private(set) var helper: HelperClient?
    private var isReconnecting = false

    private init(tunnels: [TunnelContainer]) {
        self.tunnels = tunnels
        tunnels.forEach { $0.manager = self }
    }

    static func create(completionHandler: @escaping (Result<TunnelsManager, TunnelsManagerError>) -> Void) {
        let stored: [String: TunnelStore.Tunnel]
        do {
            stored = try TunnelStore.load()
        } catch {
            completionHandler(.failure(.systemErrorOnListingTunnels(systemError: error)))
            return
        }
        let tunnels = stored.compactMap { name, tunnel -> TunnelContainer? in
            guard let configuration = try? TunnelConfiguration(fromWgQuickConfig: tunnel.config, called: name) else {
                wg_log(.error, message: "Skipping tunnel '\(name)' with an unreadable configuration")
                return nil
            }
            return TunnelContainer(configuration: configuration, isSplitDNSEnabled: tunnel.isSplitDNSEnabled)
        }.sorted { tunnelNameIsLessThan($0.name, $1.name) }

        let manager = TunnelsManager(tunnels: tunnels)
        Task {
            do {
                try await manager.connectHelper(canInstall: true)
                completionHandler(.success(manager))
                manager.restoreActiveTunnels()
            } catch {
                completionHandler(.failure(.helperUnavailable(systemError: error)))
            }
        }
    }

    func add(tunnelConfiguration: TunnelConfiguration, isSplitDNSEnabled: Bool = false, completionHandler: @escaping (Result<TunnelContainer, TunnelsManagerError>) -> Void) {
        let tunnelName = tunnelConfiguration.name ?? ""
        if tunnelName.isEmpty {
            completionHandler(.failure(.tunnelNameEmpty))
            return
        }
        if tunnels.contains(where: { $0.name == tunnelName }) {
            completionHandler(.failure(.tunnelAlreadyExistsWithThatName))
            return
        }

        let tunnel = TunnelContainer(configuration: tunnelConfiguration, isSplitDNSEnabled: isSplitDNSEnabled)
        tunnel.manager = self
        let previousTunnels = tunnels
        tunnels.append(tunnel)
        tunnels.sort { TunnelsManager.tunnelNameIsLessThan($0.name, $1.name) }
        do {
            try save()
        } catch {
            tunnels = previousTunnels
            completionHandler(.failure(.systemErrorOnAddTunnel(systemError: error)))
            return
        }
        tunnelsListDelegate?.tunnelAdded(at: tunnels.firstIndex(of: tunnel)!)
        completionHandler(.success(tunnel))
    }

    func addMultiple(tunnelConfigurations: [TunnelConfiguration], completionHandler: @escaping (UInt, TunnelsManagerError?) -> Void) {
        var numberSuccessful: UInt = 0
        var lastError: TunnelsManagerError?
        for tunnelConfiguration in tunnelConfigurations {
            add(tunnelConfiguration: tunnelConfiguration) { result in
                switch result {
                case .success: numberSuccessful += 1
                case .failure(let error): lastError = error
                }
            }
        }
        completionHandler(numberSuccessful, lastError)
    }

    func modify(tunnel: TunnelContainer, tunnelConfiguration: TunnelConfiguration, isSplitDNSEnabled: Bool? = nil,
                completionHandler: @escaping (TunnelsManagerError?) -> Void) {
        let tunnelName = tunnelConfiguration.name ?? ""
        if tunnelName.isEmpty {
            completionHandler(.tunnelNameEmpty)
            return
        }
        let oldName = tunnel.name
        if tunnelName != oldName && tunnels.contains(where: { $0.name == tunnelName }) {
            completionHandler(.tunnelAlreadyExistsWithThatName)
            return
        }

        let oldConfiguration = tunnel.tunnelConfiguration
        let oldSplitDNS = tunnel.isSplitDNSEnabled
        tunnel.name = tunnelName
        tunnel.tunnelConfiguration = tunnelConfiguration
        tunnel.isSplitDNSEnabled = isSplitDNSEnabled ?? oldSplitDNS
        do {
            try save()
        } catch {
            tunnel.name = oldName
            tunnel.tunnelConfiguration = oldConfiguration
            tunnel.isSplitDNSEnabled = oldSplitDNS
            completionHandler(.systemErrorOnModifyTunnel(systemError: error))
            return
        }
        if activeTunnelNames.remove(oldName) != nil {
            activeTunnelNames.insert(tunnelName)
        }

        if tunnelName != oldName {
            let oldIndex = tunnels.firstIndex(of: tunnel)!
            tunnels.sort { TunnelsManager.tunnelNameIsLessThan($0.name, $1.name) }
            tunnelsListDelegate?.tunnelMoved(from: oldIndex, to: tunnels.firstIndex(of: tunnel)!)
        }
        tunnelsListDelegate?.tunnelModified(at: tunnels.firstIndex(of: tunnel)!)

        let isChanged = tunnelName != oldName || tunnelConfiguration != oldConfiguration || tunnel.isSplitDNSEnabled != oldSplitDNS
        if isChanged && (tunnel.status == .active || tunnel.status == .activating) {
            // Restart the tunnel, so the changes are made effective.
            tunnel.status = .restarting
            Task {
                _ = try? await helper?.request("down", name: oldName)
                tunnel.status = .inactive
                startActivation(of: tunnel)
            }
        }
        completionHandler(nil)
    }

    func remove(tunnel: TunnelContainer, completionHandler: @escaping (TunnelsManagerError?) -> Void) {
        guard let index = tunnels.firstIndex(of: tunnel) else {
            completionHandler(nil)
            return
        }
        tunnels.remove(at: index)
        do {
            try save()
        } catch {
            tunnels.insert(tunnel, at: index)
            completionHandler(.systemErrorOnRemoveTunnel(systemError: error))
            return
        }
        startDeactivation(of: tunnel)
        tunnelsListDelegate?.tunnelRemoved(at: index, tunnel: tunnel)
        completionHandler(nil)
    }

    func removeMultiple(tunnels: [TunnelContainer], completionHandler: @escaping (TunnelsManagerError?) -> Void) {
        var lastError: TunnelsManagerError?
        for tunnel in tunnels {
            remove(tunnel: tunnel) { error in
                lastError = error ?? lastError
            }
        }
        completionHandler(lastError)
    }

    func numberOfTunnels() -> Int {
        return tunnels.count
    }

    func tunnel(at index: Int) -> TunnelContainer {
        return tunnels[index]
    }

    func mapTunnels<T>(transform: (TunnelContainer) throws -> T) rethrows -> [T] {
        return try tunnels.map(transform)
    }

    func index(of tunnel: TunnelContainer) -> Int? {
        return tunnels.firstIndex(of: tunnel)
    }

    func tunnel(named tunnelName: String) -> TunnelContainer? {
        return tunnels.first { $0.name == tunnelName }
    }

    func tunnelsInOperation() -> [TunnelContainer] {
        return tunnels.filter { $0.status != .inactive }
    }

    func startActivation(of tunnel: TunnelContainer) {
        guard tunnels.contains(tunnel), let configuration = tunnel.tunnelConfiguration else { return }
        guard tunnel.status == .inactive else {
            activationDelegate?.tunnelActivationFailed(tunnel: tunnel, error: .tunnelIsNotInactive)
            return
        }
        tunnel.status = .activating
        activeTunnelNames.insert(tunnel.name)
        let config = HelperTunnelConfig(configuration, name: tunnel.name, isSplitDNSEnabled: tunnel.isSplitDNSEnabled)
        Task {
            do {
                guard let helper else { throw HelperError.disconnected }
                try await helper.request("up", config: config)
                guard tunnel.status == .activating else { return }
                tunnel.status = .active
                activationDelegate?.tunnelActivationSucceeded(tunnel: tunnel)
            } catch {
                guard tunnel.status == .activating else { return }
                wg_log(.error, message: "Starting tunnel '\(tunnel.name)' failed: \(error.localizedDescription)")
                tunnel.status = .inactive
                activationDelegate?.tunnelActivationFailed(tunnel: tunnel, error: .failedWhileStarting(systemError: error))
            }
        }
    }

    func startDeactivation(of tunnel: TunnelContainer) {
        activeTunnelNames.remove(tunnel.name)
        guard tunnel.status != .inactive && tunnel.status != .deactivating else { return }
        tunnel.status = .deactivating
        Task {
            _ = try? await helper?.request("down", name: tunnel.name)
            tunnel.status = .inactive
        }
    }

    /// The helper's log entries after the first `cursor` ones, and the new cursor.
    func helperLog(since cursor: Int) async -> (entries: [LogViewHelper.LogEntry], cursor: Int) {
        guard let response = try? await helper?.request("log", cursor: cursor) else { return ([], cursor) }
        let entries = (response.log ?? []).map { LogViewHelper.LogEntry(timestamp: $0.time, message: "[HELPER] " + $0.message) }
        return (entries, response.cursor ?? cursor)
    }

    /// The tunnels that were turned on, so they come back when the app or the helper restarts.
    private var activeTunnelNames: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: "ActiveTunnels") ?? []) }
        set { UserDefaults.standard.set(newValue.sorted(), forKey: "ActiveTunnels") }
    }

    private func restoreActiveTunnels() {
        let names = activeTunnelNames
        for tunnel in tunnels where names.contains(tunnel.name) && tunnel.status == .inactive {
            startActivation(of: tunnel)
        }
    }

    private func save() throws {
        var stored = [String: TunnelStore.Tunnel]()
        for tunnel in tunnels {
            guard let configuration = tunnel.tunnelConfiguration else { continue }
            stored[tunnel.name] = TunnelStore.Tunnel(config: configuration.asWgQuickConfig(), isSplitDNSEnabled: tunnel.isSplitDNSEnabled)
        }
        try TunnelStore.save(stored)
    }

    private func connectHelper(canInstall: Bool) async throws {
        helper = try await HelperClient.connect(canInstall: canInstall) { [weak self] in
            Task { @MainActor in await self?.helperDisconnected() }
        }
    }

    /// The helper stops the tunnels of a lost connection, so mark them inactive,
    /// reconnect, e.g. after launchd restarted the helper, and start them again.
    private func helperDisconnected() async {
        guard !isReconnecting else { return }
        isReconnecting = true
        defer { isReconnecting = false }
        wg_log(.error, staticMessage: "Lost the connection to the helper")
        helper = nil
        tunnels.forEach { $0.status = .inactive }
        for _ in 0..<10 {
            if (try? await connectHelper(canInstall: false)) != nil {
                restoreActiveTunnels()
                return
            }
            try? await Task.sleep(for: .seconds(1))
        }
        wg_log(.error, staticMessage: "Unable to reconnect to the helper")
    }

    nonisolated static func tunnelNameIsLessThan(_ lhs: String, _ rhs: String) -> Bool {
        return lhs.compare(rhs, options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive, .numeric]) == .orderedAscending
    }
}

@MainActor @Observable
class TunnelContainer: NSObject {
    var name: String
    var status: TunnelStatus = .inactive

    @ObservationIgnored fileprivate(set) var tunnelConfiguration: TunnelConfiguration?
    @ObservationIgnored fileprivate(set) var isSplitDNSEnabled: Bool
    @ObservationIgnored fileprivate weak var manager: TunnelsManager?

    fileprivate init(configuration: TunnelConfiguration, isSplitDNSEnabled: Bool) {
        name = configuration.name ?? "Unnamed"
        tunnelConfiguration = configuration
        self.isSplitDNSEnabled = isSplitDNSEnabled
        super.init()
    }

    func getRuntimeTunnelConfiguration(completionHandler: @escaping ((TunnelConfiguration?) -> Void)) {
        guard status == .active, let helper = manager?.helper, let base = tunnelConfiguration else {
            completionHandler(tunnelConfiguration)
            return
        }
        Task {
            let runtime = try? await helper.request("runtime", name: name).runtime
            completionHandler(runtime.flatMap { try? TunnelConfiguration(fromUapiConfig: $0, basedOn: base) } ?? tunnelConfiguration)
        }
    }
}
