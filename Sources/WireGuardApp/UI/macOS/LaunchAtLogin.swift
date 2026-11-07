// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import ServiceManagement

/// Opening at login is on by default, and stays off once turned off.
@MainActor
enum LaunchAtLogin {
    private static let configuredKey = "LaunchAtLoginConfigured"

    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func enableOnFirstLaunch() {
        guard !UserDefaults.standard.bool(forKey: configuredKey) else { return }
        setEnabled(true)
    }

    static func setEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(true, forKey: configuredKey)
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            wg_log(.error, message: "Unable to change launching at login: \(error.localizedDescription)")
        }
        // Turned off in System Settings, so only the user can turn it back on there.
        if enabled && SMAppService.mainApp.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
    }
}
