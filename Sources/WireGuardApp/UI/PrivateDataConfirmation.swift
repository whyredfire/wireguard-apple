// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import AppKit
import LocalAuthentication

@MainActor
enum PrivateDataConfirmation {
    static func confirmAccess(to reason: String, _ after: @escaping @MainActor () -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // We give no protection to folks who just don't set a passcode.
            if (error as? LAError)?.code == .passcodeNotSet {
                after()
            }
            return
        }
        Task {
            let success = (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
            if !NSApp.isActive {
                NSApp.activate()
            }
            if success {
                after()
            }
        }
    }
}
