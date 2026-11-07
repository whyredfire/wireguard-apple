// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Observation

/// Calls `onChange` with the observed value and with every change to it, until released.
@MainActor
final class ObservationToken {
    private let task: Task<Void, Never>

    init<Value: Sendable>(_ value: @escaping @MainActor @Sendable () -> Value, onChange: @escaping @MainActor (Value) -> Void) {
        task = Task {
            for await current in Observations(value) {
                onChange(current)
            }
        }
    }

    deinit {
        task.cancel()
    }
}
