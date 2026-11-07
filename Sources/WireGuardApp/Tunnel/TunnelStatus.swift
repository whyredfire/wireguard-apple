// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

enum TunnelStatus: Sendable {
    case inactive
    case activating
    case active
    case deactivating
    case restarting // Restarting tunnel (done after saving modifications to an active tunnel)
}

extension TunnelStatus: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self {
        case .inactive: return "inactive"
        case .activating: return "activating"
        case .active: return "active"
        case .deactivating: return "deactivating"
        case .restarting: return "restarting"
        }
    }
}
