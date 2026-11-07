// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

enum TunnelsManagerError: WireGuardAppError {
    case tunnelNameEmpty
    case tunnelAlreadyExistsWithThatName
    case helperUnavailable(systemError: Error)
    case systemErrorOnListingTunnels(systemError: Error)
    case systemErrorOnAddTunnel(systemError: Error)
    case systemErrorOnModifyTunnel(systemError: Error)
    case systemErrorOnRemoveTunnel(systemError: Error)

    var alertText: AlertText {
        switch self {
        case .tunnelNameEmpty:
            return (tr("alertTunnelNameEmptyTitle"), tr("alertTunnelNameEmptyMessage"))
        case .tunnelAlreadyExistsWithThatName:
            return (tr("alertTunnelAlreadyExistsWithThatNameTitle"), tr("alertTunnelAlreadyExistsWithThatNameMessage"))
        case .helperUnavailable(let systemError), .systemErrorOnListingTunnels(let systemError):
            return (tr("alertSystemErrorOnListingTunnelsTitle"), systemError.localizedDescription)
        case .systemErrorOnAddTunnel(let systemError):
            return (tr("alertSystemErrorOnAddTunnelTitle"), systemError.localizedDescription)
        case .systemErrorOnModifyTunnel(let systemError):
            return (tr("alertSystemErrorOnModifyTunnelTitle"), systemError.localizedDescription)
        case .systemErrorOnRemoveTunnel(let systemError):
            return (tr("alertSystemErrorOnRemoveTunnelTitle"), systemError.localizedDescription)
        }
    }
}

enum TunnelsManagerActivationError: WireGuardAppError {
    case tunnelIsNotInactive
    case failedWhileStarting(systemError: Error)

    var alertText: AlertText {
        switch self {
        case .tunnelIsNotInactive:
            return (tr("alertTunnelActivationErrorTunnelIsNotInactiveTitle"), tr("alertTunnelActivationErrorTunnelIsNotInactiveMessage"))
        case .failedWhileStarting(let systemError):
            return (tr("alertTunnelActivationSystemErrorTitle"),
                    tr(format: "alertTunnelActivationSystemErrorMessage (%@)", systemError.localizedDescription))
        }
    }
}
