// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Security

/// Keeps the tunnels' configurations in a single item of the login keychain,
/// so that the keychain asks at most once for access to all of them.
enum TunnelStore {
    struct Tunnel: Codable {
        var config: String
        var isSplitDNSEnabled: Bool
    }

    private static let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: Bundle.main.bundleIdentifier!,
        kSecAttrAccount: "tunnels"
    ]

    static func load() throws -> [String: Tunnel] {
        var query = self.query
        query[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return [:]
        }
        guard status == errSecSuccess, let data = result as? Data else { throw error(status) }
        return try JSONDecoder().decode([String: Tunnel].self, from: data)
    }

    static func save(_ tunnels: [String: Tunnel]) throws {
        let data = try JSONEncoder().encode(tunnels)
        var status = SecItemUpdate(query as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData] = data
            item[kSecAttrLabel] = "WireGuard Tunnels"
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw error(status) }
    }

    private static func error(_ status: OSStatus) -> Error {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: message])
    }
}
