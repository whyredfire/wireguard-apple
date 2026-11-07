// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa
import UniformTypeIdentifiers

@MainActor
enum ImportPanelPresenter {
    static func presentImportPanel(tunnelsManager: TunnelsManager, sourceVC: NSViewController?) {
        guard let window = sourceVC?.view.window else { return }
        let openPanel = NSOpenPanel()
        openPanel.prompt = tr("macSheetButtonImport")
        openPanel.allowedContentTypes = [UTType(filenameExtension: "conf"), .zip].compactMap { $0 }
        openPanel.allowsMultipleSelection = true
        Task { [weak tunnelsManager] in
            guard await openPanel.beginSheetModal(for: window) == .OK, let tunnelsManager else { return }
            TunnelImporter.importFromFile(urls: openPanel.urls, into: tunnelsManager, sourceVC: sourceVC, errorPresenterType: ErrorPresenter.self)
        }
    }
}
