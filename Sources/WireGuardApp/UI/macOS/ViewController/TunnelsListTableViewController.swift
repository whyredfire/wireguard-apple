// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa
import UniformTypeIdentifiers

@MainActor
protocol TunnelsListTableViewControllerDelegate: AnyObject {
    func tunnelsSelected(tunnelIndices: [Int])
    func tunnelsListEmpty()
}

class TunnelsListTableViewController: NSViewController {

    let tunnelsManager: TunnelsManager
    weak var delegate: TunnelsListTableViewControllerDelegate?
    var isRemovingTunnelsFromWithinTheApp = false

    let tableView: NSTableView = {
        let tableView = NSTableView()
        tableView.addTableColumn(NSTableColumn(identifier: NSUserInterfaceItemIdentifier("TunnelsList")))
        tableView.headerView = nil
        tableView.rowSizeStyle = .medium
        tableView.allowsMultipleSelection = true
        return tableView
    }()

    let addButton = barPullDownButton(symbol: "plus", items: [
        NSMenuItem(title: tr("macMenuAddEmptyTunnel"), action: #selector(handleAddEmptyTunnelAction), keyEquivalent: "n"),
        NSMenuItem(title: tr("macMenuImportTunnels"), action: #selector(handleImportTunnelAction), keyEquivalent: "o")
    ])

    let removeButton: NSButton = {
        let button = NSButton(image: barSymbol("minus"), target: nil, action: #selector(handleRemoveTunnelAction))
        button.isBordered = false
        return button
    }()

    private static func barSymbol(_ name: String) -> NSImage {
        NSImage(systemSymbolName: name, accessibilityDescription: nil)!
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 13, weight: .regular))!
    }

    private static func barPullDownButton(symbol: String, items: [NSMenuItem]) -> NSPopUpButton {
        // A pull-down button shows its first item, so that one only carries the symbol.
        let titleItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        titleItem.image = barSymbol(symbol)
        let menu = NSMenu()
        menu.items = [titleItem] + items
        menu.autoenablesItems = false

        let button = NSPopUpButton(frame: .zero, pullsDown: true)
        button.menu = menu
        button.isBordered = false
        (button.cell as? NSPopUpButtonCell)?.arrowPosition = .noArrow
        return button
    }

    init(tunnelsManager: TunnelsManager) {
        self.tunnelsManager = tunnelsManager
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        tableView.dataSource = self
        tableView.delegate = self

        tableView.doubleAction = #selector(listDoubleClicked(sender:))

        let isSelected = selectTunnelInOperation() || selectTunnel(at: 0)
        if !isSelected {
            delegate?.tunnelsListEmpty()
        }
        tableView.allowsEmptySelection = false

        tableView.backgroundColor = .clear

        let scrollView = NSScrollView()
        let clipView = NSClipView()
        clipView.documentView = tableView
        scrollView.contentView = clipView // Set contentView before setting drawsBackground
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true

        // Matches the box behind the tunnel details.
        let box = NSBox()
        box.titlePosition = .noTitle
        box.fillColor = .unemphasizedSelectedContentBackgroundColor

        let separator = NSBox()
        separator.boxType = .separator

        let buttonBar = NSStackView(views: [addButton, removeButton])
        buttonBar.spacing = 2
        for button in [addButton, removeButton] {
            button.widthAnchor.constraint(equalToConstant: 26).isActive = true
            button.heightAnchor.constraint(equalToConstant: 22).isActive = true
        }

        let containerView = NSView()
        for subview in [box, scrollView, separator, buttonBar] {
            containerView.addSubview(subview)
            subview.translatesAutoresizingMaskIntoConstraints = false
        }

        NSLayoutConstraint.activate([
            box.topAnchor.constraint(equalTo: containerView.topAnchor),
            box.bottomAnchor.constraint(equalTo: containerView.bottomAnchor),
            box.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            box.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),

            scrollView.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 6),
            scrollView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: separator.topAnchor),

            separator.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 8),
            separator.trailingAnchor.constraint(equalTo: containerView.trailingAnchor, constant: -8),
            separator.bottomAnchor.constraint(equalTo: buttonBar.topAnchor, constant: -4),

            buttonBar.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 6),
            buttonBar.bottomAnchor.constraint(equalTo: containerView.bottomAnchor, constant: -5),

            containerView.widthAnchor.constraint(equalToConstant: 180),
            containerView.heightAnchor.constraint(greaterThanOrEqualToConstant: 120)
        ])

        addButton.menu?.items.forEach { $0.target = self }
        removeButton.target = self

        view = containerView
    }

    override func viewWillAppear() {
        selectTunnelInOperation()
    }

    @discardableResult
    func selectTunnelInOperation() -> Bool {
        if let currentTunnel = tunnelsManager.tunnelsInOperation().first, let indexToSelect = tunnelsManager.index(of: currentTunnel) {
            return selectTunnel(at: indexToSelect)
        }
        return false
    }

    @objc func handleAddEmptyTunnelAction() {
        let tunnelEditVC = TunnelEditViewController(tunnelsManager: tunnelsManager, tunnel: nil)
        tunnelEditVC.delegate = self
        presentAsSheet(tunnelEditVC)
    }

    @objc func handleImportTunnelAction() {
        ImportPanelPresenter.presentImportPanel(tunnelsManager: tunnelsManager, sourceVC: self)
    }

    @objc func handleRemoveTunnelAction() {
        guard let window = view.window else { return }

        let selectedTunnelIndices = tableView.selectedRowIndexes.sorted().filter { $0 >= 0 && $0 < tunnelsManager.numberOfTunnels() }
        guard !selectedTunnelIndices.isEmpty else { return }
        var nextSelection = selectedTunnelIndices.last! + 1
        if nextSelection >= tunnelsManager.numberOfTunnels() {
            nextSelection = max(selectedTunnelIndices.first! - 1, 0)
        }

        let alert = DeleteTunnelsConfirmationAlert()
        if selectedTunnelIndices.count == 1 {
            let firstSelectedTunnel = tunnelsManager.tunnel(at: selectedTunnelIndices.first!)
            alert.messageText = tr(format: "macDeleteTunnelConfirmationAlertMessage (%@)", firstSelectedTunnel.name)
        } else {
            alert.messageText = tr(format: "macDeleteMultipleTunnelsConfirmationAlertMessage (%d)", selectedTunnelIndices.count)
        }
        alert.informativeText = tr("macDeleteTunnelConfirmationAlertInfo")
        alert.onDeleteClicked = { [weak self] completion in
            guard let self = self else { return }
            self.selectTunnel(at: nextSelection)
            let selectedTunnels = selectedTunnelIndices.map { self.tunnelsManager.tunnel(at: $0) }
            self.isRemovingTunnelsFromWithinTheApp = true
            self.tunnelsManager.removeMultiple(tunnels: selectedTunnels) { [weak self] error in
                guard let self = self else { return }
                self.isRemovingTunnelsFromWithinTheApp = false
                defer { completion() }
                if let error = error {
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                    return
                }
             }
        }
        alert.beginSheetModal(for: window)
    }

    @objc func handleViewLogAction() {
        let logVC = LogViewController(tunnelsManager: tunnelsManager)
        self.presentAsSheet(logVC)
    }

    /// The app-wide actions, shown next to the tunnel details' Edit button.
    func makeSettingsMenu() -> NSMenu {
        let menu = NSMenu()
        menu.items = [
            NSMenuItem(title: tr("macMenuViewLog"), action: #selector(handleViewLogAction), keyEquivalent: ""),
            NSMenuItem(title: tr("macMenuExportTunnels"), action: #selector(handleExportTunnelsAction), keyEquivalent: ""),
            .separator(),
            NSMenuItem(title: tr("macMenuLaunchAtLogin"), action: #selector(handleLaunchAtLoginAction), keyEquivalent: "")
        ]
        menu.items.forEach { $0.target = self }
        menu.delegate = self
        return menu
    }

    @objc func handleLaunchAtLoginAction() {
        LaunchAtLogin.setEnabled(!LaunchAtLogin.isEnabled)
    }

    @objc func handleExportTunnelsAction() {
        PrivateDataConfirmation.confirmAccess(to: tr("macExportPrivateData")) { [weak self] in
            guard let self, let window = self.view.window else { return }
            let savePanel = NSSavePanel()
            savePanel.allowedContentTypes = [.zip]
            savePanel.prompt = tr("macSheetButtonExportZip")
            savePanel.nameFieldLabel = tr("macNameFieldExportZip")
            savePanel.nameFieldStringValue = "wireguard-export.zip"
            Task {
                guard await savePanel.beginSheetModal(for: window) == .OK, let destinationURL = savePanel.url else { return }
                let tunnelConfigurations = self.tunnelsManager.mapTunnels { $0.tunnelConfiguration }.compactMap { $0 }
                guard !tunnelConfigurations.isEmpty else {
                    ErrorPresenter.showErrorAlert(error: ZipExporterError.noTunnelsToExport, from: self)
                    return
                }
                do throws(ZipArchiveError) {
                    try await ZipExporter.exportConfigFiles(tunnelConfigurations: tunnelConfigurations, to: destinationURL)
                } catch {
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                }
            }
        }
    }

    @objc func listDoubleClicked(sender: AnyObject) {
        let tunnelIndex = tableView.clickedRow
        guard tunnelIndex >= 0 && tunnelIndex < tunnelsManager.numberOfTunnels() else { return }
        let tunnel = tunnelsManager.tunnel(at: tunnelIndex)
        if tunnel.status == .inactive {
            tunnelsManager.startActivation(of: tunnel)
        } else if tunnel.status == .active {
            tunnelsManager.startDeactivation(of: tunnel)
        }
    }

    @discardableResult
    private func selectTunnel(at index: Int) -> Bool {
        if index < tunnelsManager.numberOfTunnels() {
            tableView.scrollRowToVisible(index)
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            return true
        }
        return false
    }
}

extension TunnelsListTableViewController: TunnelEditViewControllerDelegate {
    func tunnelSaved(tunnel: TunnelContainer) {
        if let tunnelIndex = tunnelsManager.index(of: tunnel), tunnelIndex >= 0 {
            self.selectTunnel(at: tunnelIndex)
        }
    }

    func tunnelEditingCancelled() {
        // Nothing to do
    }
}

extension TunnelsListTableViewController {
    func tunnelAdded(at index: Int) {
        tableView.insertRows(at: IndexSet(integer: index), withAnimation: .slideLeft)
        if tunnelsManager.numberOfTunnels() == 1 {
            selectTunnel(at: 0)
        }
        if !NSApp.isActive {
            // macOS's VPN prompt might have caused us to lose focus
            NSApp.activate()
        }
    }

    func tunnelModified(at index: Int) {
        tableView.reloadData(forRowIndexes: IndexSet(integer: index), columnIndexes: IndexSet(integer: 0))
    }

    func tunnelMoved(from oldIndex: Int, to newIndex: Int) {
        tableView.moveRow(at: oldIndex, to: newIndex)
    }

    func tunnelRemoved(at index: Int) {
        let selectedIndices = tableView.selectedRowIndexes
        let isSingleSelectedTunnelBeingRemoved = selectedIndices.contains(index) && selectedIndices.count == 1
        tableView.removeRows(at: IndexSet(integer: index), withAnimation: .slideLeft)
        if tunnelsManager.numberOfTunnels() == 0 {
            delegate?.tunnelsListEmpty()
        } else if !isRemovingTunnelsFromWithinTheApp && isSingleSelectedTunnelBeingRemoved {
            let newSelection = min(index, tunnelsManager.numberOfTunnels() - 1)
            tableView.selectRowIndexes(IndexSet(integer: newSelection), byExtendingSelection: false)
        }
    }
}

extension TunnelsListTableViewController: NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return tunnelsManager.numberOfTunnels()
    }
}

extension TunnelsListTableViewController: NSTableViewDelegate {
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let cell: TunnelListRow = tableView.dequeueReusableCell()
        cell.tunnel = tunnelsManager.tunnel(at: row)
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        let selectedTunnelIndices = tableView.selectedRowIndexes.sorted()
        if !selectedTunnelIndices.isEmpty {
            delegate?.tunnelsSelected(tunnelIndices: tableView.selectedRowIndexes.sorted())
        }
    }
}

extension TunnelsListTableViewController {
    override func keyDown(with event: NSEvent) {
        if event.specialKey == .delete {
            handleRemoveTunnelAction()
        }
    }
}

extension TunnelsListTableViewController: NSMenuItemValidation {
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(TunnelsListTableViewController.handleRemoveTunnelAction) {
            return !tableView.selectedRowIndexes.isEmpty
        }
        return true
    }
}

extension TunnelsListTableViewController: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.items.first { $0.action == #selector(handleLaunchAtLoginAction) }?.state = LaunchAtLogin.isEnabled ? .on : .off
    }
}
