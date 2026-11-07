// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

@MainActor
protocol TunnelEditViewControllerDelegate: AnyObject {
    func tunnelSaved(tunnel: TunnelContainer)
    func tunnelEditingCancelled()
}

class TunnelEditViewController: NSViewController {

    let nameField = NSTextField()

    let publicKeyLabel: NSTextField = {
        let label = NSTextField(labelWithString: "")
        label.isSelectable = true
        label.lineBreakMode = .byTruncatingMiddle
        return label
    }()

    let textView: ConfTextView = {
        let textView = ConfTextView()
        let minWidth: CGFloat = 120
        let minHeight: CGFloat = 0
        textView.minSize = NSSize(width: 0, height: minHeight)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.autoresizingMask = [.width] // Width should be based on superview width
        textView.isHorizontallyResizable = false // Width shouldn't be based on content
        textView.isVerticallyResizable = true // Height should be based on content
        if let textContainer = textView.textContainer {
            textContainer.size = NSSize(width: minWidth, height: CGFloat.greatestFiniteMagnitude)
            textContainer.widthTracksTextView = true
        }
        NSLayoutConstraint.activate([
            textView.widthAnchor.constraint(greaterThanOrEqualToConstant: minWidth),
            textView.heightAnchor.constraint(greaterThanOrEqualToConstant: minHeight)
        ])
        return textView
    }()

    let scrollView: NSScrollView = {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        return scrollView
    }()

    let excludePrivateIPsCheckbox: NSButton = {
        let checkbox = NSButton()
        checkbox.title = tr("tunnelPeerExcludePrivateIPs")
        checkbox.setButtonType(.switch)
        checkbox.state = .off
        return checkbox
    }()

    let splitDNSCheckbox: NSButton = {
        let checkbox = NSButton()
        checkbox.title = tr("tunnelEditSplitDNS")
        checkbox.toolTip = tr("tunnelEditSplitDNSTooltip")
        checkbox.setButtonType(.switch)
        checkbox.state = .off
        return checkbox
    }()

    let discardButton: NSButton = {
        let button = NSButton()
        button.title = tr("macEditDiscard")
        button.setButtonType(.momentaryPushIn)
        button.bezelStyle = .rounded
        button.keyEquivalent = "\u{1b}"
        return button
    }()

    let saveButton: NSButton = {
        let button = NSButton()
        button.title = tr("macEditSave")
        button.setButtonType(.momentaryPushIn)
        button.bezelStyle = .rounded
        button.keyEquivalent = "s"
        button.keyEquivalentModifierMask = [.command]
        button.bezelColor = .controlAccentColor
        return button
    }()

    let tunnelsManager: TunnelsManager
    let tunnel: TunnelContainer?

    weak var delegate: TunnelEditViewControllerDelegate?

    var privateKeyObservationToken: ObservationToken?
    var hasErrorObservationToken: ObservationToken?
    var singlePeerAllowedIPsObservationToken: ObservationToken?

    var dnsServersAddedToAllowedIPs: String?

    init(tunnelsManager: TunnelsManager, tunnel: TunnelContainer?) {
        self.tunnelsManager = tunnelsManager
        self.tunnel = tunnel
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func populateFields() {
        if let tunnel = tunnel {
            // Editing an existing tunnel
            let tunnelConfiguration = tunnel.tunnelConfiguration!
            nameField.stringValue = tunnel.name
            splitDNSCheckbox.state = tunnel.isSplitDNSEnabled ? .on : .off
            textView.string = tunnelConfiguration.asWgQuickConfig()
            publicKeyLabel.stringValue = tunnelConfiguration.interface.privateKey.publicKey.base64Key
            textView.privateKeyString = tunnelConfiguration.interface.privateKey.base64Key
            let singlePeer = tunnelConfiguration.peers.count == 1 ? tunnelConfiguration.peers.first : nil
            updateExcludePrivateIPsVisibility(singlePeerAllowedIPs: singlePeer?.allowedIPs.map { $0.stringRepresentation })
            dnsServersAddedToAllowedIPs = excludePrivateIPsCheckbox.state == .on ? tunnelConfiguration.interface.dns.map { $0.stringRepresentation }.joined(separator: ", ") : nil
        } else {
            // Creating a new tunnel
            let privateKey = PrivateKey()
            let bootstrappingText = "[Interface]\nPrivateKey = \(privateKey.base64Key)\n"
            publicKeyLabel.stringValue = privateKey.publicKey.base64Key
            textView.string = bootstrappingText
            updateExcludePrivateIPsVisibility(singlePeerAllowedIPs: nil)
            dnsServersAddedToAllowedIPs = nil
        }
        let textView = textView
        privateKeyObservationToken = ObservationToken({ textView.privateKeyString }) { [weak publicKeyLabel] privateKeyString in
            publicKeyLabel?.stringValue = privateKeyString.flatMap { PrivateKey(base64Key: $0) }?.publicKey.base64Key ?? ""
        }
        hasErrorObservationToken = ObservationToken({ textView.hasError }) { [weak saveButton] hasError in
            saveButton?.isEnabled = !hasError
        }
        singlePeerAllowedIPsObservationToken = ObservationToken({ textView.singlePeerAllowedIPs }) { [weak self] allowedIPs in
            self?.updateExcludePrivateIPsVisibility(singlePeerAllowedIPs: allowedIPs)
        }
    }

    override func loadView() {
        populateFields()

        textView.drawsBackground = false
        textView.textContainerInset = NSSize(width: 6, height: 8)
        scrollView.documentView = textView

        saveButton.target = self
        saveButton.action = #selector(handleSaveAction)

        discardButton.target = self
        discardButton.action = #selector(handleDiscardAction)

        excludePrivateIPsCheckbox.target = self
        excludePrivateIPsCheckbox.action = #selector(excludePrivateIPsCheckboxToggled(sender:))


        let margin: CGFloat = 20
        let internalSpacing: CGFloat = 10

        let nameTitle = NSTextField(labelWithString: tr(format: "macFieldKey (%@)", TunnelViewModel.InterfaceField.name.localizedUIString))
        let publicKeyTitle = NSTextField(labelWithString: tr(format: "macFieldKey (%@)", TunnelViewModel.InterfaceField.publicKey.localizedUIString))
        let form = NSGridView(views: [[nameTitle, nameField], [publicKeyTitle, publicKeyLabel]])
        form.rowSpacing = internalSpacing
        form.rowAlignment = .firstBaseline
        for title in [nameTitle, publicKeyTitle] {
            title.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        }

        // Matches the box behind the tunnel details.
        let editorBox = NSBox()
        editorBox.titlePosition = .noTitle
        editorBox.fillColor = .unemphasizedSelectedContentBackgroundColor
        let editor = NSView()
        for subview in [editorBox, scrollView] {
            editor.addSubview(subview)
            subview.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                subview.topAnchor.constraint(equalTo: editor.topAnchor),
                subview.bottomAnchor.constraint(equalTo: editor.bottomAnchor),
                subview.leadingAnchor.constraint(equalTo: editor.leadingAnchor),
                subview.trailingAnchor.constraint(equalTo: editor.trailingAnchor)
            ])
        }

        let editorStackView = NSStackView(views: [form, editor])
        editorStackView.orientation = .vertical
        editorStackView.setHuggingPriority(.defaultHigh, for: .horizontal)
        editorStackView.spacing = internalSpacing
        for view in [form, editor] {
            view.widthAnchor.constraint(equalTo: editorStackView.widthAnchor).isActive = true
        }

        let buttonRowStackView = NSStackView()
        buttonRowStackView.setViews([discardButton, saveButton], in: .trailing)
        buttonRowStackView.addView(splitDNSCheckbox, in: .leading)
        buttonRowStackView.addView(excludePrivateIPsCheckbox, in: .leading)
        buttonRowStackView.orientation = .horizontal
        buttonRowStackView.spacing = internalSpacing

        let containerView = NSStackView(views: [editorStackView, buttonRowStackView])
        containerView.orientation = .vertical
        containerView.edgeInsets = NSEdgeInsets(top: margin, left: margin, bottom: margin, right: margin)
        containerView.setHuggingPriority(.defaultHigh, for: .horizontal)
        containerView.spacing = internalSpacing

        NSLayoutConstraint.activate([
            containerView.widthAnchor.constraint(greaterThanOrEqualToConstant: 180),
            containerView.heightAnchor.constraint(greaterThanOrEqualToConstant: 240)
        ])
        containerView.frame = NSRect(x: 0, y: 0, width: 600, height: 480)

        self.view = containerView
    }

    func setUserInteractionEnabled(_ enabled: Bool) {
        view.window?.ignoresMouseEvents = !enabled
        nameField.isEditable = enabled
        textView.isEditable = enabled
    }

    @objc func handleSaveAction() {
        let name = nameField.stringValue
        guard !name.isEmpty else {
            ErrorPresenter.showErrorAlert(title: tr("macAlertNameIsEmpty"), message: "", from: self)
            return
        }


        let isTunnelModifiedWithoutChangingName = (tunnel != nil && tunnel!.name == name)
        guard isTunnelModifiedWithoutChangingName || tunnelsManager.tunnel(named: name) == nil else {
            ErrorPresenter.showErrorAlert(title: tr(format: "macAlertDuplicateName (%@)", name), message: "", from: self)
            return
        }

        var tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: textView.string, called: nameField.stringValue)
        } catch let error as WireGuardAppError {
            ErrorPresenter.showErrorAlert(error: error, from: self)
            return
        } catch {
            fatalError()
        }

        if excludePrivateIPsCheckbox.state == .on, tunnelConfiguration.peers.count == 1, let dnsServersAddedToAllowedIPs = dnsServersAddedToAllowedIPs {
            // Update the DNS servers in the AllowedIPs
            let tunnelViewModel = TunnelViewModel(tunnelConfiguration: tunnelConfiguration)
            let originalAllowedIPs = tunnelViewModel.peersData[0][.allowedIPs].splitToArray(trimmingCharacters: .whitespacesAndNewlines)
            let dnsServersInAllowedIPs =  TunnelViewModel.PeerData.normalizedIPAddressRangeStrings(dnsServersAddedToAllowedIPs.splitToArray(trimmingCharacters: .whitespacesAndNewlines))
            let dnsServersCurrent =  TunnelViewModel.PeerData.normalizedIPAddressRangeStrings(tunnelViewModel.interfaceData[.dns].splitToArray(trimmingCharacters: .whitespacesAndNewlines))
            let modifiedAllowedIPs = originalAllowedIPs.filter { !dnsServersInAllowedIPs.contains($0) } + dnsServersCurrent
            tunnelViewModel.peersData[0][.allowedIPs] = modifiedAllowedIPs.joined(separator: ", ")
            let saveResult = tunnelViewModel.save()
            if case .saved(let modifiedTunnelConfiguration) = saveResult {
                tunnelConfiguration = modifiedTunnelConfiguration
            }
        }

        let isSplitDNSEnabled = splitDNSCheckbox.state == .on
        if isSplitDNSEnabled && (tunnelConfiguration.interface.dns.isEmpty || tunnelConfiguration.interface.dnsSearch.filter({ !$0.isEmpty }).isEmpty) {
            ErrorPresenter.showErrorAlert(title: tr("alertSplitDNSRequiresSearchDomainsTitle"), message: tr("alertSplitDNSRequiresSearchDomainsMessage"), from: self)
            return
        }

        setUserInteractionEnabled(false)

        if let tunnel = tunnel {
            // We're modifying an existing tunnel
            tunnelsManager.modify(tunnel: tunnel, tunnelConfiguration: tunnelConfiguration, isSplitDNSEnabled: isSplitDNSEnabled) { [weak self] error in
                guard let self = self else { return }
                self.setUserInteractionEnabled(true)
                if let error = error {
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                    return
                }
                self.delegate?.tunnelSaved(tunnel: tunnel)
                self.presentingViewController?.dismiss(self)
            }
        } else {
            // We're creating a new tunnel
            self.tunnelsManager.add(tunnelConfiguration: tunnelConfiguration, isSplitDNSEnabled: isSplitDNSEnabled) { [weak self] result in
                guard let self = self else { return }
                self.setUserInteractionEnabled(true)
                switch result {
                case .failure(let error):
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                case .success(let tunnel):
                    self.delegate?.tunnelSaved(tunnel: tunnel)
                    self.presentingViewController?.dismiss(self)
                }
            }
        }
    }

    @objc func handleDiscardAction() {
        delegate?.tunnelEditingCancelled()
        presentingViewController?.dismiss(self)
    }

    func updateExcludePrivateIPsVisibility(singlePeerAllowedIPs: [String]?) {
        let shouldAllowExcludePrivateIPsControl: Bool
        let excludePrivateIPsValue: Bool
        if let singlePeerAllowedIPs = singlePeerAllowedIPs {
            (shouldAllowExcludePrivateIPsControl, excludePrivateIPsValue) = TunnelViewModel.PeerData.excludePrivateIPsFieldStates(isSinglePeer: true, allowedIPs: Set<String>(singlePeerAllowedIPs))
        } else {
            (shouldAllowExcludePrivateIPsControl, excludePrivateIPsValue) = TunnelViewModel.PeerData.excludePrivateIPsFieldStates(isSinglePeer: false, allowedIPs: Set<String>())
        }
        excludePrivateIPsCheckbox.isHidden = !shouldAllowExcludePrivateIPsControl
        excludePrivateIPsCheckbox.state = excludePrivateIPsValue ? .on : .off
    }

    @objc func excludePrivateIPsCheckboxToggled(sender: AnyObject?) {
        guard let excludePrivateIPsCheckbox = sender as? NSButton else { return }
        guard let tunnelConfiguration = try? TunnelConfiguration(fromWgQuickConfig: textView.string, called: nameField.stringValue) else { return }
        let isOn = excludePrivateIPsCheckbox.state == .on
        let tunnelViewModel = TunnelViewModel(tunnelConfiguration: tunnelConfiguration)
        tunnelViewModel.peersData.first?.excludePrivateIPsValueChanged(isOn: isOn, dnsServers: tunnelViewModel.interfaceData[.dns], oldDNSServers: dnsServersAddedToAllowedIPs)
        if let modifiedConfig = tunnelViewModel.asWgQuickConfig() {
            textView.setConfText(modifiedConfig)
            dnsServersAddedToAllowedIPs = isOn ? tunnelViewModel.interfaceData[.dns] : nil
        }
    }
}

extension TunnelEditViewController {
    override func cancelOperation(_ sender: Any?) {
        handleDiscardAction()
    }
}
