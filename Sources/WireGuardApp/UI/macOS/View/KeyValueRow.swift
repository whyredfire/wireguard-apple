// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

class EditableKeyValueRow: NSView {
    let keyLabel: NSTextField = {
        let keyLabel = NSTextField()
        keyLabel.isEditable = false
        keyLabel.isSelectable = false
        keyLabel.isBordered = false
        keyLabel.alignment = .left
        keyLabel.maximumNumberOfLines = 1
        keyLabel.lineBreakMode = .byTruncatingTail
        keyLabel.backgroundColor = .clear
        return keyLabel
    }()

    let valueLabel: NSTextField = {
        let valueLabel = NSTextField()
        valueLabel.isSelectable = true
        // Long values, like many allowed IPs, continue on the next lines.
        valueLabel.maximumNumberOfLines = 0
        valueLabel.lineBreakMode = .byWordWrapping
        return valueLabel
    }()

    let valueImageView: NSImageView?

    var key: String {
        get { return keyLabel.stringValue }
        set(value) { keyLabel.stringValue = value }
    }
    var value: String {
        get { return valueLabel.stringValue }
        set(value) { valueLabel.stringValue = value }
    }
    var isKeyInBold: Bool {
        get { return keyLabel.font == NSFont.boldSystemFont(ofSize: 0) }
        set(value) {
            if value {
                keyLabel.font = NSFont.boldSystemFont(ofSize: 0)
            } else {
                keyLabel.font = NSFont.systemFont(ofSize: 0)
            }
        }
    }
    var valueImage: NSImage? {
        get { return valueImageView?.image }
        set(value) { valueImageView?.image = value }
    }

    var statusObservationToken: ObservationToken?

    /// `NSTableView.dequeueReusableCell()` creates rows with `T()`, which reaches the subclasses' `init()` through this one.
    convenience init() {
        self.init(hasValueImage: false)
    }

    fileprivate init(hasValueImage: Bool) {
        valueImageView = hasValueImage ? NSImageView() : nil
        super.init(frame: CGRect.zero)

        addSubview(keyLabel)
        addSubview(valueLabel)
        keyLabel.translatesAutoresizingMaskIntoConstraints = false
        valueLabel.translatesAutoresizingMaskIntoConstraints = false

        // The row is as tall as its value, with the spacing of a medium table row.
        let verticalPadding: CGFloat = 4
        NSLayoutConstraint.activate([
            valueLabel.topAnchor.constraint(equalTo: self.topAnchor, constant: verticalPadding),
            self.bottomAnchor.constraint(equalTo: valueLabel.bottomAnchor, constant: verticalPadding),
            keyLabel.firstBaselineAnchor.constraint(equalTo: valueLabel.firstBaselineAnchor),
            self.leadingAnchor.constraint(equalTo: keyLabel.leadingAnchor),
            valueLabel.trailingAnchor.constraint(equalTo: self.trailingAnchor)
        ])

        let spacing: CGFloat = 5
        if let valueImageView = valueImageView {
            addSubview(valueImageView)
            valueImageView.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                valueImageView.centerYAnchor.constraint(equalTo: valueLabel.centerYAnchor),
                valueImageView.leadingAnchor.constraint(equalTo: keyLabel.trailingAnchor, constant: spacing),
                valueLabel.leadingAnchor.constraint(equalTo: valueImageView.trailingAnchor)
            ])
        } else {
            NSLayoutConstraint.activate([
                valueLabel.leadingAnchor.constraint(equalTo: keyLabel.trailingAnchor, constant: spacing)
            ])
        }

        keyLabel.setContentCompressionResistancePriority(.defaultHigh + 2, for: .horizontal)
        keyLabel.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        valueLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        // Wraps within the row instead of widening it.
        valueLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let widthConstraint = keyLabel.widthAnchor.constraint(equalToConstant: Self.keyWidth)
        widthConstraint.priority = .defaultHigh + 1
        widthConstraint.isActive = true
    }

    required init?(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func layout() {
        super.layout()
        // A wrapping label only knows its height once it knows its width.
        if valueLabel.preferredMaxLayoutWidth != valueLabel.frame.width {
            valueLabel.preferredMaxLayoutWidth = valueLabel.frame.width
            super.layout()
        }
    }

    override func prepareForReuse() {
        key = ""
        value = ""
        isKeyInBold = false
        statusObservationToken = nil
    }
}

class KeyValueRow: EditableKeyValueRow {
    init() {
        super.init(hasValueImage: false)
        valueLabel.isEditable = false
        valueLabel.isBordered = false
        valueLabel.backgroundColor = .clear
    }

    required init?(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

class KeyValueImageRow: EditableKeyValueRow {
    init() {
        super.init(hasValueImage: true)
        valueLabel.isEditable = false
        valueLabel.isBordered = false
        valueLabel.backgroundColor = .clear
    }

    required init?(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

extension EditableKeyValueRow {
    /// Fits every key a tunnel can show, so the values line up in one column whichever tunnel is shown.
    static let keyWidth: CGFloat = {
        let interfaceKeys = TunnelViewModel.InterfaceField.allCases
            .filter { !TunnelViewModel.interfaceFieldsWithControl.contains($0) }.map(\.localizedUIString)
        let peerKeys = TunnelViewModel.PeerField.allCases
            .filter { !TunnelViewModel.peerFieldsWithControl.contains($0) }.map(\.localizedUIString)
        let sectionTitles = [tr("tunnelSectionTitleInterface"), tr("tunnelSectionTitlePeer")]
        let keys = (interfaceKeys + peerKeys).map { ($0, NSFont.systemFont(ofSize: 0)) }
            + sectionTitles.map { ($0, NSFont.boldSystemFont(ofSize: 0)) }
        let textWidth = keys.map { key, font in tr(format: "macFieldKey (%@)", key).size(withAttributes: [.font: font]).width }.max()!
        // A label adds a few points around its text.
        return ceil(textWidth) + 4
    }()
}
