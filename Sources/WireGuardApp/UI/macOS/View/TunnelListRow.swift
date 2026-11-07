// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

class TunnelListRow: NSView {
    var tunnel: TunnelContainer? {
        didSet {
            guard let tunnel else {
                nameObservationToken = nil
                statusObservationToken = nil
                return
            }
            nameLabel.stringValue = tunnel.name
            statusImageView.image = TunnelListRow.image(for: tunnel)
            nameObservationToken = ObservationToken({ tunnel.name }) { [weak self] name in
                self?.nameLabel.stringValue = name
            }
            statusObservationToken = ObservationToken({ tunnel.status }) { [weak self] _ in
                self?.statusImageView.image = TunnelListRow.image(for: tunnel)
            }
        }
    }

    let nameLabel: NSTextField = {
        let nameLabel = NSTextField()
        nameLabel.isEditable = false
        nameLabel.isSelectable = false
        nameLabel.isBordered = false
        nameLabel.maximumNumberOfLines = 1
        nameLabel.lineBreakMode = .byTruncatingTail
        return nameLabel
    }()

    let statusImageView = NSImageView()

    private var statusObservationToken: ObservationToken?
    private var nameObservationToken: ObservationToken?

    init() {
        super.init(frame: CGRect.zero)

        addSubview(statusImageView)
        addSubview(nameLabel)
        statusImageView.translatesAutoresizingMaskIntoConstraints = false
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        nameLabel.backgroundColor = .clear
        NSLayoutConstraint.activate([
            self.leadingAnchor.constraint(equalTo: statusImageView.leadingAnchor),
            statusImageView.trailingAnchor.constraint(equalTo: nameLabel.leadingAnchor),
            statusImageView.widthAnchor.constraint(equalToConstant: 20),
            nameLabel.trailingAnchor.constraint(equalTo: self.trailingAnchor),
            statusImageView.centerYAnchor.constraint(equalTo: self.centerYAnchor),
            nameLabel.centerYAnchor.constraint(equalTo: self.centerYAnchor)
        ])
    }

    required init?(coder decoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    static func image(for tunnel: TunnelContainer?) -> NSImage? {
        guard let tunnel = tunnel else { return nil }
        switch tunnel.status {
        case .active, .restarting:
            return NSImage(named: NSImage.statusAvailableName)
        case .activating, .deactivating:
            return NSImage(named: NSImage.statusPartiallyAvailableName)
        case .inactive:
            return NSImage(named: NSImage.statusNoneName)
        }
    }

    override func prepareForReuse() {
        nameLabel.stringValue = ""
        statusImageView.image = nil
    }
}
