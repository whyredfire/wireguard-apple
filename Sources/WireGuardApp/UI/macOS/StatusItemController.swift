// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

@MainActor
class StatusItemController {
    var tunnelsInOperation: [TunnelContainer] = [] {
        didSet {
            updateStatusItemImage()
        }
    }

    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let statusBarImageWhenActive = NSImage(named: "StatusBarIconTemplate")!
    private let statusBarImageWhenInactive = NSImage(named: "StatusBarIconDimmedTemplate")!

    private let animationImages = [
        NSImage(named: "StatusBarIconDot1Template")!,
        NSImage(named: "StatusBarIconDot2Template")!,
        NSImage(named: "StatusBarIconDot3Template")!
    ]
    private var animationTask: Task<Void, Never>?

    init() {
        updateStatusItemImage()
    }

    func updateStatusItemImage() {
        guard !tunnelsInOperation.isEmpty else {
            stopActivatingAnimation()
            statusItem.button?.image = statusBarImageWhenInactive
            return
        }
        if tunnelsInOperation.contains(where: { $0.status != .active }) {
            startActivatingAnimation()
        } else {
            stopActivatingAnimation()
            statusItem.button?.image = statusBarImageWhenActive
        }
    }

    func startActivatingAnimation() {
        guard animationTask == nil else { return }
        animationTask = Task { [weak self] in
            var imageIndex = 0
            while !Task.isCancelled, let images = self?.animationImages {
                self?.statusItem.button?.image = images[imageIndex]
                imageIndex = (imageIndex + 1) % images.count
                try? await Task.sleep(for: .milliseconds(300))
            }
        }
    }

    func stopActivatingAnimation() {
        animationTask?.cancel()
        animationTask = nil
    }
}
