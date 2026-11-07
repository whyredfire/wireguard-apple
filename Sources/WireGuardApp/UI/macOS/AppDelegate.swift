// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa

@main
@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {

    var tunnelsManager: TunnelsManager?
    var tunnelsTracker: TunnelsTracker?
    var statusItemController: StatusItemController?

    var manageTunnelsRootVC: ManageTunnelsRootViewController?
    var manageTunnelsWindowObject: NSWindow?
    var onAppDeactivation: (() -> Void)?

    func applicationWillFinishLaunching(_ notification: Notification) {
        // To workaround a possible AppKit bug that causes the main menu to become unresponsive sometimes
        // (especially when launched through Xcode) if we call setActivationPolicy(.regular) in
        // in applicationDidFinishLaunching, we set it to .prohibited here.
        // Setting it to .regular would fix that problem too, but at this point, we don't know
        // whether the app was launched at login or not, so we're not sure whether we should
        // show the app icon in the dock or not.
        NSApp.setActivationPolicy(.prohibited)
    }

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let info = Bundle.main.infoDictionary
        wg_log(.info, message: "App version: \(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?"))")
        let isLaunchedAtLogin = isLaunchingAtLogin
        LaunchAtLogin.enableOnFirstLaunch()

        NSApp.mainMenu = MainMenu.make()
        setDockIconAndMainMenuVisibility(isVisible: !isLaunchedAtLogin)

        TunnelsManager.create { [weak self] result in
            guard let self = self else { return }

            switch result {
            case .failure(let error):
                // Without tunnels there is nothing to show, so quit once the error is read.
                ErrorPresenter.showErrorAlert(error: error, from: nil, onDismissal: { NSApp.terminate(nil) })
            case .success(let tunnelsManager):
                let statusMenu = StatusMenu(tunnelsManager: tunnelsManager)
                statusMenu.windowDelegate = self

                let statusItemController = StatusItemController()
                statusItemController.statusItem.menu = statusMenu

                let tunnelsTracker = TunnelsTracker(tunnelsManager: tunnelsManager)
                tunnelsTracker.statusMenu = statusMenu
                tunnelsTracker.statusItemController = statusItemController

                self.tunnelsManager = tunnelsManager
                self.tunnelsTracker = tunnelsTracker
                self.statusItemController = statusItemController

                if !isLaunchedAtLogin {
                    self.showManageTunnelsWindow(completion: nil)
                }
            }
        }
    }

    /// The launch event's login-item flag isn't documented for apps registered with `SMAppService`,
    /// so launches within a minute of logging in count as well.
    private var isLaunchingAtLogin: Bool {
        let event = NSAppleEventManager.shared().currentAppleEvent
        if event?.eventID == kAEOpenApplication,
           event?.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem {
            return true
        }
        return Self.consoleLoginDate.map { Date.now.timeIntervalSince($0) < 60 } ?? false
    }

    private static var consoleLoginDate: Date? {
        setutxent()
        defer { endutxent() }
        while let entry = getutxent()?.pointee {
            let line = withUnsafeBytes(of: entry.ut_line) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            let user = withUnsafeBytes(of: entry.ut_user) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            if entry.ut_type == USER_PROCESS, line == "console", user == NSUserName() {
                return Date(timeIntervalSince1970: TimeInterval(entry.ut_tv.tv_sec))
            }
        }
        return nil
    }

    @objc func confirmAndQuit() {
        let alert = NSAlert()
        alert.messageText = tr("macConfirmAndQuitAlertMessage")
        alert.informativeText = tr("macConfirmAndQuitAlertInfo")
        alert.addButton(withTitle: tr("macConfirmAndQuitAlertCloseWindow"))
        alert.addButton(withTitle: tr("macConfirmAndQuitAlertQuitWireGuard"))

        NSApp.activate()
        if let manageWindow = manageTunnelsWindowObject {
            manageWindow.orderFront(self)
            alert.beginSheetModal(for: manageWindow) { response in
                switch response {
                case .alertFirstButtonReturn:
                    manageWindow.close()
                case .alertSecondButtonReturn:
                    NSApp.terminate(nil)
                default:
                    break
                }
            }
        }
    }

    @objc func quit() {
        if let manageWindow = manageTunnelsWindowObject, manageWindow.attachedSheet != nil {
            NSApp.activate()
            manageWindow.orderFront(self)
            return
        }
        NSApp.terminate(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ application: NSApplication) -> Bool {
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(200)) { [weak self] in
            self?.setDockIconAndMainMenuVisibility(isVisible: false)
        }
        return false
    }

    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows: Bool) -> Bool {
        guard !hasVisibleWindows else { return true }
        showManageTunnelsWindow(completion: nil)
        return false
    }

    private func setDockIconAndMainMenuVisibility(isVisible: Bool, completion: (() -> Void)? = nil) {
        let currentActivationPolicy = NSApp.activationPolicy()
        let newActivationPolicy: NSApplication.ActivationPolicy = isVisible ? .regular : .accessory
        guard currentActivationPolicy != newActivationPolicy else {
            if newActivationPolicy == .regular {
                NSApp.activate()
            }
            completion?()
            return
        }
        if newActivationPolicy == .regular && NSApp.isActive {
            // To workaround a possible AppKit bug that causes the main menu to become unresponsive,
            // we should deactivate the app first and then set the activation policy.
            // NSApp.deactivate() doesn't always deactivate the app, so we instead use
            // setActivationPolicy(.prohibited).
            onAppDeactivation = {
                NSApp.setActivationPolicy(.regular)
                NSApp.activate()
                completion?()
            }
            NSApp.setActivationPolicy(.prohibited)
        } else {
            NSApp.setActivationPolicy(newActivationPolicy)
            if newActivationPolicy == .regular {
                NSApp.activate()
            }
            completion?()
        }
    }

    func applicationDidResignActive(_ notification: Notification) {
        onAppDeactivation?()
        onAppDeactivation = nil
    }
}

extension AppDelegate {
    @objc func aboutClicked() {
        var appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
        if let appBuild = Bundle.main.infoDictionary?["CFBundleVersion"] as? String {
            appVersion += " (\(appBuild))"
        }
        let goBackendVersion = Bundle.main.infoDictionary?["WireGuardGoVersion"] as? String ?? "Unknown"
        let appVersionString = [
            tr(format: "macAppVersion (%@)", appVersion),
            tr(format: "macGoBackendVersion (%@)", goBackendVersion)
        ].joined(separator: "\n")
        NSApp.activate()
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationVersion: appVersionString,
            .version: "",
            .credits: ""
        ])
    }
}

extension AppDelegate: StatusMenuWindowDelegate {
    func showManageTunnelsWindow(completion: ((NSWindow?) -> Void)?) {
        guard let tunnelsManager = tunnelsManager else {
            completion?(nil)
            return
        }
        if manageTunnelsWindowObject == nil {
            manageTunnelsRootVC = ManageTunnelsRootViewController(tunnelsManager: tunnelsManager)
            let window = NSWindow(contentViewController: manageTunnelsRootVC!)
            window.title = tr("macWindowTitleManageTunnels")
            window.setContentSize(NSSize(width: 800, height: 480))
            window.setFrameAutosaveName(NSWindow.FrameAutosaveName("ManageTunnelsWindow")) // Auto-save window position and size
            manageTunnelsWindowObject = window
            tunnelsTracker?.manageTunnelsRootVC = manageTunnelsRootVC
        }
        setDockIconAndMainMenuVisibility(isVisible: true) { [weak manageTunnelsWindowObject] in
            manageTunnelsWindowObject?.makeKeyAndOrderFront(self)
            completion?(manageTunnelsWindowObject)
        }
    }
}
