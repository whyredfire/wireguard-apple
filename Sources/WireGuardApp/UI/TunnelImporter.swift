// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

@MainActor
enum TunnelImporter {
    static func importFromFile(urls: [URL], into tunnelsManager: TunnelsManager, sourceVC: AnyObject?, errorPresenterType: ErrorPresenterProtocol.Type, completionHandler: (() -> Void)? = nil) {
        guard !urls.isEmpty else {
            completionHandler?()
            return
        }
        Task {
            var configs = [TunnelConfiguration?]()
            var lastFileImportErrorText: (title: String, message: String)?
            for url in urls {
                if url.pathExtension.lowercased() == "zip" {
                    do throws(ZipArchiveError) {
                        configs += try await ZipImporter.importConfigFiles(from: url)
                    } catch {
                        lastFileImportErrorText = error.alertText
                    }
                } else { /* if it is not a zip, we assume it is a conf */
                    let fileName = url.lastPathComponent
                    let fileBaseName = url.deletingPathExtension().lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines)
                    do {
                        let fileContents = try await readFile(url)
                        configs.append(try TunnelConfiguration(fromWgQuickConfig: fileContents, called: fileBaseName))
                    } catch let error as WireGuardAppError {
                        lastFileImportErrorText = error.alertText
                        configs.append(nil)
                    } catch let error as CocoaError where error.isFileError {
                        lastFileImportErrorText = (title: tr("alertCantOpenInputConfFileTitle"), message: error.localizedDescription)
                        configs.append(nil)
                    } catch {
                        lastFileImportErrorText = (title: tr("alertCantOpenInputConfFileTitle"), message: tr(format: "alertCantOpenInputConfFileMessage (%@)", fileName))
                        configs.append(nil)
                    }
                }
            }
            tunnelsManager.addMultiple(tunnelConfigurations: configs.compactMap { $0 }) { numberSuccessful, lastAddError in
                if !configs.isEmpty && numberSuccessful == configs.count {
                    completionHandler?()
                    return
                }
                let alertText: (title: String, message: String)?
                if urls.count == 1 {
                    if urls.first!.pathExtension.lowercased() == "zip" && !configs.isEmpty {
                        alertText = (title: tr(format: "alertImportedFromZipTitle (%d)", numberSuccessful),
                                     message: tr(format: "alertImportedFromZipMessage (%1$d of %2$d)", numberSuccessful, configs.count))
                    } else {
                        alertText = lastFileImportErrorText ?? lastAddError?.alertText
                    }
                } else {
                    alertText = (title: tr(format: "alertImportedFromMultipleFilesTitle (%d)", numberSuccessful),
                                 message: tr(format: "alertImportedFromMultipleFilesMessage (%1$d of %2$d)", numberSuccessful, configs.count))
                }
                if let alertText = alertText {
                    errorPresenterType.showErrorAlert(title: alertText.title, message: alertText.message, from: sourceVC, onPresented: completionHandler)
                } else {
                    completionHandler?()
                }
            }
        }
    }

    @concurrent
    private static func readFile(_ url: URL) async throws -> String {
        try String(contentsOf: url, encoding: .utf8)
    }
}
