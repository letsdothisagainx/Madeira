// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

// Only the genuine bootstrapper is replaced. Valve's updater owns the rest
// of the migration, including its signed manifests and mandatory checks.
enum SteamClientUpdateFiles {
    static let package = "steam_win64.zip.9ddc7f402ba9bec08b7dbee2cf6ee37d21e1b4e0"
    static let packageBytes = 2_692_595
    static let packageSHA256 = "9a5aba7f8b5341344717f4a07027ac128e6913bb918454672e843fb5f7e61468"
    static let imageSHA256 = "f8a4ca44008c516eebecafaa4bc26772b2a6eb0fef8034bce56a3311e21ab705"
    static let backupName = "steam.exe.madeira-win32-backup"

    enum Failure: LocalizedError {
        case active, missing, invalid, changed, unsupported
        var errorDescription: String? {
            switch self {
            case .active: return "Close the Wine session before updating Steam."
            case .missing: return "The existing Windows Steam launcher could not be found."
            case .invalid: return "Valve's Steam launcher could not be verified."
            case .changed: return "Steam's launcher or backup changed during the update. Try again after closing Steam."
            case .unsupported: return "This Madeira build cannot load the 64-bit Steam launcher."
            }
        }
    }

    static func machine(_ data: Data) -> UInt16? {
        guard data.count >= 64, data[0] == 0x4d, data[1] == 0x5a else { return nil }
        func u16(_ p: Int) -> UInt16 { UInt16(data[p]) | UInt16(data[p + 1]) << 8 }
        let pe = Int(UInt32(u16(0x3c)) | UInt32(u16(0x3e)) << 16)
        guard pe <= data.count - 26, data[pe..<pe + 4].elementsEqual([0x50, 0x45, 0, 0]),
              u16(pe + 20) >= 2, Int(u16(pe + 20)) <= data.count - pe - 24 else { return nil }
        let machine = u16(pe + 4), magic = u16(pe + 24)
        guard (machine == 0x014c && magic == 0x10b) ||
              (machine == 0x8664 && magic == 0x20b) else { return nil }
        return machine
    }

    static func launcher(drive: URL) throws -> URL {
        let fm = FileManager.default
        for root in ["Program Files (x86)/Steam", "Program Files/Steam"] {
            let file = try SteamRuntimeFiles.destination(root + "/steam.exe", under: drive)
            if fm.fileExists(atPath: file.path) { return file }
        }
        throw Failure.missing
    }

    // The caller verifies both pinned hashes before reaching this function.
    // No suspension between the idle/original checks and the atomic replace.
    // An existing backup is never overwritten, even after an interrupted run.
    static func commit(_ image: Data, replacing original: Data, at launcher: URL,
                       idle: () -> Bool) throws {
        let fm = FileManager.default
        guard machine(original) == 0x014c, machine(image) == 0x8664 else { throw Failure.invalid }
        guard idle() else { throw Failure.active }
        guard launcher.standardizedFileURL.path == launcher.resolvingSymlinksInPath().standardizedFileURL.path,
              try Data(contentsOf: launcher) == original else { throw Failure.changed }
        let backup = launcher.deletingLastPathComponent().appendingPathComponent(backupName)
        guard backup.standardizedFileURL.path == backup.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw Failure.changed
        }
        if fm.fileExists(atPath: backup.path) {
            guard try Data(contentsOf: backup) == original else { throw Failure.changed }
        } else {
            try fm.copyItem(at: launcher, to: backup)
        }
        guard idle(), try Data(contentsOf: launcher) == original else { throw Failure.changed }
        try image.write(to: launcher, options: .atomic)
    }
}

#if canImport(SwiftUI) && canImport(CryptoKit)
import SwiftUI
import CryptoKit

// This UI operation and Wine launch preparation run on the main actor. The
// download may suspend; the final idle check and file transaction do not.
@MainActor final class SteamClientUpdateModel: ObservableObject {
    static let shared = SteamClientUpdateModel()
    @Published private(set) var busy = false
    @Published private(set) var message = ""
    @Published private(set) var error: String?

    private func idle() -> Bool {
        !SteamNativeBrowserLaunch.shared.busy && !SteamBrowserRuntime.busy &&
        wine_process_is_running() == 0 && wineserver_is_running() == 0 &&
            LibraryModel.shared.current == nil && !SteamOwnedLibrary.shared.wineSessionActive
    }
    private static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    func update() {
        guard !busy else { return }
        guard idle() else { error = SteamClientUpdateFiles.Failure.active.localizedDescription; return }
        busy = true; error = nil; message = "Downloading Valve's 64-bit Steam launcher…"
        Task { @MainActor in
            defer { busy = false }
            do {
                let launcher = try SteamClientUpdateFiles.launcher(drive: MadeiraDock.drive)
                let original = try Data(contentsOf: launcher)
                if SteamClientUpdateFiles.machine(original) == 0x8664 {
                    message = "Steam already uses a 64-bit launcher. Check for updates inside Steam."
                    return
                }
                guard SteamClientUpdateFiles.machine(original) == 0x014c,
                      let bundle = Bundle.main.resourceURL else { throw SteamClientUpdateFiles.Failure.unsupported }
                for name in ["ntdll.dll", "xtajit64.dll"] {
                    let data = try Data(contentsOf: bundle.appendingPathComponent("arm64ec-windows/" + name))
                    guard SteamClientUpdateFiles.machine(data) == 0x8664 else {
                        throw SteamClientUpdateFiles.Failure.unsupported
                    }
                }
                let config = URLSessionConfiguration.ephemeral
                config.httpCookieStorage = nil; config.urlCredentialStorage = nil
                config.timeoutIntervalForRequest = 60; config.timeoutIntervalForResource = 180
                let session = URLSession(configuration: config, delegate: SteamClientUpdateRedirects(), delegateQueue: nil)
                defer { session.invalidateAndCancel() }
                let url = URL(string: SteamRuntimeFiles.origin + SteamClientUpdateFiles.package)!
                let (temporary, response) = try await session.download(from: url)
                defer { try? FileManager.default.removeItem(at: temporary) }
                guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == url,
                      (try temporary.resourceValues(forKeys: [.fileSizeKey])).fileSize == SteamClientUpdateFiles.packageBytes else {
                    throw SteamClientUpdateFiles.Failure.invalid
                }
                let archive = try Data(contentsOf: temporary, options: .mappedIfSafe)
                guard Self.hash(archive) == SteamClientUpdateFiles.packageSHA256 else { throw SteamClientUpdateFiles.Failure.invalid }
                var image: Data?
                try SteamRuntimeFiles.unpack(archive) { name, data in
                    guard name == "steam.exe", image == nil else { throw SteamClientUpdateFiles.Failure.invalid }
                    image = data
                }
                guard let image, Self.hash(image) == SteamClientUpdateFiles.imageSHA256 else {
                    throw SteamClientUpdateFiles.Failure.invalid
                }
                try Task.checkCancellation()
                try SteamClientUpdateFiles.commit(image, replacing: original, at: launcher, idle: idle)
                message = "The 64-bit Steam launcher is ready. Start Windows Steam to let Valve's updater finish the client update."
                LogStore.shared.log("[steam-client-update-v1] bootstrap=win64 machine=8664 verified=1 original-backup=retained action=official-updater-next-launch")
            } catch {
                self.error = error.localizedDescription
                message = ""
                LogStore.shared.log("[steam-client-update-v1] prepared=0 error=\(error is SteamClientUpdateFiles.Failure ? "validation-or-session" : "download-or-file")")
            }
        }
    }
}

private final class SteamClientUpdateRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // the pinned package is fetched only from its exact HTTPS URL
    }
}

struct SteamClientUpdateView: View {
    @ObservedObject private var update = SteamClientUpdateModel.shared
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("An outdated Steam client can reject games with ‘Steam client outdated’. Download Valve's genuine 64-bit launcher, then start Windows Steam to complete its official update.")
                    Text("Your Steam folder, account session and installed games are kept. The previous launcher is backed up.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if !checkAppEntitlement("com.apple.developer.kernel.extended-virtual-addressing") {
                    Section("Address-space limits") {
                        Text("This copy lacks Extended Virtual Addressing, but increased-memory or JIT permission can already select the same iOS address-space limit. A missing entitlement alone does not diagnose a Steam startup failure.")
                        Text("The 64-bit browser also needs large aligned reservations. Enabling this entitlement does not guarantee that it can initialize.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Section {
                    if update.busy { HStack { ProgressView(); Text(update.message) } }
                    else { Button("Update Windows Steam") { update.update() } }
                    if !update.busy && !update.message.isEmpty { Text(update.message) }
                    if let error = update.error { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Windows Steam update")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
#endif
