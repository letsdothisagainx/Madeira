// SPDX-License-Identifier: GPL-3.0-or-later
// Candidate only. Named source bridge + verified browser launch preparation.
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Combine)
import Combine
#endif

enum SteamNativeBrowserLaunchFiles {
    static let bridgeName = "madeira-htmlipc-bridge.dll"
    static let manifestName = "madeira-htmlipc-bridge.manifest.json"
    static let stampName = "madeira-htmlipc-bridge.madeira-owned-v1.json"
    static let abiSHA256 = "431e697a27ea58bd662359d3c8bc41a37b4afca2692d6a3b77862743b181fd76"
    static let nativePrefix = "C:\\windows\\madeira-compat\\SteamBrowserRuntime\\"
    static let nativeCache = nativePrefix + SteamBrowserRuntimeFiles.official.id + "\\bin\\cef\\cef.win7"
    static let lockedNames = ["MADEIRA_HTMLIPC_HELPER", "MADEIRA_HTMLIPC_CACHE_DIR",
                              "MADEIRA_NATIVE_STEAM_LAUNCH", "MADEIRA_ENV_LOCKED"]
    struct Fingerprint: Codable, Equatable, Sendable {
        let bytes: Int, sha256: String
    }
    struct ReadinessABI: Codable, Equatable, Sendable {
        let version: Int, size: Int, sha256: String
    }
    struct BridgeManifest: Codable, Equatable, Sendable {
        let format: Int, mode: String, filename: String, bytes: Int, sha256: String, coreSHA256: String
        let readinessABI: ReadinessABI
        var fingerprint: Fingerprint { Fingerprint(bytes: bytes, sha256: sha256) }
    }
    struct Stamp: Codable, Equatable, Sendable {
        let format: Int, owner: String, filename: String
        let installed: Fingerprint?, pending: Fingerprint?
    }
    struct Prepared: Sendable {
        let helper: String, cacheDirectory: String
        let bridge: Fingerprint
    }
    enum Failure: LocalizedError {
        case active, missingBridge, invalidBridge, ownership, environment
        var errorDescription: String? {
            switch self {
            case .active: return "Wait for Steam browser preparation to finish and close the running Wine session."
            case .missingBridge: return "This Madeira build is missing its Steam browser bridge."
            case .invalidBridge: return "This Madeira build's Steam browser bridge could not be verified."
            case .ownership: return "Existing Steam bridge files were kept because they could not be verified."
            case .environment: return "Steam's verified browser launch could not be configured."
            }
        }
    }
    typealias DigestFile = SteamBrowserRuntimeFiles.DigestFile
    private static func valid(_ fingerprint: Fingerprint) -> Bool {
        fingerprint.bytes >= 392 && fingerprint.bytes <= 32 * 1024 * 1024 &&
        fingerprint.sha256.utf8.count == 64 &&
        fingerprint.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func bounded(_ file: URL, maximum: Int) throws -> Data {
        try SteamBrowserRuntimeFiles.plain(file, directory: false)
        guard let count = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize,
              count >= 0, count <= maximum else { throw Failure.invalidBridge }
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        let result = try handle.read(upToCount: maximum + 1) ?? Data()
        guard result.count == count else { throw Failure.invalidBridge }
        return result
    }
    static func bundle(_ resourceRoot: URL, digest: DigestFile) throws -> (URL, BridgeManifest) {
        typealias Files = SteamBrowserRuntimeFiles
        try Files.plain(resourceRoot, directory: true)
        let dll = try Files.destination("arm64ec-windows/" + bridgeName, under: resourceRoot)
        let metadata = try Files.destination("arm64ec-windows/" + manifestName, under: resourceRoot)
        let manifest = try JSONDecoder().decode(BridgeManifest.self, from: bounded(metadata, maximum: 64 * 1024))
        guard manifest.format == 1, manifest.mode == "native-owner", manifest.filename == bridgeName,
              manifest.coreSHA256 == Files.official.coreSHA256,
              manifest.readinessABI == ReadinessABI(version: 1, size: 80, sha256: abiSHA256),
              valid(manifest.fingerprint) else { throw Failure.invalidBridge }
        try verify(dll, fingerprint: manifest.fingerprint, digest: digest)
        return (dll, manifest)
    }
    static func verify(_ dll: URL, fingerprint: Fingerprint, digest: DigestFile) throws {
        try SteamBrowserRuntimeFiles.plain(dll, directory: false)
        guard valid(fingerprint),
              (try dll.resourceValues(forKeys: [.fileSizeKey])).fileSize == fingerprint.bytes,
              try digest(dll) == fingerprint.sha256 else { throw Failure.invalidBridge }
        let handle = try FileHandle(forReadingFrom: dll); defer { try? handle.close() }
        guard let header = try handle.read(upToCount: 64 * 1024),
              SteamBrowserRuntimeFiles.machine(header) == 0x8664 else { throw Failure.invalidBridge }
    }
    static func compatRoot(drive: URL, idle: () -> Bool) throws -> URL {
        typealias Files = SteamBrowserRuntimeFiles
        try Files.plain(drive, directory: true)
        let windows = try Files.destination("windows", under: drive)
        try Files.plain(windows, directory: true)
        let root = URL(fileURLWithPath: try Files.destination("windows/madeira-compat", under: drive).path, isDirectory: true)
        if FileManager.default.fileExists(atPath: root.path) { try Files.plain(root, directory: true) }
        else {
            guard idle() else { throw Failure.active }
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        }
        return root
    }
    private static func checkedStamp(_ file: URL) throws -> Stamp {
        let value = try JSONDecoder().decode(Stamp.self, from: bounded(file, maximum: 16 * 1024))
        guard value.format == 1, value.owner == "org.madeira.NativeSteamBrowserBridge/v1", value.filename == bridgeName,
              value.installed != nil || value.pending != nil,
              value.installed.map(valid) ?? true, value.pending.map(valid) ?? true else { throw Failure.ownership }
        return value
    }
    // Pending ownership is written before replacing the one named app DLL. A
    // retry accepts only the recorded previous/new fingerprint. Unknown files,
    // links, mismatched stamps and unrelated system32 files are always retained.
    static func installBridge(_ source: URL, manifest: BridgeManifest, drive: URL,
                              digest: DigestFile, idle: () -> Bool) throws {
        typealias Files = SteamBrowserRuntimeFiles
        let fm = FileManager.default
        try verify(source, fingerprint: manifest.fingerprint, digest: digest)
        let system = try Files.destination("windows/system32", under: drive)
        try Files.plain(system, directory: true)
        let target = try Files.destination("windows/system32/" + bridgeName, under: drive)
        let stamp = try Files.destination("windows/system32/" + stampName, under: drive)
        let hasTarget = fm.fileExists(atPath: target.path), hasStamp = fm.fileExists(atPath: stamp.path)
        var previous: Fingerprint?
        if hasStamp {
            let value = try checkedStamp(stamp)
            if hasTarget {
                let count = try target.resourceValues(forKeys: [.fileSizeKey]).fileSize
                guard let match = [value.installed, value.pending].compactMap({ $0 })
                    .first(where: { $0.bytes == count && (try? digest(target)) == $0.sha256 }) else { throw Failure.ownership }
                try verify(target, fingerprint: match, digest: digest); previous = match
            }
        } else if hasTarget { throw Failure.ownership }
        if previous == manifest.fingerprint, hasStamp {
            // Recover a completed copy whose final stamp write was interrupted.
            guard idle() else { throw Failure.active }
        } else {
            guard idle() else { throw Failure.active }
            let pending = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                                installed: previous, pending: manifest.fingerprint)
            let encoded = try JSONEncoder().encode(pending)
            try encoded.write(to: stamp, options: hasStamp ? .atomic : .withoutOverwriting)
            guard idle() else { throw Failure.active }
            if let previous { try verify(target, fingerprint: previous, digest: digest) }
            else if fm.fileExists(atPath: target.path) { throw Failure.ownership }
            // The bundle has a strict 32 MiB pin and was reverified above.
            let image = try bounded(source, maximum: 32 * 1024 * 1024)
            try image.write(to: target, options: .atomic)
            try verify(target, fingerprint: manifest.fingerprint, digest: digest)
        }
        guard idle() else { throw Failure.active }
        let complete = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                             installed: manifest.fingerprint, pending: nil)
        try JSONEncoder().encode(complete).write(to: stamp, options: .atomic)
    }
    static func windowsPath(_ file: URL, drive: URL) throws -> String {
        let root = drive.standardizedFileURL.path, path = file.standardizedFileURL.path
        guard path.hasPrefix(root + "/"),
              path == file.resolvingSymlinksInPath().standardizedFileURL.path else { throw Failure.environment }
        let relative = String(path.dropFirst(root.count + 1))
        guard SteamRuntimeFiles.validPath(relative), relative.utf8.allSatisfy({ (32...126).contains($0) }) else { throw Failure.environment }
        return "C:\\" + relative.replacingOccurrences(of: "/", with: "\\")
    }
    static func prepared(_ cache: SteamBrowserRuntimeFiles.Prepared, bridge: Fingerprint, drive: URL) throws -> Prepared {
        let helper = try windowsPath(cache.helper, drive: drive), root = try windowsPath(cache.browserRoot, drive: drive)
        guard root == nativeCache, helper == root + "\\steamwebhelper.exe", valid(bridge),
              cache.recipe == SteamBrowserRuntimeFiles.official.id,
              cache.coreSHA256 == SteamBrowserRuntimeFiles.official.coreSHA256 else { throw Failure.environment }
        return Prepared(helper: helper, cacheDirectory: root, bridge: bridge)
    }
    static func mergedLocks(_ existing: String?) throws -> String {
        guard (existing?.utf8.count ?? 0) <= 16 * 1024 else { throw Failure.environment }
        var names: [String] = []
        for raw in (existing ?? "").split(separator: ",") {
            let name = raw.trimmingCharacters(in: .whitespaces)
            if !name.isEmpty, !names.contains(name) { names.append(name) }
        }
        for name in lockedNames where !names.contains(name) { names.append(name) }
        return names.joined(separator: ",")
    }
    // Called on the launch worker after all profile environment application.
    // The locklist protects both global and per-game cfg loops in the bridge.
    // Unrelated launches lock these names absent so cfg cannot activate a gate.
    static func export(native: Bool, prepared: Prepared?, get: (String) -> String?,
                       set: (String, String) -> Bool, unset: (String) -> Void) throws {
        for name in lockedNames.prefix(3) { unset(name) }
        let locks = try mergedLocks(get("MADEIRA_ENV_LOCKED"))
        guard set("MADEIRA_ENV_LOCKED", locks) else { throw Failure.environment }
        guard native else { return }
        guard let selected = prepared, selected.cacheDirectory == nativeCache, valid(selected.bridge),
              selected.helper == selected.cacheDirectory + "\\steamwebhelper.exe" else { throw Failure.environment }
        guard set("MADEIRA_HTMLIPC_HELPER", selected.helper),
              set("MADEIRA_HTMLIPC_CACHE_DIR", selected.cacheDirectory),
              set("MADEIRA_NATIVE_STEAM_LAUNCH", "1") else {
            for name in lockedNames.prefix(3) { unset(name) }; throw Failure.environment
        }
    }
}

#if canImport(CryptoKit) && canImport(Combine)
@MainActor final class SteamNativeBrowserLaunch: ObservableObject {
    static let shared = SteamNativeBrowserLaunch()
    typealias Prepared = SteamNativeBrowserLaunchFiles.Prepared
    @Published private(set) var busy = false
    static var appDrive: URL {
        // Resolve only the trusted OS container alias, retaining child symlink
        // rejection for the prefix, Windows/Steam directories and destination.
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            .resolvingSymlinksInPath().appendingPathComponent("wine/drive_c")
    }
    // Reserve on the caller's main-actor turn, before creating an async task.
    // A second Play cannot slip in before the first task starts running.
    func begin(drive: URL, resourceRoot: URL?, idle: @escaping () -> Bool,
               progress: @escaping (String) -> Void = { _ in }) throws -> Task<Prepared, Error> {
        typealias Files = SteamNativeBrowserLaunchFiles
        guard !busy, !SteamBrowserRuntime.busy, idle() else { throw Files.Failure.active }
        busy = true
        return Task { @MainActor in
            defer { self.busy = false }
            return try await self.prepare(drive: drive, resourceRoot: resourceRoot, idle: idle, progress: progress)
        }
    }
    private func prepare(drive: URL, resourceRoot: URL?, idle: () -> Bool,
                         progress: (String) -> Void) async throws -> Prepared {
        typealias Files = SteamNativeBrowserLaunchFiles
        guard idle() else { throw Files.Failure.active }
        guard let resources = resourceRoot else { throw Files.Failure.missingBridge }
        let (source, manifest) = try Files.bundle(resources.resolvingSymlinksInPath(), digest: SteamBrowserRuntime.hash)
        let launcher = try SteamClientUpdateFiles.launcher(drive: drive)
        let steam = launcher.deletingLastPathComponent(), chromeHTML = steam.appendingPathComponent("bin/chromehtml.dll")
        let compat = try Files.compatRoot(drive: drive, idle: idle)
        let cache = try await SteamBrowserRuntime.prepare(cacheBase: compat, steamRoot: steam, chromeHTML: chromeHTML,
                                                        idle: idle, progress: progress)
        guard idle() else { throw Files.Failure.active }
        try Files.installBridge(source, manifest: manifest, drive: drive, digest: SteamBrowserRuntime.hash, idle: idle)
        try SteamBrowserRuntimeFiles.core(chromeHTML, steamRoot: steam, recipe: .official, digest: SteamBrowserRuntime.hash)
        guard idle() else { throw Files.Failure.active }
        return try Files.prepared(cache, bridge: manifest.fingerprint, drive: drive)
    }
}
#endif
