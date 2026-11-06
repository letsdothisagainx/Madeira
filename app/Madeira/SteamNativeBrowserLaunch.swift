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
    static let logRootName = "SteamBrowserLogs"
    static let logOwnerName = ".madeira-browser-logs-owner-v1"
    static let logOwnerBytes = Data("org.madeira.SteamBrowserLogs/v1\n".utf8)
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
    enum Phase: String {
        case bundle = "bridge-bundled-source", source = "bridge-source-recheck"
        case stamp = "bridge-existing-stamp", existing = "bridge-existing-target"
        case pending = "bridge-pending-transaction", copy = "bridge-copy"
        case readback = "bridge-installed-readback", paths = "bridge-paths"
    }
    private static func trace(_ phase: Phase, result: String, reason: String = "none", expected: Int = -1,
                              observed: Int = -1, hash: String = "not-checked", machine: UInt16? = nil,
                              state: String = "none", report: (String) -> Void) {
        report("[steam-browser-bridge-v2] phase=\(phase.rawValue) result=\(result) reason=\(reason) expected-size=\(expected) observed-size=\(observed) sha256=\(hash) expected-machine=8664 machine=\(machine.map { String(format: "%04x", $0) } ?? "unknown") stamp=\(state)")
    }
    private static func stampState(_ value: Stamp) -> String {
        value.installed != nil ? (value.pending != nil ? "installed+pending" : "installed") : "pending"
    }
    // URL.resourceValues caches metadata on Darwin. Atomic replacement changes
    // the inode without invalidating that URL's cached fileSizeKey. Open the
    // current file and obtain its size from the descriptor on EVERY readback.
    private static func length(_ handle: FileHandle) throws -> Int {
        let count = try handle.seekToEnd()
        guard count <= UInt64(Int.max) else { throw Failure.invalidBridge }
        try handle.seek(toOffset: 0)
        return Int(count)
    }
    private static func freshLength(_ file: URL) throws -> Int {
        try SteamBrowserRuntimeFiles.plain(file, directory: false)
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        return try length(handle)
    }
    private static func valid(_ fingerprint: Fingerprint) -> Bool {
        fingerprint.bytes >= 392 && fingerprint.bytes <= 32 * 1024 * 1024 &&
        fingerprint.sha256.utf8.count == 64 &&
        fingerprint.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func bounded(_ file: URL, maximum: Int) throws -> Data {
        try SteamBrowserRuntimeFiles.plain(file, directory: false)
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        let count = try length(handle)
        guard count <= maximum else { throw Failure.invalidBridge }
        var result = Data()
        while result.count <= maximum {
            let chunk = try handle.read(upToCount: min(1024 * 1024, maximum + 1 - result.count)) ?? Data()
            if chunk.isEmpty { break }; result.append(chunk)
        }
        guard result.count == count else { throw Failure.invalidBridge }
        return result
    }
    static func bundle(_ resourceRoot: URL, digest: DigestFile, report: (String) -> Void = { _ in }) throws -> (URL, BridgeManifest) {
        typealias Files = SteamBrowserRuntimeFiles
        try Files.plain(resourceRoot, directory: true)
        let dll = try Files.destination("arm64ec-windows/" + bridgeName, under: resourceRoot)
        let metadata = try Files.destination("arm64ec-windows/" + manifestName, under: resourceRoot)
        trace(.bundle, result: "begin", report: report)
        let manifest = try JSONDecoder().decode(BridgeManifest.self, from: bounded(metadata, maximum: 64 * 1024))
        guard manifest.format == 1, manifest.mode == "native-owner", manifest.filename == bridgeName,
              manifest.coreSHA256 == Files.official.coreSHA256,
              manifest.readinessABI == ReadinessABI(version: 1, size: 80, sha256: abiSHA256),
              valid(manifest.fingerprint) else { throw Failure.invalidBridge }
        try verify(dll, fingerprint: manifest.fingerprint, digest: digest, phase: .bundle, report: report)
        return (dll, manifest)
    }
    static func verify(_ dll: URL, fingerprint: Fingerprint, digest: DigestFile, phase: Phase = .source,
                       state: String = "none", report: (String) -> Void = { _ in }) throws {
        var size = -1, hash = "not-checked", machine: UInt16?, reason = "fingerprint"
        do {
            guard valid(fingerprint) else { throw Failure.invalidBridge }
            reason = "filesystem"
            try SteamBrowserRuntimeFiles.plain(dll, directory: false)
            let handle = try FileHandle(forReadingFrom: dll); defer { try? handle.close() }
            size = try length(handle)
            reason = "size"
            guard size == fingerprint.bytes else { throw Failure.invalidBridge }
            let header = try handle.read(upToCount: 64 * 1024) ?? Data()
            machine = SteamBrowserRuntimeFiles.machine(header)
            reason = "sha256"; hash = try digest(dll) == fingerprint.sha256 ? "match" : "mismatch"
            guard hash == "match" else { throw Failure.invalidBridge }
            reason = "architecture"
            guard machine == 0x8664 else { throw Failure.invalidBridge }
            trace(phase, result: "verified", expected: fingerprint.bytes, observed: size, hash: hash, machine: machine, state: state, report: report)
        } catch {
            trace(phase, result: "failed", reason: reason, expected: fingerprint.bytes, observed: size, hash: hash, machine: machine, state: state, report: report)
            throw error
        }
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
    private static func checkedStamp(_ file: URL, report: (String) -> Void) throws -> (Stamp, Data) {
        let bytes: Data
        do { bytes = try bounded(file, maximum: 16 * 1024) }
        catch {
            trace(.stamp, result: "failed", reason: "bounded-metadata", observed: (try? freshLength(file)) ?? -1, state: "invalid", report: report)
            throw error
        }
        let value: Stamp
        do { value = try JSONDecoder().decode(Stamp.self, from: bytes) }
        catch {
            trace(.stamp, result: "failed", reason: "metadata", observed: bytes.count, state: "invalid", report: report)
            throw Failure.ownership
        }
        guard value.format == 1, value.owner == "org.madeira.NativeSteamBrowserBridge/v1", value.filename == bridgeName,
              value.installed != nil || value.pending != nil,
              value.installed.map(valid) ?? true, value.pending.map(valid) ?? true else {
            trace(.stamp, result: "failed", reason: "ownership", observed: bytes.count, state: "invalid", report: report)
            throw Failure.ownership
        }
        trace(.stamp, result: "verified", observed: bytes.count, state: stampState(value), report: report)
        return (value, bytes)
    }
    // Pending ownership is written before replacing the one named app DLL. A
    // retry accepts only the recorded previous/new fingerprint. Unknown files,
    // links, mismatched stamps and unrelated system32 files are always retained.
    static func installBridge(_ source: URL, manifest: BridgeManifest, drive: URL,
                              digest: DigestFile, idle: () -> Bool, report: (String) -> Void = { _ in }) throws {
        typealias Files = SteamBrowserRuntimeFiles
        let fm = FileManager.default
        try verify(source, fingerprint: manifest.fingerprint, digest: digest, report: report)
        let system = try Files.destination("windows/system32", under: drive)
        try Files.plain(system, directory: true)
        let target = try Files.destination("windows/system32/" + bridgeName, under: drive)
        let stamp = try Files.destination("windows/system32/" + stampName, under: drive)
        let hasTarget = fm.fileExists(atPath: target.path), hasStamp = fm.fileExists(atPath: stamp.path)
        var previous: Fingerprint?, previousStamp: Data?, state = "missing"
        if hasStamp {
            let (value, bytes) = try checkedStamp(stamp, report: report)
            previousStamp = bytes
            state = stampState(value)
            if hasTarget {
                trace(.existing, result: "begin", state: state, report: report)
                let count = try freshLength(target)
                guard count <= 32 * 1024 * 1024 else {
                    trace(.existing, result: "failed", reason: "size", observed: count, state: state, report: report)
                    throw Failure.ownership
                }
                let actualHash = try digest(target)
                guard let match = [value.installed, value.pending].compactMap({ $0 })
                    .first(where: { $0.bytes == count && actualHash == $0.sha256 }) else {
                    trace(.existing, result: "failed", reason: "ownership-fingerprint", observed: count, hash: "mismatch", state: state, report: report)
                    throw Failure.ownership
                }
                try verify(target, fingerprint: match, digest: digest, phase: .existing, state: state, report: report)
                previous = match
            } else {
                trace(.existing, result: "absent", reason: "pending-recovery", state: state, report: report)
            }
        } else if hasTarget {
            trace(.stamp, result: "absent", reason: "unowned-target", state: state, report: report)
            throw Failure.ownership
        } else {
            trace(.stamp, result: "absent", state: state, report: report)
            trace(.existing, result: "absent", state: state, report: report)
        }
        if previous == manifest.fingerprint, hasStamp {
            // Recover a completed copy whose final stamp write was interrupted.
            guard idle() else { throw Failure.active }
        } else {
            guard idle() else { throw Failure.active }
            trace(.pending, result: "begin", state: state, report: report)
            var backup: URL?
            if let previous {
                // Retain only a version proved by the existing ownership stamp.
                // This invocation creates the directory; no old/ambient backup
                // is adopted or overwritten. It remains available for diagnosis.
                let directory = system.appendingPathComponent(".madeira-bridge-previous-" + UUID().uuidString, isDirectory: true)
                try fm.createDirectory(at: directory, withIntermediateDirectories: false)
                let saved = directory.appendingPathComponent(bridgeName)
                try bounded(target, maximum: 32 * 1024 * 1024).write(to: saved, options: .withoutOverwriting)
                guard let previousStamp else { throw Failure.ownership }
                try previousStamp.write(to: directory.appendingPathComponent(stampName), options: .withoutOverwriting)
                try verify(saved, fingerprint: previous, digest: digest, phase: .pending, state: "previous-retained", report: report)
                backup = saved
            }
            let pending = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                                installed: previous, pending: manifest.fingerprint)
            let encoded = try JSONEncoder().encode(pending)
            try encoded.write(to: stamp, options: hasStamp ? .atomic : .withoutOverwriting)
            state = stampState(pending)
            trace(.pending, result: "written", observed: encoded.count, state: state, report: report)
            do {
                guard idle() else { throw Failure.active }
                if let previous { try verify(target, fingerprint: previous, digest: digest, phase: .existing, state: state, report: report) }
                else if fm.fileExists(atPath: target.path) { throw Failure.ownership }
                // Atomic write retains the established publication behavior.
                // Readback opens the NEW inode instead of reusing URL metadata.
                trace(.copy, result: "begin", expected: manifest.bytes, state: state, report: report)
                let image = try bounded(source, maximum: 32 * 1024 * 1024)
                try image.write(to: target, options: .atomic)
                trace(.copy, result: "written", expected: manifest.bytes, observed: image.count, state: state, report: report)
                try verify(target, fingerprint: manifest.fingerprint, digest: digest, phase: .readback, state: state, report: report)
                guard idle() else { throw Failure.active }
            } catch {
                // Restore only a still-owned published version. An unexpected
                // third-party/corrupted file is never overwritten on failure.
                if let backup, let previous, let previousStamp, idle(),
                   (try? verify(target, fingerprint: manifest.fingerprint, digest: digest)) != nil,
                   (try? verify(backup, fingerprint: previous, digest: digest)) != nil {
                    do {
                        try bounded(backup, maximum: 32 * 1024 * 1024).write(to: target, options: .atomic)
                        try verify(target, fingerprint: previous, digest: digest, phase: .readback, state: "rollback", report: report)
                        try previousStamp.write(to: stamp, options: .atomic)
                    } catch {
                        trace(.readback, result: "failed", reason: "rollback", state: state, report: report)
                    }
                }
                throw error
            }
        }
        guard idle() else { throw Failure.active }
        // Reuse/pending recovery also emits the mandatory installed readback.
        try verify(target, fingerprint: manifest.fingerprint, digest: digest, phase: .readback, state: state, report: report)
        let complete = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                             installed: manifest.fingerprint, pending: nil)
        try JSONEncoder().encode(complete).write(to: stamp, options: .atomic)
        trace(.pending, result: "completed", observed: manifest.bytes, hash: "match", machine: 0x8664, state: "installed", report: report)
    }
    // The helper executable's statically linked logger writes debug.log next
    // to its executable even when libcef receives an explicit --log-file.
    // Prepare a separate owned namespace. Logging must never add a launch gate:
    // if unavailable, the native exact-file policy returns a real I/O error.
    @discardableResult
    static func prepareMutableLogs(drive: URL, idle: () -> Bool,
                                   report: (String) -> Void = { _ in }) -> Bool {
        typealias Files = SteamBrowserRuntimeFiles
        let fm = FileManager.default
        var reason = "filesystem"
        do {
            guard idle() else { reason = "active"; throw Failure.active }
            let compat = try compatRoot(drive: drive, idle: idle)
            let root = URL(fileURLWithPath: try Files.destination(logRootName, under: compat).path, isDirectory: true)
            if fm.fileExists(atPath: root.path) {
                reason = "ownership"
                try Files.plain(root, directory: true)
                let owner = try Files.destination(logOwnerName, under: root)
                guard try bounded(owner, maximum: 128) == logOwnerBytes else { throw Failure.ownership }
                guard (try fm.attributesOfItem(atPath: owner.path)[.referenceCount] as? NSNumber)?.intValue == 1 else { throw Failure.ownership }
            } else {
                let stage = compat.appendingPathComponent(".browser-logs-" + UUID().uuidString, isDirectory: true)
                try fm.createDirectory(at: stage, withIntermediateDirectories: false)
                defer { if fm.fileExists(atPath: stage.path) { try? fm.removeItem(at: stage) } }
                try logOwnerBytes.write(to: stage.appendingPathComponent(logOwnerName), options: .withoutOverwriting)
                guard idle() else { reason = "active"; throw Failure.active }
                try fm.moveItem(at: stage, to: root)
            }
            let log = try Files.destination("debug.log", under: root)
            if fm.fileExists(atPath: log.path) {
                reason = "log-type"; try Files.plain(log, directory: false)
                guard (try fm.attributesOfItem(atPath: log.path)[.referenceCount] as? NSNumber)?.intValue == 1 else { throw Failure.ownership }
            }
            report("[steam-browser-log-v2] destination=owned-mutable result=ready immutable-default=redirected")
            return true
        } catch {
            report("[steam-browser-log-v2] destination=owned-mutable result=unavailable reason=\(reason) immutable-default=denied")
            return false
        }
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
        do {
            guard idle() else { throw Files.Failure.active }
            guard let resources = resourceRoot else { throw Files.Failure.missingBridge }
            let (source, manifest) = try Files.bundle(resources.resolvingSymlinksInPath(), digest: SteamBrowserRuntime.hash, report: progress)
            let launcher = try SteamClientUpdateFiles.launcher(drive: drive)
            let steam = launcher.deletingLastPathComponent(), chromeHTML = steam.appendingPathComponent("bin/chromehtml.dll")
            let compat = try Files.compatRoot(drive: drive, idle: idle)
            let cache = try await SteamBrowserRuntime.prepare(cacheBase: compat, steamRoot: steam, chromeHTML: chromeHTML,
                                                            idle: idle, progress: progress)
            guard idle() else { throw Files.Failure.active }
            try Files.installBridge(source, manifest: manifest, drive: drive, digest: SteamBrowserRuntime.hash, idle: idle, report: progress)
            Files.prepareMutableLogs(drive: drive, idle: idle, report: progress)
            try SteamBrowserRuntimeFiles.core(chromeHTML, steamRoot: steam, recipe: SteamBrowserRuntimeFiles.official, digest: SteamBrowserRuntime.hash)
            guard idle() else { throw Files.Failure.active }
            progress("[steam-browser-bridge-v2] phase=bridge-paths result=begin")
            let prepared = try Files.prepared(cache, bridge: manifest.fingerprint, drive: drive)
            progress("[steam-browser-bridge-v2] phase=bridge-paths result=verified helper=accepted installed=verified")
            return prepared
        } catch {
            progress("[steam-browser-bridge-v2] phase=bridge-preparation result=failed code=\((error as NSError).code)")
            // Raw Foundation errors may contain the private container path.
            // Keep our existing public failure types and sanitize everything else.
            if let failure = error as? Files.Failure { throw failure }
            if let failure = error as? SteamBrowserRuntimeFiles.Failure { throw failure }
            if let failure = error as? SteamBrowserRuntimeFiles.ValidationIssue { throw failure }
            if error is CancellationError { throw CancellationError() }
            throw Files.Failure.invalidBridge
        }
    }
}
#endif
