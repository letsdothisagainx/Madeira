// SPDX-License-Identifier: GPL-3.0-or-later
// Verified official browser cache, prepared before Wine starts.
import Foundation
import Dispatch
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

enum SteamBrowserRuntimeFiles {
    struct Package: Codable, Equatable, Sendable {
        let file: String, bytes: Int, sha256: String
        // A verified core archive may supply one exact root DLL only. Every
        // other member is still parsed/decompressed/CRC-checked by unpack().
        let singleMember: String?
        init(file: String, bytes: Int, sha256: String, singleMember: String? = nil) {
            self.file = file; self.bytes = bytes; self.sha256 = sha256; self.singleMember = singleMember
        }
    }
    struct Key: Equatable, Sendable {
        let name: String, sha256: String, bytes: Int?
        let machine: UInt16
        init(name: String, sha256: String, bytes: Int? = nil, machine: UInt16 = 0x014c) {
            self.name = name; self.sha256 = sha256; self.bytes = bytes; self.machine = machine
        }
    }
    struct GeneratedFile: Equatable, Sendable {
        let name: String, bytes: Data, sha256: String
    }
    struct Recipe: Equatable, Sendable {
        let id: String, coreSHA256: String, prefix: String
        let expectedFiles: Int
        let packages: [Package], keys: [Key]
        let marker: GeneratedFile
    }
    // Exact cache-contract-v2.txt bytes, including the final LF.
    // The native gate treats this as host verification metadata, not a signature.
    static let officialMarker = GeneratedFile(name: ".madeira-cache-verified-v1", bytes: Data((
        "MadeiraHtmlIPC-I386-Cache-v2\n" +
        "steamwebhelper.exe 014c 8dba99d204779a30a88a794d1a88d7e76355d004d876ed4bb29da7c3d5a4fc70\n" +
        "libcef.dll 014c b2dc73b55ca1d6a44a594e97b4ddd57bd19e79b2d09521faf2dfb83f51e2a94e\n" +
        "chrome_elf.dll 014c 0c91bfdbb22d20ea153869a3dc7379d54a7380faee300d0fd6809fce491a3677\n" +
        "SDL3.dll 014c db01ec466db9c4e19cc5fe8c878ac89bc1b6057136432554842b3cd4dca88669\n"
    ).utf8), sha256: "fff4a23d727dd4f33ec070d29cb0012d7a22bf7f6f4e84e2cffc6709224e1781")
    static let official = Recipe(
        id: "official-i386-fee14790d59463f3-1ab3b3834172a644-sdl-db01ec466db9c4e1-v2",
        coreSHA256: "37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b",
        prefix: "bin/cef/cef.win7/", expectedFiles: 79,
        packages: [
            Package(file: "bins_cef_win32.zip.1c1d9dc1d899e7c8d1cff9cb0fcc11b89e412b98", bytes: 130_079_979,
                    sha256: "fee14790d59463f31693ef95e10327824f5bdd95baf0aa8fae3b81aea98e794f"),
            Package(file: "bins_webhelpers_win32.zip.8a153ec2ee2090c19b25204806ffca2a7ba15bf2", bytes: 2_735_010,
                    sha256: "1ab3b3834172a644759860f65d853970ba1d8b65f30190aae774395d69136307"),
            Package(file: "bins_win32.zip.23e34a6d4b10596a44561a5100dac5585d2517da", bytes: 59_544_006,
                    sha256: "8b712b2a3412a9066b7725f4e1c5cef9a7ca5b187b6585a5b92d25d09df0ba62", singleMember: "SDL3.dll")
        ], keys: [
            Key(name: "steamwebhelper.exe", sha256: "8dba99d204779a30a88a794d1a88d7e76355d004d876ed4bb29da7c3d5a4fc70"),
            Key(name: "libcef.dll", sha256: "b2dc73b55ca1d6a44a594e97b4ddd57bd19e79b2d09521faf2dfb83f51e2a94e"),
            Key(name: "chrome_elf.dll", sha256: "0c91bfdbb22d20ea153869a3dc7379d54a7380faee300d0fd6809fce491a3677"),
            Key(name: "SDL3.dll", sha256: "db01ec466db9c4e19cc5fe8c878ac89bc1b6057136432554842b3cd4dca88669", bytes: 2_432_152),
            // Valve includes this AMD64 diagnostic component in its I386 CEF
            // archive. Preserve the genuine file; it is not a browser DLL swap.
            Key(name: "msdia140.dll", sha256: "484dee047c0f2a6e556056ad994ef6a9b846a676a067883257c7122c46c97d66",
                bytes: 2_245_784, machine: 0x8664)
        ], marker: officialMarker)
    // These independently inspected chromehtml profiles share the verified
    // browser wire contract. Keep the cache recipe/manifest identity stable:
    // this is compatibility selection, never a new cache trust shortcut.
    static let officialCompatibleCoreSHA256 = [
        "37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b",
        "7afabbd8fae70a1b9831546d4c126ebd74c18796457e3a12fa259f529f7f2266"
    ]
    static let ownerName = ".madeira-browser-owner-v1"
    static let ownerBytes = Data("org.madeira.SteamBrowserRuntime/v1\n".utf8)
    static let completion = ".complete-v1.json"
    static let origin = "https://client-update.akamai.steamstatic.com/"

    enum Failure: LocalizedError {
        case active, invalid, ownership, changedCore
        var errorDescription: String? {
            switch self {
            case .active: return "Close the Wine session before preparing Steam's browser."
            case .invalid: return "Valve's browser components could not be verified."
            case .ownership: return "The browser cache contains existing files that were kept."
            case .changedCore: return "This Steam client does not match the verified browser bridge."
            }
        }
    }
    // Only fixed predicates and relative component names enter diagnostics.
    // Foundation errors can contain the app container path; never print them.
    enum Reason: String, Sendable {
        case missingFile = "missing-file", fileType = "file-type", fileSize = "file-size"
        case fileHash = "file-hash", architecture, generatedMarker = "generated-marker"
        case completionSize = "completion-size", completionMalformed = "completion-malformed"
        case completionMismatch = "completion-mismatch", recordCount = "record-count"
        case recordInvalid = "record-invalid", duplicateRecord = "duplicate-record"
        case keyRecord = "key-record", unexpectedFile = "unexpected-file"
        case unexpectedDirectory = "unexpected-directory", enumeration, relativePath = "relative-path"
        case filesystem, archiveSize = "archive-size", archiveHash = "archive-hash"
        case archiveMember = "archive-member", archiveMetadata = "archive-metadata"
        case responseStatus = "response-status", responseURL = "response-url"
        case responseLength = "response-length", responseEncoding = "response-encoding", bodyLength = "body-length"
        case ownership, active, changedCore = "changed-core", cancelled
    }
    struct ValidationIssue: LocalizedError, Equatable, Sendable {
        let reason: Reason, name: String
        let expected: Int, observed: Int, records: Int
        init(_ reason: Reason, _ name: String = "", expected: Int = -1, observed: Int = -1, records: Int = -1) {
            self.reason = reason; self.name = name; self.expected = expected; self.observed = observed
            self.records = records
        }
        var errorDescription: String? { Failure.invalid.errorDescription }
        func diagnostic(phase: String, recipe: Recipe) -> String {
            // Reject path/URL escapes and redact long opaque filename segments.
            let relative: String
            if name.isEmpty { relative = "-" }
            else if !SteamRuntimeFiles.validPath(name) { relative = "<invalid-relative-name>" }
            else {
                relative = name.split(separator: "/").prefix(12).map { part in
                    let lower = part.lowercased()
                    if part.utf8.count > 64 || ["token", "password", "credential", "cookie"].contains(where: lower.contains) {
                        return "<private>"
                    }
                    return String(part.unicodeScalars.map { scalar in
                        scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || "._-".unicodeScalars.contains(scalar)) ? Character(String(scalar)) : "_"
                    })
                }.joined(separator: "/")
            }
            return "[steam-browser-cache-v4] phase=\(phase) reason=\(reason.rawValue) recipe=\(recipe.id) expected=\(expected) observed=\(observed) records-expected=\(recipe.expectedFiles + 1) records-observed=\(records) relative=\(relative)"
        }
    }
    // Numeric transfer state only. No response URL, header, filesystem path
    // or arbitrary NSError text enters the preparation progress callback.
    struct DownloadEvent: Sendable, Equatable {
        enum Phase: String, Sendable { case waiting, response, receiving, completed, failed, cancelled }
        let phase: Phase
        let received: Int, expected: Int, elapsedMS: Int
        let code: Int, retryable: Bool
        init(_ phase: Phase, received: Int, expected: Int, elapsedMS: Int,
             code: Int = 0, retryable: Bool = false) {
            self.phase = phase; self.received = received; self.expected = expected
            self.elapsedMS = elapsedMS; self.code = code; self.retryable = retryable
        }
        func diagnostic(package: Int, count: Int) -> String {
            "[steam-browser-transfer-v1] package=\(package)/\(count) phase=\(phase.rawValue) received=\(received) expected=\(expected) elapsed-ms=\(elapsedMS) code=\(code) retryable=\(retryable ? 1 : 0)"
        }
    }
    // Rate limiting is independent of networking, with a hard update budget.
    // Critical start/response/completion/failure events are reported separately.
    struct DownloadProgress: Sendable {
        private(set) var updates = 0
        private var lastMS = 0, lastBucket = 0
        mutating func shouldReport(received: Int, expected: Int, elapsedMS: Int) -> Bool {
            guard updates < 64, received >= 0, expected > 0, expected <= Int.max / 20,
                  received <= expected, elapsedMS >= lastMS else { return false }
            let bucket = Int((Int64(received) * 20) / Int64(expected))
            guard elapsedMS - lastMS >= 15_000 || (bucket > lastBucket && elapsedMS - lastMS >= 1_000) else { return false }
            updates += 1; lastMS = elapsedMS; lastBucket = bucket
            return true
        }
    }
    struct FileRecord: Codable, Equatable, Sendable {
        let name: String, bytes: Int, sha256: String
        let generated: Bool
        init(name: String, bytes: Int, sha256: String, generated: Bool = false) {
            self.name = name; self.bytes = bytes; self.sha256 = sha256; self.generated = generated
        }
    }
    struct Manifest: Codable, Equatable, Sendable {
        let format: Int, recipe: String, coreSHA256: String
        let packages: [Package], files: [FileRecord]
    }
    struct Prepared: Sendable {
        let helper: URL, browserRoot: URL, coreSHA256: String, recipe: String
    }
    typealias DigestFile = (URL) throws -> String
    typealias DigestData = (Data) -> String

    static func inside(_ child: URL, _ root: URL) -> Bool {
        // Conservatively treat case aliases as overlapping even on hosts with
        // case-sensitive filesystems; the device may be case-insensitive.
        let c = child.standardizedFileURL.path.lowercased(), r = root.standardizedFileURL.path.lowercased()
        return c == r || c.hasPrefix(r.hasSuffix("/") ? r : r + "/")
    }
    static func plain(_ url: URL, directory: Bool) throws {
        guard url.isFileURL,
              url.standardizedFileURL.path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw Failure.ownership
        }
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey])
        guard values.isSymbolicLink != true,
              directory ? values.isDirectory == true : values.isRegularFile == true else { throw Failure.ownership }
    }
    static func destination(_ name: String, under root: URL) throws -> URL {
        // Shared checker refuses traversal, linked parents, and case aliases.
        try SteamRuntimeFiles.destination(name, under: root)
    }
    static func machine(_ data: Data) -> UInt16? {
        guard data.count >= 64, data[0] == 0x4d, data[1] == 0x5a else { return nil }
        func u16(_ p: Int) -> UInt16 { UInt16(data[p]) | UInt16(data[p + 1]) << 8 }
        let offset = Int(UInt32(u16(0x3c)) | UInt32(u16(0x3e)) << 16)
        guard offset <= data.count - 26, data[offset..<offset + 4].elementsEqual([0x50, 0x45, 0, 0]),
              u16(offset + 20) >= 2, Int(u16(offset + 20)) <= data.count - offset - 24 else { return nil }
        let kind = u16(offset + 4), magic = u16(offset + 24)
        return (kind == 0x014c && magic == 0x10b) || (kind == 0x8664 && magic == 0x20b) ? kind : nil
    }
    static func executable(_ name: String) -> Bool {
        ["exe", "dll"].contains(URL(fileURLWithPath: name).pathExtension.lowercased())
    }
    static func expectedMachine(_ name: String, recipe: Recipe) -> UInt16 {
        recipe.keys.first(where: { recipe.prefix + $0.name == name })?.machine ?? 0x014c
    }
    static func compatibleCoreSHA256(_ file: URL, steamRoot: URL, recipe: Recipe, digest: DigestFile) throws -> String {
        guard file.standardizedFileURL != steamRoot.standardizedFileURL, inside(file, steamRoot) else {
            throw Failure.changedCore
        }
        try plain(steamRoot, directory: true); try plain(file, directory: false)
        let actual = try digest(file)
        // Compare the entire recipe, not its public identifier or one field.
        // Unrelated/test recipes retain their original exact-core contract.
        let permitted = recipe == official ? officialCompatibleCoreSHA256 : [recipe.coreSHA256]
        guard permitted.contains(actual) else { throw Failure.changedCore }
        return actual
    }
    static func core(_ file: URL, steamRoot: URL, recipe: Recipe, digest: DigestFile) throws {
        _ = try compatibleCoreSHA256(file, steamRoot: steamRoot, recipe: recipe, digest: digest)
    }

    // The dedicated owner root is atomically introduced. A preexisting unowned
    // directory is never adopted. Existing incomplete stages are never removed.
    static func ownerRoot(cacheBase: URL, steamRoot: URL, idle: () -> Bool) throws -> URL {
        let fm = FileManager.default
        try plain(cacheBase, directory: true)
        // Foundation otherwise infers a trailing directory slash only AFTER
        // creation, making the fresh and reused URL values compare unequal.
        let root = URL(fileURLWithPath: try destination("SteamBrowserRuntime", under: cacheBase).path, isDirectory: true)
        guard !inside(root, steamRoot), !inside(steamRoot, root) else { throw Failure.ownership }
        if fm.fileExists(atPath: root.path) {
            try plain(root, directory: true)
            let marker = try destination(ownerName, under: root)
            try plain(marker, directory: false)
            guard (try marker.resourceValues(forKeys: [.fileSizeKey])).fileSize == ownerBytes.count,
                  try Data(contentsOf: marker) == ownerBytes else { throw Failure.ownership }
            return root
        }
        guard idle() else { throw Failure.active }
        let stage = cacheBase.appendingPathComponent(".browser-owner-" + UUID().uuidString)
        try fm.createDirectory(at: stage, withIntermediateDirectories: false)
        var moved = false
        defer { if !moved { try? fm.removeItem(at: stage) } }
        try ownerBytes.write(to: stage.appendingPathComponent(ownerName), options: .withoutOverwriting)
        guard idle() else { throw Failure.active }
        try fm.moveItem(at: stage, to: root); moved = true
        return root
    }

    static func appendArchive(_ archive: Data, package: Package, recipe: Recipe, stage: URL,
                              records: inout [FileRecord], digest: DigestData, idle: () -> Bool) throws {
        // The sole call that raises ZIP budgets follows both exact pin checks.
        guard recipe.packages.contains(package) else { throw ValidationIssue(.archiveMember) }
        guard archive.count == package.bytes else {
            throw ValidationIssue(.archiveSize, package.file, expected: package.bytes, observed: archive.count)
        }
        guard digest(archive) == package.sha256 else { throw ValidationIssue(.archiveHash, package.file) }
        if let member = package.singleMember {
            guard SteamRuntimeFiles.validPath(member), !member.contains("/") else { throw Failure.invalid }
        }
        guard idle() else { throw Failure.active }
        var seen = Set(records.map { $0.name.lowercased() })
        func install(_ name: String, _ bytes: Data) throws {
            guard name.hasPrefix(recipe.prefix), name.count > recipe.prefix.count,
                  name.lowercased() != (recipe.prefix + recipe.marker.name).lowercased(),
                  seen.insert(name.lowercased()).inserted, records.count < recipe.expectedFiles else { throw ValidationIssue(.archiveMember, name) }
            if executable(name), machine(bytes) != expectedMachine(name, recipe: recipe) {
                throw ValidationIssue(.architecture, name, expected: Int(expectedMachine(name, recipe: recipe)), observed: Int(machine(bytes) ?? 0))
            }
            let hash = digest(bytes)
            if let key = recipe.keys.first(where: { recipe.prefix + $0.name == name }) {
                guard key.sha256 == hash else { throw ValidationIssue(.fileHash, name) }
                if let size = key.bytes, size != bytes.count { throw ValidationIssue(.fileSize, name, expected: size, observed: bytes.count) }
            }
            guard idle() else { throw Failure.active }
            let file = try destination(name, under: stage)
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try bytes.write(to: file, options: .withoutOverwriting)
            records.append(FileRecord(name: name, bytes: bytes.count, sha256: hash))
        }
        var selected: Data?
        do { try SteamRuntimeFiles.unpack(archive, limits: .trustedOfficialI386Browser) { name, bytes in
            if let member = package.singleMember {
                // Continue through every other member: unsafe metadata or a bad
                // CRC anywhere refuses the archive before the SDL file is saved.
                guard name == member else { return }
                guard selected == nil else { throw ValidationIssue(.archiveMember, member) }
                selected = bytes
            } else { try install(name, bytes) }
        } } catch SteamRuntimeFiles.Failure.invalidPackage { throw ValidationIssue(.archiveMetadata, package.file) }
        if let member = package.singleMember {
            guard let selected else { throw ValidationIssue(.missingFile, member, expected: 1, observed: 0) }
            try install(recipe.prefix + member, selected)
        }
    }

    static func checkOfficialRecords(recipe: Recipe, records: [FileRecord]) throws {
        // Fixture/custom recipes cannot emit the real native-ready contract.
        // That exact contract requires every immutable production recipe pin.
        guard recipe.marker.bytes != officialMarker.bytes || recipe == official else { throw Failure.invalid }
        guard records.count == recipe.expectedFiles else { throw ValidationIssue(.recordCount, expected: recipe.expectedFiles, observed: records.count) }
        var names = Set<String>(), total = 0
        for item in records {
            guard !item.generated, item.name.hasPrefix(recipe.prefix), SteamRuntimeFiles.validPath(item.name),
                  item.name.lowercased() != (recipe.prefix + recipe.marker.name).lowercased(),
                  names.insert(item.name.lowercased()).inserted,
                  item.bytes >= 0, item.bytes <= 256 * 1024 * 1024,
                  item.sha256.utf8.count == 64,
                  item.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw ValidationIssue(.recordInvalid, item.name)
            }
            total += item.bytes
            guard total <= 768 * 1024 * 1024 else { throw Failure.invalid }
        }
        for key in recipe.keys {
            guard records.contains(where: { record in record.name == recipe.prefix + key.name && record.sha256 == key.sha256
                && (key.bytes.map({ $0 == record.bytes }) ?? true) }) else {
                throw ValidationIssue(.keyRecord, recipe.prefix + key.name)
            }
        }
    }

    static func generatedRecord(recipe: Recipe) -> FileRecord {
        FileRecord(name: recipe.prefix + recipe.marker.name, bytes: recipe.marker.bytes.count,
                   sha256: recipe.marker.sha256, generated: true)
    }
    static func manifest(recipe: Recipe, records: [FileRecord]) throws -> Manifest {
        guard records.count == recipe.expectedFiles + 1 else {
            throw ValidationIssue(.recordCount, completion, expected: recipe.expectedFiles + 1, observed: records.count)
        }
        guard records.filter(\.generated) == [generatedRecord(recipe: recipe)] else {
            throw ValidationIssue(.generatedMarker, recipe.prefix + recipe.marker.name)
        }
        try checkOfficialRecords(recipe: recipe, records: records.filter { !$0.generated })
        guard records.reduce(0, { $0 + $1.bytes }) <= 768 * 1024 * 1024 else { throw Failure.invalid }
        return Manifest(format: 1, recipe: recipe.id, coreSHA256: recipe.coreSHA256, packages: recipe.packages,
                        files: records.sorted { $0.name < $1.name })
    }

    // A completion manifest is a transaction record, not an authentication
    // shortcut. Every file, its size, its architecture and the exact tree are
    // checked again before reuse. No ambient file is accepted into the cache.
    static func relativePath(_ target: URL, under root: URL, directory: Bool) throws -> String {
        // Darwin's enumerator can use the OS /var alias while its caller uses
        // /private/var, and directory URL hints can add a final slash. Compare
        // standardized filesystem paths before computing the relative suffix.
        var base = root.resolvingSymlinksInPath().standardizedFileURL.path
        while base.count > 1 && base.hasSuffix("/") { base.removeLast() }
        let full = target.resolvingSymlinksInPath().standardizedFileURL.path
        guard full.hasPrefix(base + "/") else { throw ValidationIssue(.relativePath) }
        var name = String(full.dropFirst(base.count + 1))
        if directory { while name.hasSuffix("/") { name.removeLast() } }
        guard SteamRuntimeFiles.validPath(name) else { throw ValidationIssue(.relativePath) }
        return name
    }
    static func validateTree(_ root: URL, recipe: Recipe, records: [FileRecord],
                             extraFiles: Set<String>, digest: DigestFile) throws {
        let fm = FileManager.default
        try plain(root, directory: true)
        var seen = Set<String>()
        for item in records {
            guard item.name.hasPrefix(recipe.prefix), item.bytes >= 0, item.bytes <= 256 * 1024 * 1024 else {
                throw ValidationIssue(.recordInvalid, item.name)
            }
            guard seen.insert(item.name.lowercased()).inserted else { throw ValidationIssue(.duplicateRecord, item.name) }
            let target = try destination(item.name, under: root)
            guard fm.fileExists(atPath: target.path) else { throw ValidationIssue(.missingFile, item.name, expected: 1, observed: 0) }
            // Links and aliased parents remain ownership errors, never rebuild
            // candidates. Canonicalizing enumeration does not adopt symlinks.
            let kind = try target.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard kind.isSymbolicLink != true else { throw Failure.ownership }
            guard kind.isRegularFile == true else { throw ValidationIssue(.fileType, item.name) }
            try plain(target, directory: false)
            let size = (try target.resourceValues(forKeys: [.fileSizeKey])).fileSize ?? -1
            guard size == item.bytes else { throw ValidationIssue(.fileSize, item.name, expected: item.bytes, observed: size) }
            if executable(item.name) {
                let observed = machine(try Data(contentsOf: target, options: .mappedIfSafe))
                guard observed == expectedMachine(item.name, recipe: recipe) else {
                    throw ValidationIssue(.architecture, item.name, expected: Int(expectedMachine(item.name, recipe: recipe)), observed: Int(observed ?? 0))
                }
            }
            guard try digest(target) == item.sha256 else { throw ValidationIssue(.fileHash, item.name) }
            if item.generated {
                guard item == generatedRecord(recipe: recipe),
                      try Data(contentsOf: target) == recipe.marker.bytes else { throw ValidationIssue(.generatedMarker, item.name) }
            }
        }
        var enumerationFailed = false
        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
                                             options: [], errorHandler: { _, _ in enumerationFailed = true; return false }) else {
            throw ValidationIssue(.enumeration)
        }
        var actual = Set<String>()
        let expected = Set(records.map(\.name)).union(extraFiles)
        for case let target as URL in enumerator {
            let value = try target.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard value.isSymbolicLink != true else { throw Failure.ownership }
            let relative = try relativePath(target, under: root, directory: value.isDirectory == true)
            if value.isDirectory == true {
                // Empty or unrelated directories do not belong to this tree.
                guard records.contains(where: { $0.name.hasPrefix(relative + "/") }) else {
                    throw ValidationIssue(.unexpectedDirectory, relative, expected: 0, observed: 1)
                }
            } else {
                guard expected.contains(relative) else {
                    throw ValidationIssue(.unexpectedFile, relative, expected: 0, observed: 1)
                }
                actual.insert(relative)
            }
        }
        guard !enumerationFailed else { throw ValidationIssue(.enumeration) }
        guard actual == expected else {
            throw ValidationIssue(.missingFile, expected.subtracting(actual).sorted().first ?? "", expected: expected.count, observed: actual.count)
        }
    }

    static func validate(_ root: URL, recipe: Recipe, digest: DigestFile) throws -> Prepared {
        try plain(root, directory: true)
        let file = try destination(completion, under: root)
        guard FileManager.default.fileExists(atPath: file.path) else { throw ValidationIssue(.missingFile, completion, expected: 1, observed: 0) }
        let kind = try file.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey])
        guard kind.isSymbolicLink != true else { throw Failure.ownership }
        guard kind.isRegularFile == true else { throw ValidationIssue(.fileType, completion) }
        try plain(file, directory: false)
        let size = (try file.resourceValues(forKeys: [.fileSizeKey])).fileSize ?? Int.max
        guard size <= 256 * 1024 else { throw ValidationIssue(.completionSize, completion, expected: 256 * 1024, observed: size) }
        let decoded: Manifest
        do { decoded = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: file)) }
        catch is DecodingError { throw ValidationIssue(.completionMalformed, completion) }
        let expected: Manifest
        do { expected = try manifest(recipe: recipe, records: decoded.files) }
        catch let issue as ValidationIssue { throw issue }
        catch {
            if decoded.files.count != recipe.expectedFiles + 1 {
                throw ValidationIssue(.recordCount, completion, expected: recipe.expectedFiles + 1, observed: decoded.files.count)
            }
            throw ValidationIssue(.recordInvalid, completion)
        }
        guard decoded == expected else { throw ValidationIssue(.completionMismatch, completion) }
        do { try validateTree(root, recipe: recipe, records: decoded.files, extraFiles: [completion], digest: digest) }
        catch let issue as ValidationIssue {
            throw ValidationIssue(issue.reason, issue.name, expected: issue.expected, observed: issue.observed, records: decoded.files.count)
        }
        let browser = try destination(String(recipe.prefix.dropLast()), under: root)
        return Prepared(helper: browser.appendingPathComponent("steamwebhelper.exe"), browserRoot: browser,
                        coreSHA256: recipe.coreSHA256, recipe: recipe.id)
    }

    static func reuse(_ final: URL, recipe: Recipe, digest: DigestFile, idle: () -> Bool,
                      report: (String) -> Void = { _ in }) throws -> Prepared? {
        guard idle() else { throw Failure.active }
        guard FileManager.default.fileExists(atPath: final.path) else { return nil }
        do { return try validate(final, recipe: recipe, digest: digest) }
        catch let issue as ValidationIssue {
            report(issue.diagnostic(phase: "reuse", recipe: recipe) + " action=rebuild-retain")
            return nil
        }
    }

    static func commit(stage: URL, destination final: URL, recipe: Recipe, records: [FileRecord],
                       digest: DigestFile, idle: () -> Bool, report: (String) -> Void = { _ in },
                       recheckCore: () throws -> Void) throws -> Prepared {
        let owner = final.deletingLastPathComponent()
        try plain(owner, directory: true); try plain(stage, directory: true)
        let marker = try destination(ownerName, under: owner)
        try plain(marker, directory: false)
        guard (try marker.resourceValues(forKeys: [.fileSizeKey])).fileSize == ownerBytes.count,
              try Data(contentsOf: marker) == ownerBytes,
              final.lastPathComponent == recipe.id,
              stage.deletingLastPathComponent().standardizedFileURL == owner.standardizedFileURL,
              stage.lastPathComponent.hasPrefix(".stage-") else { throw Failure.ownership }
        guard idle() else { throw Failure.active }
        // No generated marker exists until the complete official tree has been
        // rehashed and every executable/key pin and the exact tree have passed.
        try checkOfficialRecords(recipe: recipe, records: records)
        try validateTree(stage, recipe: recipe, records: records, extraFiles: [], digest: digest)
        try recheckCore()
        guard idle() else { throw Failure.active }
        let verified = try destination(recipe.prefix + recipe.marker.name, under: stage)
        try recipe.marker.bytes.write(to: verified, options: .withoutOverwriting)
        let value = try manifest(recipe: recipe, records: records + [generatedRecord(recipe: recipe)])
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(value).write(to: stage.appendingPathComponent(completion), options: .withoutOverwriting)
        _ = try validate(stage, recipe: recipe, digest: digest)
        try recheckCore()
        guard idle() else { throw Failure.active }
        let fm = FileManager.default
        guard final.standardizedFileURL.path == final.resolvingSymlinksInPath().standardizedFileURL.path else { throw Failure.ownership }
        var retained: URL?
        if fm.fileExists(atPath: final.path) {
            // The exact recipe path is inside our verified dedicated owner root.
            // Never adopt its bytes or touch it until the replacement is ready.
            try plain(final, directory: true)
            do {
                let existing = try validate(final, recipe: recipe, digest: digest)
                guard idle() else { throw Failure.active }
                return existing
            } catch let issue as ValidationIssue {
                guard idle() else { throw Failure.active }
                let backup = owner.appendingPathComponent(".retained-" + UUID().uuidString, isDirectory: true)
                try fm.moveItem(at: final, to: backup)
                retained = backup
                report(issue.diagnostic(phase: "retain", recipe: recipe) + " action=retained")
            }
        }
        do {
            guard idle() else { throw Failure.active }
            try fm.moveItem(at: stage, to: final)
        } catch {
            // No active process was admitted. Restore the previous name if the
            // publish failed; a crash between renames leaves the old tree in its
            // retained directory and the next invocation can prepare afresh.
            if let retained, !fm.fileExists(atPath: final.path) { try? fm.moveItem(at: retained, to: final) }
            throw error
        }
        return try validate(final, recipe: recipe, digest: digest)
    }
}

#if canImport(CryptoKit)
// This operation and the app's launch gate share the main actor. The caller
// must honor busy before starting Wine, Steam or a Steam-owned-library session.
// idle must check all four: Wine processes, wineserver, current Library launch,
// and SteamOwnedLibrary.shared.wineSessionActive. No Wine calls occur here.
@MainActor enum SteamBrowserRuntime {
    private(set) static var busy = false
    nonisolated static func hash(_ file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        var state = SHA256()
        while let bytes = try handle.read(upToCount: 1024 * 1024), !bytes.isEmpty {
            try Task.checkCancellation(); state.update(data: bytes)
        }
        return state.finalize().map { String(format: "%02x", $0) }.joined()
    }
    nonisolated private static func hashData(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    static func prepare(cacheBase: URL, steamRoot: URL, chromeHTML: URL,
                        idle: () -> Bool,
                        progress: @escaping (String) -> Void = { _ in },
                        download: ((SteamBrowserRuntimeFiles.Package) async throws -> URL)? = nil) async throws -> SteamBrowserRuntimeFiles.Prepared {
        typealias Files = SteamBrowserRuntimeFiles
        guard !busy, idle() else { throw Files.Failure.active }
        busy = true; defer { busy = false }
        let recipe = Files.official, fm = FileManager.default
        var phase = "core"
        do {
            progress("[steam-browser-cache-v4] phase=core recipe=\(recipe.id) action=begin")
            try Files.core(chromeHTML, steamRoot: steamRoot, recipe: recipe, digest: hash)
            phase = "owner"
            let root = try Files.ownerRoot(cacheBase: cacheBase, steamRoot: steamRoot, idle: idle)
            let final = try Files.destination(recipe.id, under: root)
            phase = "reuse"
            if let prepared = try Files.reuse(final, recipe: recipe, digest: hash, idle: idle, report: progress) {
                try Files.core(chromeHTML, steamRoot: steamRoot, recipe: recipe, digest: hash)
                guard idle() else { throw Files.Failure.active }
                progress("[steam-browser-cache-v4] phase=reuse recipe=\(recipe.id) action=verified records=\(recipe.expectedFiles + 1)")
                return prepared
            }
            phase = "stage"
            let stage = root.appendingPathComponent(".stage-" + UUID().uuidString)
            try fm.createDirectory(at: stage, withIntermediateDirectories: false)
            // Only this invocation's new stage can be cleaned up. Interrupted stages
            // and any completed or conflicting cache version are always retained.
            defer { if fm.fileExists(atPath: stage.path) { try? fm.removeItem(at: stage) } }
            var records: [Files.FileRecord] = []
            progress("[steam-browser-cache-v3] recipe=\(recipe.id) action=prepare")
            for (index, package) in recipe.packages.enumerated() {
                try Task.checkCancellation()
                progress("Preparing Steam browser (\(index + 1) of \(recipe.packages.count))…")
                phase = "download-\(index + 1)"
                do {
                    progress("[steam-browser-cache-v5] phase=download package=\(index + 1)/\(recipe.packages.count) action=start expected=\(package.bytes) attempt=1 automatic-retry=none")
                    let temporary: URL
                    if let download {
                        // Transport injection supplies bytes only. All production
                        // size/hash/archive/core/ownership checks below still run.
                        temporary = try await download(package)
                    } else {
                        let events = AsyncStream<Files.DownloadEvent>.makeStream()
                        let observer = Task { @MainActor in
                            for await event in events.stream {
                                progress(event.diagnostic(package: index + 1, count: recipe.packages.count))
                            }
                        }
                        do {
                            temporary = try await SteamBrowserDownload.download(package) { event in
                                events.continuation.yield(event)
                            }
                            events.continuation.finish(); await observer.value
                        } catch {
                            events.continuation.finish(); await observer.value
                            throw error
                        }
                    }
                    defer { try? fm.removeItem(at: temporary) }
                    guard idle() else { throw Files.Failure.active }
                    phase = "sha256-\(index + 1)"
                    progress("[steam-browser-cache-v5] phase=sha256 package=\(index + 1) action=begin expected=\(package.bytes)")
                    guard try hash(temporary) == package.sha256 else { throw Files.ValidationIssue(.archiveHash, package.file) }
                    progress("[steam-browser-cache-v5] phase=sha256 package=\(index + 1) action=verified")
                    phase = "extract-\(index + 1)"
                    progress("[steam-browser-cache-v5] phase=extract package=\(index + 1) action=begin")
                    let archive = try Data(contentsOf: temporary, options: .mappedIfSafe)
                    try Files.appendArchive(archive, package: package, recipe: recipe, stage: stage,
                                            records: &records, digest: hashData, idle: idle)
                    progress("[steam-browser-cache-v3] package=\(index + 1) stage=verified records=\(records.count)")
                } catch {
                    let issue = error as NSError
                    // Fixed stages and numeric codes only: no URLs, account data,
                    // response bodies or user paths are copied into diagnostics.
                    progress("[steam-browser-cache-v3] package=\(index + 1) stage=\(phase) result=failed code=\(issue.code)")
                    throw error
                }
            }
            try Task.checkCancellation()
            phase = "commit"
            progress("[steam-browser-cache-v5] phase=commit action=begin records=\(records.count)")
            let prepared = try Files.commit(stage: stage, destination: final, recipe: recipe, records: records,
                                    digest: hash, idle: idle, report: progress) {
                try Files.core(chromeHTML, steamRoot: steamRoot, recipe: recipe, digest: hash)
            }
            progress("[steam-browser-cache-v4] phase=commit recipe=\(recipe.id) action=verified records=\(recipe.expectedFiles + 1)")
            return prepared
        } catch {
            let issue: Files.ValidationIssue
            if let value = error as? Files.ValidationIssue { issue = value }
            else if error is CancellationError { issue = Files.ValidationIssue(.cancelled) }
            else if let failure = error as? Files.Failure {
                switch failure {
                case .active: issue = Files.ValidationIssue(.active)
                case .ownership: issue = Files.ValidationIssue(.ownership)
                case .changedCore: issue = Files.ValidationIssue(.changedCore)
                case .invalid: issue = Files.ValidationIssue(.recordInvalid)
                }
            } else { issue = Files.ValidationIssue(.filesystem) }
            progress(issue.diagnostic(phase: phase, recipe: recipe) + " action=failed code=\((error as NSError).code) retry=next-play previous-cache=retained")
            // Preserve our actionable public failures, but never let a raw
            // filesystem/network NSError leak private paths through the caller.
            if let failure = error as? Files.Failure { throw failure }
            if error is CancellationError { throw CancellationError() }
            throw issue
        }
    }
}

// Writes each network chunk directly to a new temporary file. A response with
// the wrong URL/status/length is refused before its body is accepted; a body
// exceeding the exact pinned byte count is cancelled without writing the chunk.
// Redirects, cookies, credentials, caches and compression are disabled.
private final class SteamBrowserDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let package: SteamBrowserRuntimeFiles.Package
    private let url: URL, temporary: URL, handle: FileHandle
    private let lock = NSLock()
    private var cancelled = false
    private var task: URLSessionDataTask?
    private var continuation: CheckedContinuation<URL, Error>?
    private var session: URLSession?
    private var accepted = false, received = 0
    private var failure: Error?
    private let report: @Sendable (SteamBrowserRuntimeFiles.DownloadEvent) -> Void
    private let started = ProcessInfo.processInfo.systemUptime
    private var progress = SteamBrowserRuntimeFiles.DownloadProgress()
    private var timer: DispatchSourceTimer?
    private var finished = false
    private init(_ package: SteamBrowserRuntimeFiles.Package,
                 report: @escaping @Sendable (SteamBrowserRuntimeFiles.DownloadEvent) -> Void) throws {
        self.package = package; self.report = report
        url = URL(string: SteamBrowserRuntimeFiles.origin + package.file)!
        temporary = FileManager.default.temporaryDirectory.appendingPathComponent("madeira-browser-" + UUID().uuidString + ".zip")
        try Data().write(to: temporary, options: .withoutOverwriting)
        do { handle = try FileHandle(forWritingTo: temporary) }
        catch { try? FileManager.default.removeItem(at: temporary); throw error }
    }
    static func download(_ package: SteamBrowserRuntimeFiles.Package,
                         progress: @escaping @Sendable (SteamBrowserRuntimeFiles.DownloadEvent) -> Void = { _ in }) async throws -> URL {
        let transfer = try SteamBrowserDownload(package, report: progress)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in transfer.start(continuation) }
        } onCancel: { transfer.cancel() }
    }
    private func start(_ next: CheckedContinuation<URL, Error>) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil; configuration.urlCredentialStorage = nil; configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 60; configuration.timeoutIntervalForResource = 900
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        let task = session.dataTask(with: request)
        lock.lock(); self.continuation = next; self.session = session; self.task = task
        let wasCancelled = cancelled; lock.unlock()
        report(event(.waiting))
        let heartbeat = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        heartbeat.schedule(deadline: .now() + 15, repeating: 15)
        heartbeat.setEventHandler { [weak self, weak queue] in
            guard let self, let queue else { return }
            queue.addOperation { [weak self] in self?.reportProgress() }
        }
        timer = heartbeat; heartbeat.resume()
        task.resume(); if wasCancelled { task.cancel() }
    }
    private func event(_ phase: SteamBrowserRuntimeFiles.DownloadEvent.Phase, code: Int = 0,
                       retryable: Bool = false) -> SteamBrowserRuntimeFiles.DownloadEvent {
        let elapsed = max(0, min(900_000_000, (ProcessInfo.processInfo.systemUptime - started) * 1000))
        return .init(phase, received: received, expected: package.bytes, elapsedMS: Int(elapsed), code: code, retryable: retryable)
    }
    private func reportProgress() {
        guard !finished else { return }
        let value = event(accepted ? .receiving : .waiting)
        if progress.shouldReport(received: received, expected: package.bytes, elapsedMS: value.elapsedMS) { report(value) }
    }
    private func cancel() { lock.lock(); cancelled = true; let current = task; lock.unlock(); current?.cancel() }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        typealias Files = SteamBrowserRuntimeFiles
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            failure = Files.ValidationIssue(.responseStatus, package.file, expected: 200, observed: (response as? HTTPURLResponse)?.statusCode ?? -1)
            completionHandler(.cancel); return
        }
        guard http.url == url,
              url.scheme == "https", url.host == "client-update.akamai.steamstatic.com",
              url.port == nil, url.user == nil, url.password == nil else {
            failure = Files.ValidationIssue(.responseURL, package.file); completionHandler(.cancel); return
        }
        guard response.expectedContentLength == Int64(package.bytes) else {
            failure = Files.ValidationIssue(.responseLength, package.file, expected: package.bytes, observed: Int(response.expectedContentLength))
            completionHandler(.cancel); return
        }
        guard http.value(forHTTPHeaderField: "Content-Encoding").map({ $0.lowercased() == "identity" }) ?? true else {
            failure = Files.ValidationIssue(.responseEncoding, package.file); completionHandler(.cancel); return
        }
        accepted = true; report(event(.response, code: http.statusCode)); completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard accepted, data.count <= package.bytes - received else {
            failure = SteamBrowserRuntimeFiles.ValidationIssue(.bodyLength, package.file, expected: package.bytes, observed: received + data.count)
            dataTask.cancel(); return
        }
        do { try handle.write(contentsOf: data); received += data.count; reportProgress() }
        catch { failure = error; dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finished = true; timer?.cancel(); timer = nil
        do { try handle.close() } catch { failure = error }
        lock.lock(); let next = continuation; continuation = nil; let wasCancelled = cancelled; lock.unlock()
        let issue: Error? = wasCancelled ? CancellationError() : (failure ?? error)
        if let issue {
            let native = issue as NSError
            let retryable = native.domain == NSURLErrorDomain && [NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost, NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost].contains(native.code)
            report(event(wasCancelled ? .cancelled : .failed, code: native.code, retryable: retryable))
            try? FileManager.default.removeItem(at: temporary); next?.resume(throwing: issue)
        }
        else if !accepted || received != package.bytes {
            try? FileManager.default.removeItem(at: temporary)
            report(event(.failed))
            next?.resume(throwing: SteamBrowserRuntimeFiles.ValidationIssue(.bodyLength, package.file, expected: package.bytes, observed: received))
        } else { report(event(.completed)); next?.resume(returning: temporary) }
        session.finishTasksAndInvalidate(); self.session = nil
    }
}
#endif
