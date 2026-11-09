// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 125hz
// Madeira Converter Exception: see LICENSE-EXCEPTION.md

import Foundation
import CommonCrypto
#if canImport(Security)
import Security
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A bounded comparison with the exact installed depot's cached manifest.
/// This is diagnostic only: cache provenance/signature trust is not established
/// by a hash comparison, and it cannot decide Steam authentication or VAC.
/// No game, registry, manifest, prefix or journal is ever written here.
enum SteamContentIntegrity {
    struct Limits: Sendable {
        var maxFiles = 16
        var maxBytes: UInt64 = 384 << 20
        var maxSeconds: TimeInterval = 6
    }

    struct Finding: Sendable {
        let relative: String       // only a literal from criticalPaths below
        let state: String
        let bytes: UInt64
        let certificate: String
        var packageSignature = "not-vpk"
        var packageDetails = ""
        var currentSHA1 = "unmeasured"
        var referenceSHA1 = "unavailable"
        var line: String {
            let extra = relative.hasSuffix("_dir.vpk")
                ? " \(packageDetails) current-sha1=\(currentSHA1) reference-sha1=\(referenceSHA1) hash-source=\(currentSHA1 == "unmeasured" ? "unmeasured" : "current-file-read")" : ""
            return "[steam-content-audit-v1] app=730 relative=\(relative) state=\(state) bytes=\(bytes) certificate=\(certificate) vpk-signature=\(packageSignature)\(extra) trust=unmeasured"
        }
    }

    struct Report: Sendable {
        var state = "unmeasured"
        var depots = 0
        var references = 0
        var bytes: UInt64 = 0
        var findings: [Finding] = []
        var lines: [String] {
            ["[steam-content-audit-v1] app=730 phase=summary state=\(state) installed-depots=\(depots) cached-references=\(references) files=\(findings.count) bytes=\(bytes) reference=installed-cache authentication=not-revalidated trust=unmeasured"] + findings.map(\.line)
        }
    }

    // Fixed application-relative names make exported reports private by
    // construction. Nothing from an account, mod path or arbitrary manifest
    // filename is interpolated into them. Numbered VPKs are not PE files and
    // are never called unsigned just because they have no PE certificate.
    static let criticalPaths = [
        "game/bin/win64/cs2.exe", "game/bin/win64/tier0.dll",
        "game/bin/win64/engine2.dll", "game/bin/win64/filesystem_stdio.dll",
        "game/bin/win64/rendersystemdx11.dll", "game/bin/win64/steam_api64.dll",
        "game/bin/win64/steamnetworkingsockets.dll",
        "game/csgo/bin/win64/client.dll", "game/csgo/bin/win64/server.dll",
        "game/csgo/pak01_dir.vpk", "game/core/pak01_dir.vpk"
    ]

    /// Run off the main actor while no install/repair is writing the tree.
    /// Absent/encrypted/malformed references and budget limits remain explicit
    /// unknowns. A session gate is checked between reads so a scheduled idle
    /// diagnostic stops when Steam/Wine begins. It never delays their launch.
    static func auditCS2(steamApps: URL, installURL: URL, limits: Limits = Limits(),
                         shouldContinue: @Sendable () -> Bool = { true }) -> Report {
        var result = Report()
        let start = ProcessInfo.processInfo.systemUptime
        guard shouldContinue() else { result.state = "stopped-unmeasured"; return result }
        guard limits.maxFiles > 0, limits.maxFiles <= 64, limits.maxBytes > 0,
              limits.maxSeconds.isFinite, limits.maxSeconds > 0,
              let record = readBounded(root: steamApps, relative: "appmanifest_730.acf", maximum: 4 << 20, shouldContinue: shouldContinue),
              var parser = try? SteamKeyValues(record), let tree = try? parser.read(),
              let app = tree["AppState"], app["appid"]?.string == "730" else {
            result.state = shouldContinue() ? "install-record-unavailable" : "stopped-unmeasured"; return result
        }
        let installed = (app["InstalledDepots"]?.fields ?? [:]).compactMap { name, entry -> (UInt32, UInt64)? in
            guard let depot = UInt32(name), let text = entry["manifest"]?.string, let gid = UInt64(text), gid > 0 else { return nil }
            return (depot, gid)
        }.sorted { $0.0 < $1.0 }
        guard !installed.isEmpty, installed.count <= 64 else { result.state = "depot-record-unavailable"; return result }
        result.depots = installed.count
        var entries: [String: DepotManifest.FileEntry] = [:]
        var conflicting = Set<String>()
        let roots = [steamApps.appendingPathComponent("depotcache", isDirectory: true),
                     steamApps.deletingLastPathComponent().appendingPathComponent("depotcache", isDirectory: true)]
        for (depot, gid) in installed {
            guard shouldContinue(), ProcessInfo.processInfo.systemUptime - start < limits.maxSeconds else { break }
            let name = "\(depot)_\(gid).manifest"
            var payload: Data?
            for cache in roots {
                if let data = readBounded(root: cache, relative: name, maximum: 16 << 20, shouldContinue: shouldContinue) { payload = data; break }
            }
            guard let payload, let manifest = try? DepotManifest.parse(depotID: depot, manifestGID: gid, data: payload) else { continue }
            result.references += 1
            for file in manifest.files {
                let name = file.filename.lowercased()
                guard criticalPaths.contains(name), !file.isDirectory, file.flags & 0x200 == 0 else { continue }
                if let previous = entries[name], previous.size != file.size || previous.contentSHA1 != file.contentSHA1 {
                    conflicting.insert(name)
                } else { entries[name] = file }
            }
        }
        guard shouldContinue() else { result.state = "stopped-unmeasured"; return result }
        let rootFD = open(installURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard rootFD >= 0 else { result.state = "install-tree-unavailable"; return result }
        defer { close(rootFD) }
        result.state = "bounded-comparison"
        for relative in criticalPaths.prefix(limits.maxFiles) {
            guard shouldContinue() else {
                result.state = "stopped-unmeasured"
                result.findings.append(Finding(relative: relative, state: "stopped-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            if ProcessInfo.processInfo.systemUptime - start >= limits.maxSeconds {
                result.findings.append(Finding(relative: relative, state: "time-budget-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            // Container presence/bounds can be measured without a hash
            // reference. It never supplies the missing expected content or
            // establishes cryptographic signature validity.
            let fd = openRelative(rootFD, relative)
            defer { if fd >= 0 { close(fd) } }
            var before = stat()
            let readable = fd >= 0 && fstat(fd, &before) == 0 && before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.st_size >= 0
            var certificate = readable && (relative.hasSuffix(".dll") || relative.hasSuffix(".exe"))
                ? peCertificate(fd, size: UInt64(before.st_size), shouldContinue: shouldContinue) : "unmeasured"
            let available = limits.maxBytes - min(result.bytes, limits.maxBytes)
            let reserveSHA1 = readable ? min(UInt64(before.st_size), available) : 0
            var package = readable && relative.hasSuffix("_dir.vpk")
                ? vpkSignature(fd, size: UInt64(before.st_size), byteBudget: available - reserveSHA1,
                               deadline: start + limits.maxSeconds, shouldContinue: shouldContinue) : VPKObservation()
            result.bytes += package.readBytes
            var metadataAfter = stat()
            if readable && (fstat(fd, &metadataAfter) != 0 || !unchanged(before, metadataAfter)) {
                certificate = "changed-unmeasured"; package.changed()
            }
            guard shouldContinue() else {
                result.state = "stopped-unmeasured"
                result.findings.append(Finding(relative: relative, state: "stopped-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            func finding(_ state: String, _ bytes: UInt64 = 0, _ current: Data? = nil, _ reference: Data? = nil) -> Finding {
                func hex(_ data: Data?, unknown: String) -> String { data.map { $0.map { String(format: "%02x", $0) }.joined() } ?? unknown }
                return Finding(relative: relative, state: state, bytes: bytes,
                               certificate: relative.hasSuffix(".vpk") ? "not-pe" : certificate,
                               packageSignature: package.state, packageDetails: package.fields,
                               currentSHA1: hex(current, unknown: "unmeasured"), referenceSHA1: hex(reference, unknown: "unavailable"))
            }
            guard !conflicting.contains(relative), let file = entries[relative] else {
                result.findings.append(finding(conflicting.contains(relative) ? "reference-conflict" : "reference-unavailable")); continue
            }
            // Valve customizes CustomExecutable files per user; a depot hash
            // is not a valid expected installed hash for these files.
            guard file.flags & DepotManifest.customExecutableFlag == 0 else {
                result.findings.append(finding("steam-customized-unmeasured")); continue
            }
            guard let expected = file.contentSHA1, expected.count == Int(CC_SHA1_DIGEST_LENGTH) else {
                result.findings.append(finding("file-hash-unavailable")); continue
            }
            guard file.size <= limits.maxBytes - min(result.bytes, limits.maxBytes) else {
                result.findings.append(finding("byte-budget-unmeasured")); continue
            }
            guard readable else { result.findings.append(finding("file-unavailable")); continue }
            guard UInt64(before.st_size) == file.size else {
                result.findings.append(finding("size-mismatch")); continue
            }
            let hashed = hash(fd, size: file.size, deadline: start + limits.maxSeconds, shouldContinue: shouldContinue)
            result.bytes += hashed.bytes
            var after = stat()
            let stable = fstat(fd, &after) == 0 && unchanged(before, after)
            let state: String
            if !shouldContinue() { state = "stopped-unmeasured"; result.state = state }
            else if !stable { state = "changed-during-read"; package.changed() }
            else if let digest = hashed.digest { state = digest == expected ? "cache-hash-match" : "cache-hash-mismatch" }
            else { state = "read-incomplete-unmeasured" }
            result.findings.append(finding(state, hashed.bytes, stable && shouldContinue() ? hashed.digest : nil, expected))
        }
        return result
    }

    /// Resolve a Windows path only when each component is exact or has one
    /// case-insensitive spelling. Never traverse a symlink or ambiguous case
    /// collision. openat pins each parent while walking the tree.
    private static func openRelative(_ rootFD: Int32, _ relative: String) -> Int32 {
        let parts = relative.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\\") && !$0.contains(":") }) else { return -1 }
        var current = dup(rootFD)
        guard current >= 0 else { return -1 }
        for (index, part) in parts.enumerated() {
            let flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | (index < parts.count - 1 ? O_DIRECTORY : 0)
            var next = openat(current, part, flags)
            if next < 0, errno == ENOENT {
                // fdopendir owns its descriptor; duplicate so the pinned
                // parent remains valid for the following openat.
                if let directory = fdopendir(dup(current)) {
                    var names: [String] = []
                    var visited = 0
                    while let entry = readdir(directory) {
                        visited += 1
                        if visited > 4096 { names.removeAll(); break }
                        let capacity = MemoryLayout.size(ofValue: entry.pointee.d_name)
                        let name = withUnsafePointer(to: &entry.pointee.d_name) {
                            $0.withMemoryRebound(to: CChar.self, capacity: capacity) { String(cString: $0) }
                        }
                        if name.lowercased() == part.lowercased() { names.append(name) }
                    }
                    closedir(directory)
                    if names.count == 1 { next = openat(current, names[0], flags) }
                }
            }
            close(current)
            guard next >= 0 else { return -1 }
            current = next
        }
        return current
    }

    private static func readBounded(root: URL, relative: String, maximum: Int, shouldContinue: () -> Bool) -> Data? {
        let rootFD = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard rootFD >= 0 else { return nil }
        defer { close(rootFD) }
        let fd = openRelative(rootFD, relative)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_size >= 0, before.st_size <= off_t(maximum) else { return nil }
        var data = Data(count: Int(before.st_size))
        var offset = 0
        while offset < data.count {
            guard shouldContinue() else { return nil }
            let count = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress! + offset, min(1 << 20, $0.count - offset), off_t(offset)) }
            guard count > 0 else { return nil }
            offset += count
        }
        var after = stat()
        guard fstat(fd, &after) == 0, unchanged(before, after) else { return nil }
        return data
    }

    private static func unchanged(_ a: stat, _ b: stat) -> Bool {
        guard a.st_dev == b.st_dev, a.st_ino == b.st_ino, a.st_size == b.st_size else { return false }
        #if canImport(Darwin)
        return a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
               a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
        #else
        return a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
               a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec
        #endif
    }

    private static func hash(_ fd: Int32, size: UInt64, deadline: TimeInterval, shouldContinue: () -> Bool) -> (digest: Data?, bytes: UInt64) {
        var context = CC_SHA1_CTX()
        CC_SHA1_Init(&context)
        var bytes: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while bytes < size {
            guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline else { return (nil, bytes) }
            let wanted = Int(min(UInt64(buffer.count), size - bytes))
            let got = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, wanted, off_t(bytes)) }
            guard got > 0 else { return (nil, bytes) }
            buffer.withUnsafeBytes { _ = CC_SHA1_Update(&context, $0.baseAddress, CC_LONG(got)) }
            bytes += UInt64(got)
        }
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1_Final(&digest, &context)
        return (Data(digest), bytes)
    }

    /// PE security-directory bounds/presence only, not certificate validation.
    /// The directory address is a FILE OFFSET, never an image RVA.
    private static func peCertificate(_ fd: Int32, size: UInt64, shouldContinue: () -> Bool) -> String {
        func read(_ offset: UInt64, _ count: Int) -> Data? {
            guard shouldContinue(), offset <= size, UInt64(count) <= size - offset else { return nil }
            var bytes = Data(count: count)
            let got = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(offset)) }
            return got == count ? bytes : nil
        }
        func u16(_ d: Data, _ i: Int) -> UInt16 { UInt16(d[i]) | UInt16(d[i + 1]) << 8 }
        func u32(_ d: Data, _ i: Int) -> UInt32 { UInt32(u16(d, i)) | UInt32(u16(d, i + 2)) << 16 }
        guard let dos = read(0, 64), dos[0] == 0x4d, dos[1] == 0x5a,
              let coff = read(UInt64(u32(dos, 60)), 24), coff.starts(with: [0x50, 0x45, 0, 0]) else { return "not-pe" }
        let optionalOffset = UInt64(u32(dos, 60)) + 24
        guard let optional = read(optionalOffset, Int(u16(coff, 20))), optional.count >= 2 else { return "pe-header-invalid" }
        let dirStart: Int
        switch u16(optional, 0) { case 0x10b: dirStart = 96; case 0x20b: dirStart = 112; default: return "pe-header-invalid" }
        guard optional.count >= dirStart + 40, u32(optional, dirStart - 4) > 4 else { return "absent" }
        let offset = UInt64(u32(optional, dirStart + 32)), length = UInt64(u32(optional, dirStart + 36))
        if offset == 0 && length == 0 { return "absent" }
        guard offset > 0, offset % 8 == 0, length >= 8, offset <= size, length <= size - offset else { return "table-out-of-file" }
        guard length <= 1 << 20 else { return "table-limit-unmeasured" }
        var cursor: UInt64 = 0
        var records = 0
        while cursor < length {
            records += 1
            guard shouldContinue(), records <= 32 else { return "table-limit-unmeasured" }
            guard length - cursor >= 8, let header = read(offset + cursor, 8) else { return "table-invalid" }
            let record = UInt64(u32(header, 0))
            guard record > 8, record <= length - cursor, u16(header, 4) == 0x200, u16(header, 6) == 2 else { return "table-invalid" }
            let rounded = (record + 7) & ~UInt64(7)
            guard rounded <= length - cursor else { return "table-invalid" }
            cursor += rounded
        }
        return "table-present-unverified"
    }

    /// Bounded container observations, never a Valve-key or VAC verdict.
    private struct VPKObservation {
        var state = "not-vpk"
        var reason = "not-vpk"
        var format = "unknown"
        var version: UInt32?
        var type: UInt32?
        var reserved: UInt32?
        var offset: UInt64?
        var declared: UInt64?
        var keyBytes: UInt64?
        var signatureBytes: UInt64?
        var trailerBytes: UInt64?
        var treeBytes: UInt64?
        var tableOffset: UInt64?
        var tableBytes: UInt64?
        var otherOffset: UInt64?
        var otherBytes: UInt64?
        var treeMD5 = "unmeasured"
        var tableMD5 = "unmeasured"
        var wholeMD5 = "unmeasured"
        var crypto = "unmeasured"
        var readBytes: UInt64 = 0
        var fields: String {
            func n<T>(_ value: T?) -> String { value.map { String(describing: $0) } ?? "unmeasured" }
            return "vpk-format=\(format) vpk-version=\(n(version)) vpk-type=\(n(type)) vpk-reserved=\(n(reserved)) vpk-offset=\(n(offset)) vpk-declared=\(n(declared)) vpk-key-bytes=\(n(keyBytes)) vpk-signature-bytes=\(n(signatureBytes)) vpk-trailing-bytes=\(n(trailerBytes)) vpk-tree-bytes=\(n(treeBytes)) vpk-table-offset=\(n(tableOffset)) vpk-table-bytes=\(n(tableBytes)) vpk-other-offset=\(n(otherOffset)) vpk-other-bytes=\(n(otherBytes)) vpk-reason=\(reason) vpk-tree-md5=\(treeMD5) vpk-table-md5=\(tableMD5) vpk-whole-md5=\(wholeMD5) vpk-crypto=\(crypto) vpk-extra-read-bytes=\(readBytes) key-provenance=embedded-untrusted archive-payloads=not-read vac=unclaimed"
        }
        mutating func changed() {
            state = "changed-unmeasured"; reason = "changed-during-read"
            treeMD5 = "unmeasured"; tableMD5 = "unmeasured"; wholeMD5 = "unmeasured"; crypto = "unmeasured"
        }
    }

    /// The modern descriptor's declared size is 20 bytes. Its key and
    /// signature follow that descriptor OUTSIDE the declared section size.
    /// Layout/preimages: pinned ValvePak 037f25e Package.Read/Verify.cs; see
    /// docs/STEAM_VPK_SIGNATURE_DIAGNOSTICS.md. No embedded key is trusted.
    private static func vpkSignature(_ fd: Int32, size: UInt64, byteBudget: UInt64,
                                     deadline: TimeInterval, shouldContinue: () -> Bool) -> VPKObservation {
        var observation = VPKObservation()
        func finish(_ state: String, _ reason: String) -> VPKObservation {
            observation.state = state; observation.reason = reason; return observation
        }
        func read(_ offset: UInt64, _ count: Int) -> Data? {
            guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline,
                  offset <= size, count >= 0, UInt64(count) <= size - offset else { return nil }
            var bytes = Data(count: count)
            let got = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(offset)) }
            return got == count ? bytes : nil
        }
        func u32(_ data: Data, _ offset: Int) -> UInt32 {
            UInt32(data[offset]) | UInt32(data[offset + 1]) << 8 |
                UInt32(data[offset + 2]) << 16 | UInt32(data[offset + 3]) << 24
        }
        guard let first = read(0, 12) else { return finish("header-unmeasured", "header-unreadable") }
        observation.version = u32(first, 4)
        guard u32(first, 0) == 0x55aa1234 else { return finish("header-invalid", "header-magic") }
        if observation.version == 1 { return finish("v1-section-unavailable", "v1-no-signature-section") }
        guard observation.version == 2 else { return finish("format-unsupported-unmeasured", "version-unsupported") }
        guard let header = read(0, 28) else { return finish("header-unmeasured", "v2-header-unreadable") }
        let treeSize = UInt64(u32(header, 8)), dataSize = UInt64(u32(header, 12))
        let tableSize = UInt64(u32(header, 16)), otherSize = UInt64(u32(header, 20))
        let tableOffset = UInt64(28) + treeSize + dataSize
        let otherOffset = tableOffset + tableSize
        let signatureStart = otherOffset + otherSize
        let declared = UInt64(u32(header, 24))
        observation.offset = signatureStart; observation.declared = declared
        observation.treeBytes = treeSize; observation.tableOffset = tableOffset; observation.tableBytes = tableSize
        observation.otherOffset = otherOffset; observation.otherBytes = otherSize
        guard signatureStart <= size, declared <= size - signatureStart else { return finish("section-out-of-file", "declared-section-bounds") }
        if declared == 0 { return finish("absent", "no-signature-section") }
        guard declared >= 4, let firstWord = read(signatureStart, 4) else { return finish("section-invalid", "length-field-unreadable") }
        let marker = u32(firstWord, 0)
        var keyOffset: UInt64, signatureOffset: UInt64, keyLength: UInt64, signatureLength: UInt64
        if marker == 0x55aa1234 {
            observation.format = "descriptor20"
            guard declared == 20 else { return finish("format-unsupported-unmeasured", "descriptor-size-unsupported") }
            guard let descriptor = read(signatureStart, 20) else { return finish("section-invalid", "descriptor-truncated") }
            observation.type = u32(descriptor, 4); observation.reserved = u32(descriptor, 16)
            keyLength = UInt64(u32(descriptor, 8)); signatureLength = UInt64(u32(descriptor, 12))
            observation.keyBytes = keyLength; observation.signatureBytes = signatureLength
            guard keyLength < 0x80000000, signatureLength < 0x80000000 else { return finish("section-invalid", "negative-length") }
            // Only type 1's descriptor/preimage is independently exercised by
            // the signed CS2 reference. Unknown/reserved forms stay unknown.
            guard observation.type == 1 else { return finish("format-unsupported-unmeasured", "descriptor-type-unsupported") }
            guard observation.reserved == 0 else { return finish("format-unsupported-unmeasured", "reserved-unsupported") }
            keyOffset = signatureStart + 20
            guard keyLength <= size - keyOffset else { return finish("section-out-of-file", "descriptor-key-truncated") }
            signatureOffset = keyOffset + keyLength
            guard signatureLength <= size - signatureOffset else { return finish("section-out-of-file", "descriptor-signature-truncated") }
        } else {
            observation.format = "legacy-inline"; observation.type = 0
            keyLength = UInt64(marker); observation.keyBytes = keyLength
            guard keyLength < 0x80000000 else { return finish("section-invalid", "negative-length") }
            guard declared >= 8, keyLength <= declared - 8 else { return finish("section-invalid", "legacy-key-bounds") }
            keyOffset = signatureStart + 4
            guard let lengthWord = read(keyOffset + keyLength, 4) else { return finish("section-invalid", "legacy-signature-length-unreadable") }
            signatureLength = UInt64(u32(lengthWord, 0)); observation.signatureBytes = signatureLength
            guard signatureLength < 0x80000000 else { return finish("section-invalid", "negative-length") }
            guard 8 + keyLength + signatureLength == declared else { return finish("section-invalid", "legacy-payload-bounds") }
            signatureOffset = keyOffset + keyLength + 4
        }
        let end = signatureOffset + signatureLength
        observation.trailerBytes = size - end
        guard end == size else { return finish("format-unsupported-unmeasured", "trailing-bytes-unsupported") }
        guard keyLength <= 16384, signatureLength <= 16384 else { return finish("length-limit-unmeasured", "audit-key-signature-limit") }
        let unsigned = keyLength == 0 && signatureLength == 0
        guard unsigned || (keyLength > 0 && signatureLength > 0) else { return finish("section-incomplete-unmeasured", "unpaired-key-signature") }
        observation.state = unsigned ? "absent" : "section-present-unverified"
        observation.reason = unsigned ? "descriptor-without-signature" : "bounded-known-layout"

        // No numbered archive payloads are read. These are the three hashes
        // stored in the directory file's OtherMD5 block, from current bytes.
        guard otherSize >= 48, let expected = read(otherOffset, 48) else {
            observation.crypto = "checksum-preimage-unavailable"; return observation
        }
        let md5Cost = treeSize + tableSize + otherOffset + 32
        let shaCost: UInt64 = observation.format == "legacy-inline" && !unsigned ? signatureStart : 0
        guard md5Cost <= byteBudget, shaCost <= byteBudget - md5Cost else {
            observation.crypto = "byte-budget-unmeasured"; return observation
        }
        func digest(_ offset: UInt64, _ length: UInt64, sha256: Bool = false) -> Data? {
            let result = hashRange(fd, offset: offset, size: length, sha256: sha256,
                                   deadline: deadline, shouldContinue: shouldContinue)
            observation.readBytes += result.bytes
            return result.digest
        }
        guard let tree = digest(28, treeSize), let table = digest(tableOffset, tableSize),
              let whole = digest(0, otherOffset + 32) else {
            observation.crypto = "read-incomplete-unmeasured"; return observation
        }
        observation.treeMD5 = tree == expected.subdata(in: 0..<16) ? "match" : "mismatch"
        observation.tableMD5 = table == expected.subdata(in: 16..<32) ? "match" : "mismatch"
        observation.wholeMD5 = whole == expected.subdata(in: 32..<48) ? "match" : "mismatch"
        if unsigned { observation.crypto = "absent"; return observation }
        let signedDigest: Data
        if observation.format == "descriptor20" {
            guard observation.wholeMD5 == "match" else { observation.crypto = "preimage-checksum-mismatch"; return observation }
            var bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            whole.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(whole.count), &bytes) }
            signedDigest = Data(bytes)
        } else {
            guard let value = digest(0, signatureStart, sha256: true) else { observation.crypto = "read-incomplete-unmeasured"; return observation }
            signedDigest = value
        }
        guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline,
              let key = read(keyOffset, Int(keyLength)), let signature = read(signatureOffset, Int(signatureLength)) else {
            observation.crypto = "read-incomplete-unmeasured"; return observation
        }
        observation.crypto = rsaConsistency(spki: key, signature: signature, digest: signedDigest)
        return observation
    }

    private static func hashRange(_ fd: Int32, offset: UInt64, size: UInt64, sha256: Bool,
                                  deadline: TimeInterval, shouldContinue: () -> Bool) -> (digest: Data?, bytes: UInt64) {
        var md5 = CC_MD5_CTX(), sha = CC_SHA256_CTX()
        if sha256 { CC_SHA256_Init(&sha) } else { CC_MD5_Init(&md5) }
        var bytes: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while bytes < size {
            guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline else { return (nil, bytes) }
            let wanted = Int(min(UInt64(buffer.count), size - bytes))
            let got = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, wanted, off_t(offset + bytes)) }
            guard got > 0 else { return (nil, bytes) }
            buffer.withUnsafeBytes {
                if sha256 { _ = CC_SHA256_Update(&sha, $0.baseAddress, CC_LONG(got)) }
                else { _ = CC_MD5_Update(&md5, $0.baseAddress, CC_LONG(got)) }
            }
            bytes += UInt64(got)
        }
        var digest = [UInt8](repeating: 0, count: sha256 ? Int(CC_SHA256_DIGEST_LENGTH) : Int(CC_MD5_DIGEST_LENGTH))
        if sha256 { CC_SHA256_Final(&digest, &sha) } else { CC_MD5_Final(&digest, &md5) }
        return (Data(digest), bytes)
    }

    /// Extract only an RSA SubjectPublicKeyInfo's PKCS#1 public-key object.
    /// SecKey's RSA external representation is PKCS#1, not the SPKI wrapper.
    private static func rsaPKCS1(_ data: Data) -> Data? {
        let bytes = [UInt8](data)
        func item(_ position: inout Int, _ end: Int, _ tag: UInt8) -> Range<Int>? {
            guard position + 2 <= end, bytes[position] == tag else { return nil }
            position += 1
            let first = Int(bytes[position]); position += 1
            var length = first
            if first & 0x80 != 0 {
                let count = first & 0x7f
                guard count > 0, count <= 4, count <= end - position, bytes[position] != 0 else { return nil }
                length = 0
                for _ in 0..<count { length = length << 8 | Int(bytes[position]); position += 1 }
                guard length >= 128 else { return nil }
            }
            guard length <= end - position else { return nil }
            let range = position..<(position + length); position += length; return range
        }
        var position = 0
        guard let sequence = item(&position, bytes.count, 0x30), position == bytes.count else { return nil }
        var inside = sequence.lowerBound
        guard let algorithm = item(&inside, sequence.upperBound, 0x30) else { return nil }
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        let algorithmBytes = Array(bytes[algorithm])
        guard algorithmBytes == rsaOID || algorithmBytes == rsaOID + [0x05, 0] else { return nil }
        guard let bits = item(&inside, sequence.upperBound, 0x03), inside == sequence.upperBound,
              bits.count > 1, bytes[bits.lowerBound] == 0 else { return nil }
        let start = bits.lowerBound + 1
        var key = start
        guard let integers = item(&key, bits.upperBound, 0x30), key == bits.upperBound else { return nil }
        var integer = integers.lowerBound
        guard let modulus = item(&integer, integers.upperBound, 0x02), !modulus.isEmpty,
              let exponent = item(&integer, integers.upperBound, 0x02), !exponent.isEmpty,
              integer == integers.upperBound, bytes[modulus.lowerBound] & 0x80 == 0,
              bytes[exponent.lowerBound] & 0x80 == 0 else { return nil }
        for value in [modulus, exponent] {
            if value.count > 1 && bytes[value.lowerBound] == 0 && bytes[value.lowerBound + 1] & 0x80 == 0 { return nil }
            guard bytes[value].contains(where: { $0 != 0 }) else { return nil }
        }
        return Data(bytes[start..<bits.upperBound])
    }

    private static func rsaConsistency(spki: Data, signature: Data, digest: Data) -> String {
        guard let pkcs1 = rsaPKCS1(spki) else { return "key-format-unmeasured" }
        #if canImport(Security)
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        defer { error?.release() }
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &error) else { return "key-import-unmeasured" }
        let algorithm = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else { return "algorithm-unavailable" }
        return SecKeyVerifySignature(key, algorithm, digest as CFData, signature as CFData, &error)
            ? "consistent-embedded-key" : "mismatch-embedded-key"
        #else
        return "platform-api-unavailable"
        #endif
    }
}
