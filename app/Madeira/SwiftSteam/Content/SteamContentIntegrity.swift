// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 125hz
// Madeira Converter Exception: see LICENSE-EXCEPTION.md

import Foundation
import CommonCrypto
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
    struct Limits {
        var maxFiles = 16
        var maxBytes: UInt64 = 384 << 20
        var maxSeconds: TimeInterval = 6
    }

    struct Finding {
        let relative: String       // only a literal from criticalPaths below
        let state: String
        let bytes: UInt64
        let certificate: String
        var line: String {
            "[steam-content-audit-v1] app=730 relative=\(relative) state=\(state) bytes=\(bytes) certificate=\(certificate) trust=unmeasured"
        }
    }

    struct Report {
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
    /// unknowns. It does not download or silently repair a current install.
    static func auditCS2(steamApps: URL, installURL: URL, limits: Limits = Limits()) -> Report {
        var result = Report()
        let start = ProcessInfo.processInfo.systemUptime
        guard limits.maxFiles > 0, limits.maxFiles <= 64, limits.maxBytes > 0,
              limits.maxSeconds.isFinite, limits.maxSeconds > 0,
              let record = readBounded(root: steamApps, relative: "appmanifest_730.acf", maximum: 4 << 20),
              var parser = try? SteamKeyValues(record), let tree = try? parser.read(),
              let app = tree["AppState"], app["appid"]?.string == "730" else {
            result.state = "install-record-unavailable"; return result
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
            guard ProcessInfo.processInfo.systemUptime - start < limits.maxSeconds else { break }
            let name = "\(depot)_\(gid).manifest"
            var payload: Data?
            for cache in roots {
                if let data = readBounded(root: cache, relative: name, maximum: 16 << 20) { payload = data; break }
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
        let rootFD = open(installURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard rootFD >= 0 else { result.state = "install-tree-unavailable"; return result }
        defer { close(rootFD) }
        result.state = "bounded-comparison"
        for relative in criticalPaths.prefix(limits.maxFiles) {
            if ProcessInfo.processInfo.systemUptime - start >= limits.maxSeconds {
                result.findings.append(Finding(relative: relative, state: "time-budget-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            guard !conflicting.contains(relative), let file = entries[relative] else {
                result.findings.append(Finding(relative: relative, state: conflicting.contains(relative) ? "reference-conflict" : "reference-unavailable", bytes: 0, certificate: "unmeasured")); continue
            }
            // Valve customizes CustomExecutable files per user; a depot hash
            // is not a valid expected installed hash for these files.
            guard file.flags & DepotManifest.customExecutableFlag == 0 else {
                result.findings.append(Finding(relative: relative, state: "steam-customized-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            guard let expected = file.contentSHA1, expected.count == Int(CC_SHA1_DIGEST_LENGTH) else {
                result.findings.append(Finding(relative: relative, state: "file-hash-unavailable", bytes: 0, certificate: "unmeasured")); continue
            }
            guard file.size <= limits.maxBytes - min(result.bytes, limits.maxBytes) else {
                result.findings.append(Finding(relative: relative, state: "byte-budget-unmeasured", bytes: 0, certificate: "unmeasured")); continue
            }
            let fd = openRelative(rootFD, relative)
            guard fd >= 0 else {
                result.findings.append(Finding(relative: relative, state: "file-unavailable", bytes: 0, certificate: "unmeasured")); continue
            }
            defer { close(fd) }
            var before = stat()
            guard fstat(fd, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), before.st_size >= 0 else {
                result.findings.append(Finding(relative: relative, state: "file-unavailable", bytes: 0, certificate: "unmeasured")); continue
            }
            let certificate = relative.hasSuffix(".dll") || relative.hasSuffix(".exe") ? peCertificate(fd, size: UInt64(before.st_size)) : "not-pe"
            guard UInt64(before.st_size) == file.size else {
                result.findings.append(Finding(relative: relative, state: "size-mismatch", bytes: 0, certificate: certificate)); continue
            }
            let hashed = hash(fd, size: file.size, deadline: start + limits.maxSeconds)
            result.bytes += hashed.bytes
            var after = stat()
            let stable = fstat(fd, &after) == 0 && unchanged(before, after)
            let state: String
            if !stable { state = "changed-during-read" }
            else if let digest = hashed.digest { state = digest == expected ? "cache-hash-match" : "cache-hash-mismatch" }
            else { state = "read-incomplete-unmeasured" }
            result.findings.append(Finding(relative: relative, state: state, bytes: hashed.bytes, certificate: certificate))
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

    private static func readBounded(root: URL, relative: String, maximum: Int) -> Data? {
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
        let count = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        var after = stat()
        guard count == data.count, fstat(fd, &after) == 0, unchanged(before, after) else { return nil }
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

    private static func hash(_ fd: Int32, size: UInt64, deadline: TimeInterval) -> (digest: Data?, bytes: UInt64) {
        var context = CC_SHA1_CTX()
        CC_SHA1_Init(&context)
        var bytes: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while bytes < size {
            guard ProcessInfo.processInfo.systemUptime < deadline else { return (nil, bytes) }
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
    private static func peCertificate(_ fd: Int32, size: UInt64) -> String {
        func read(_ offset: UInt64, _ count: Int) -> Data? {
            guard offset <= size, UInt64(count) <= size - offset else { return nil }
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
        var cursor: UInt64 = 0
        while cursor < length {
            guard length - cursor >= 8, let header = read(offset + cursor, 8) else { return "table-invalid" }
            let record = UInt64(u32(header, 0))
            guard record > 8, record <= length - cursor, u16(header, 4) == 0x200, u16(header, 6) == 2 else { return "table-invalid" }
            let rounded = (record + 7) & ~UInt64(7)
            guard rounded <= length - cursor else { return "table-invalid" }
            cursor += rounded
        }
        return "table-present-unverified"
    }
}
