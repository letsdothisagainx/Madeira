// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Madeira contributors
// Madeira Converter Exception: see LICENSE-EXCEPTION.md
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// An explicit, bounded share operation. Sources are fixed app-owned log paths;
/// account/configuration databases, arbitrary directories and links are excluded.
enum RunDiagnostics {
    struct Limits {
        var mainBytes = 32 << 20
        var consoleBytes = 4 << 20
        var steamBytes = 1 << 20
        var totalBytes = 48 << 20
        var lines = 500_000
        var lineBytes = 16 << 10
    }
    enum Failure: Error { case unavailable, cancelled }
    final class Cancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var stopped = false
        func cancel() { lock.lock(); stopped = true; lock.unlock() }
        func isCancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    }
    private static let secret = try! NSRegularExpression(pattern: #"(?i)(?:authorization\s*:|\b(?:bearer|basic)\s+\S+|\b(?:refresh[ _-]?token|access[ _-]?token|auth[ _-]?(?:token|ticket)|password|passwd|passphrase|client[ _-]?secret|cookies?|set-cookie|steamlogin(?:secure)?|sessionid|csrf|xsrf|credential|encrypted_loginkey|twofactor|oauth|nonce)\b|(?<!reported-)\b(?:token|ticket|secret)\s*[:=]\s*(?!(?:unavailable|unmeasured|excluded|redacted|unknown)\b)|(?:^|\s)-(?:login|password|autologin|auth|token|ticket)\b|\b(?:logged on as|logging in|signed in as|signing in as)\b|\b(?:accountname|username|persona(?:name)?|email)\s*[:=]|\benv\.|madeira\.cfg:)"#)
    private static let chat = try! NSRegularExpression(pattern: #"(?i)(?:\b(?:say|say_team)\s|\[ALL\]|\[TEAM\]|\(TEAM\)|\*DEAD\*|\b(?:chat|playername|personaname)\s*[:=])"#)
    private static let jwt = try! NSRegularExpression(pattern: #"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"#)
    private static let privateAssignment = try! NSRegularExpression(pattern: #"(?i)(?<!reported-)\b[A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|COOKIE|TICKET|CREDENTIALS?|SESSIONID|API_KEY|AUTH_KEY)[A-Z0-9_]*\s*[:=]|\b(?:account|user|steamid)(?:name|id)?\s*[:=]"#)
    private static let opaque = try! NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])[A-Za-z0-9_+/-]{24,}={0,2}(?![A-Za-z0-9_])"#)
    private static let accountAssignment = try! NSRegularExpression(pattern: #"(?i)\b(?:account|user|steam)[ _-]?(?:name|id)\s*[:=]|^\s*\[(?:Client|Server|Chat)\]\s+(?!(?:CL|SV|Warning|Error):)[^:\[\]]{1,64}:\s"#)
    private static let replacements: [(NSRegularExpression, String)] = [
        (#"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+"#, "[redacted-url]"),
        (#"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#, "[redacted-email]"),
        (#"(?i)[A-Z]:[\\/](?:users|documents and settings)[\\/][^\\/\s\"']+"#, "[user-directory]"),
        (#"/(?:Users|home)/[^/\s\"']+"#, "[user-directory]"),
        (#"(?i)([\\/](?:userdata|usercache)[\\/])[0-9]{1,20}([\\/])"#, "$1[redacted-account-id]$2"),
        (#"(?:/private)?/var/mobile/Containers/(?:Data|Bundle|Shared)/[^/\s]+/[0-9A-Fa-f-]{32,36}"#, "[app-container]"),
        (#"\b[0-9]{17}\b|\[U:[0-9]:[0-9]+\]|STEAM_[0-5]:[01]:[0-9]+"#, "[redacted-account-id]"),
        (#"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b"#, "[redacted-endpoint]"),
        (#"(?i)\b(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+[A-Z]{2,63}:[0-9]{1,5}\b|\b(?:[A-Z0-9-]+\.)+(?:com|net|org|io|gg|co|dev|app|local|internal|ru|cn|eu|uk|us|de|fr|ca|xyz|invalid|test)\b"#, "[redacted-endpoint]"),
        (#"(?i)\[[0-9a-f:]*:[0-9a-f:.%]+\](?::[0-9]+)?|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{0,4}\b|\b[0-9a-f]*::[0-9a-f:%]+"#, "[redacted-endpoint]"),
        (#"\"[^\"]*\"|'[^']*'"#, "[redacted-quoted-text]")
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }
    /// Broad diagnostic text, not only the VAC schema. Secret-bearing and chat
    /// rows are omitted whole; remaining identifiers/endpoints/opaque values are
    /// removed. No original text is included in the omission manifest.
    static func sanitize(_ original: String) -> String? {
        guard !original.isEmpty, original.utf8.count <= 16 << 10,
              original.unicodeScalars.allSatisfy({ $0.value == 9 || (32...126).contains($0.value) }) else { return nil }
        let range = NSRange(original.startIndex..., in: original)
        guard secret.firstMatch(in: original, range: range) == nil,
              chat.firstMatch(in: original, range: range) == nil,
              jwt.firstMatch(in: original, range: range) == nil,
              privateAssignment.firstMatch(in: original, range: range) == nil,
              accountAssignment.firstMatch(in: original, range: range) == nil else { return nil }
        var line = original
        for (expression, replacement) in replacements {
            line = expression.stringByReplacingMatches(in: line, range: NSRange(line.startIndex..., in: line), withTemplate: replacement)
        }
        // Preserve build hashes/UUIDs, addresses and diagnostic field names;
        // redact long opaque strings (including JWT/base64-style payloads).
            for match in opaque.matches(in: line, range: NSRange(line.startIndex..., in: line)).reversed() {
                guard let range = Range(match.range, in: line) else { continue }
                let word = String(line[range])
                func hex(_ bytes: String.UTF8View) -> Bool { bytes.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) } }
                let key = line[..<range.lowerBound].split(whereSeparator: { $0 == " " || $0 == "\t" }).last.map(String.init) ?? ""
                let hashKey = ["source=", "package-source=", "virtual-source=", "expected-virtual=", "jit-source=", "expected-jit=", "virtual-build=", "jit-build=", "build=", "revision=", "sha1=", "sha256=", "native-uuid=", "packaged-uuid="]
                let uuid = ["native-uuid=", "packaged-uuid="].contains(key) &&
                    word.range(of: "^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$", options: .regularExpression) != nil
                let hash = [32, 40, 64].contains(word.utf8.count) && hex(word.utf8) && hashKey.contains(key)
                let tag = range.lowerBound > line.startIndex && line[line.index(before: range.lowerBound)] == "[" &&
                    range.upperBound < line.endIndex && line[range.upperBound] == "]" &&
                    ["native-build-provenance-v1", "cs2-user-marker-v1", "steam-content-audit-v1", "startup-timeline-v1", "fex-code-buffer-guard-v1"].contains(word)
                let field = range.upperBound < line.endIndex && line[range.upperBound] == "=" &&
                    ["compiled-hard-image-arena-mb", "expected-hard-image-arena-mb"].contains(word)
                let policy = ["WINE_IOS_JIT_CODE_TAIL_LIMIT_MB", "WINE_IOS_JIT_HEAD_RESERVE_MB", "MADEIRA_POOL_HEAD_RESERVE_MB",
                              "WINE_IOS_JIT_IMAGE_ARENA_MB", "WINE_IOS_FEX_CODE_GUARD_V1"].contains(word)
                let address = word.hasPrefix("0x") && hex(String(word.dropFirst(2)).utf8)
                if !hash && !uuid && !tag && !field && !policy && !address { line.replaceSubrange(range, with: "[redacted-opaque-value]") }
            }
        return line
    }
    private static func json(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
    }
    private static func metadata(_ info: [String: Any], now: Date, uptime: UInt64) -> [String: Any] {
        var value: [String: Any] = ["schema": "madeira-run-metadata-v1", "exportUTC": ISO8601DateFormatter().string(from: now),
            "exportAppDispatchUptimeNanoseconds": String(uptime), "utcOffsetMinutes": TimeZone.current.secondsFromGMT(for: now) / 60,
            "osVersion": "\(ProcessInfo.processInfo.operatingSystemVersion.majorVersion).\(ProcessInfo.processInfo.operatingSystemVersion.minorVersion).\(ProcessInfo.processInfo.operatingSystemVersion.patchVersion)"]
        for key in ["CFBundleShortVersionString", "CFBundleVersion", "MadeiraBuild"] {
            if let text = info[key] as? String, text.utf8.count <= 512, let cleaned = sanitize(text) { value[key] = cleaned }
        }
        var provenance: [String: Any] = [:]
        let raw = info["MadeiraNativeBuildProvenance"] as? [String: Any] ?? [:]
        for (key, digits) in [("packageSourceRevision", 40), ("virtualBuildRevision", 40), ("jitallocatorBuildRevision", 40),
                              ("expectedVirtualSourceSHA256", 64), ("expectedJITAllocatorSourceSHA256", 64)] {
            if let text = raw[key] as? String, text.range(of: "^[0-9a-f]{\(digits)}$", options: .regularExpression) != nil { provenance[key] = text }
        }
        if let uuid = raw["nativeImageUUID"] as? String,
           uuid.range(of: "^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$", options: .regularExpression) != nil { provenance["nativeImageUUID"] = uuid }
        for key in ["expectedJITCodeTailLimitMB", "expectedJITImageArenaMB"] {
            if let limit = raw[key] as? NSNumber, (0...8192).contains(limit.intValue) { provenance[key] = limit.intValue }
        }
        value["packagedNativeBuildProvenance"] = provenance
        value["provenanceInterpretation"] = "packaged-expectations; compare-with-native-build-provenance-v1-runtime-row-for-linked-image-agreement"
        return value
    }
    static func collect(documents: URL, bundleInfo: [String: Any] = [:], now: Date = Date(),
                        uptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds,
                        limits: Limits = Limits(), cancelled: () -> Bool = { false }) throws -> [SteamGameDiagnostics.Entry] {
        guard limits.mainBytes > 0, limits.mainBytes <= 64 << 20, limits.consoleBytes > 0, limits.consoleBytes <= 8 << 20,
              limits.steamBytes > 0, limits.steamBytes <= 4 << 20, limits.totalBytes >= 4096, limits.totalBytes <= 96 << 20,
              limits.lines > 0, limits.lines <= 1_000_000, limits.lineBytes > 0, limits.lineBytes <= 16 << 10 else { throw Failure.unavailable }
        let root = open(documents.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw Failure.unavailable }
        defer { close(root) }
        var info = stat()
        guard fstat(root, &info) == 0, info.st_uid == getuid() else { throw Failure.unavailable }
        var entries: [SteamGameDiagnostics.Entry] = [], sources: [[String: Any]] = [], identities: [String: String] = [:]
        var used = 0
        let payloadBudget = max(0, limits.totalBytes - min(2 << 20, limits.totalBytes / 8))
        func checkCancellation() throws { if cancelled() { throw Failure.cancelled } }
        func consume(_ id: String, _ relative: String, _ maximum: Int) throws {
            try checkCancellation()
            let remaining = payloadBudget - used
            guard remaining > 0 else { sources.append(["source": id, "state": "omitted-total-byte-budget"]); return }
            guard let snapshot = SteamGameDiagnostics.snapshot(root, relative, maximum: min(maximum, remaining),
                preserveStartup: id == "madeira-session", annotateGap: true) else {
                sources.append(["source": id, "state": "unavailable-or-not-owned-regular-file"]); return
            }
            if let previous = identities[snapshot.identity] {
                sources.append(["source": id, "state": "same-file-as-earlier-source", "sameAsSource": previous]); return
            }
            identities[snapshot.identity] = id
            let rows = snapshot.bytes.reduce(0) { $0 + ($1 == 10 ? 1 : 0) }
            let headRows = min(rows / 4, limits.lines / 4), tailRows = min(rows - headRows, limits.lines - headRows)
            func firstEnd(_ count: Int) -> Int {
                guard count > 0 else { return snapshot.bytes.startIndex }
                var found = 0
                for index in snapshot.bytes.indices where snapshot.bytes[index] == 10 {
                    found += 1; if found == count { return index + 1 }
                }
                return snapshot.bytes.endIndex
            }
            func lastStart(_ count: Int) -> Int {
                guard count > 0 else { return snapshot.bytes.endIndex }
                var cursor = snapshot.bytes.endIndex, found = 0
                if cursor > snapshot.bytes.startIndex && snapshot.bytes[cursor - 1] == 10 { cursor -= 1 }
                while cursor > snapshot.bytes.startIndex {
                    cursor -= 1
                    if snapshot.bytes[cursor] == 10 { found += 1; if found == count { return cursor + 1 } }
                }
                return snapshot.bytes.startIndex
            }
            let headEnd = firstEnd(headRows), tailStart = max(headEnd, lastStart(tailRows))
            var prefix = Data(), tail: [Data] = [], tailFirst = 0, tailBytes = 0
            var scanned = 0, omitted = rows - headRows - tailRows, changed = 0, longRows = 0, byteOmitted = 0
            let available = max(0, remaining - 256), headBudget = available / 4
            for (range, startup) in [(snapshot.bytes.startIndex..<headEnd, true), (tailStart..<snapshot.bytes.endIndex, false)] {
                var start = range.lowerBound
                while start < range.upperBound {
                    if scanned & 1023 == 0 { try checkCancellation() }
                    let end = snapshot.bytes[start..<range.upperBound].firstIndex(of: 10) ?? range.upperBound
                    scanned += 1
                    if end - start > limits.lineBytes { omitted += 1; longRows += 1 }
                    else {
                        let raw = String(decoding: snapshot.bytes[start..<end], as: UTF8.self).trimmingCharacters(in: .newlines)
                        if let line = sanitize(raw) {
                            let encoded = Data((line + "\n").utf8)
                            if line != raw { changed += 1 }
                            if startup {
                                if encoded.count <= headBudget - prefix.count { prefix.append(encoded) }
                                else { byteOmitted += 1; omitted += 1 }
                            } else {
                                let budget = available - prefix.count
                                if encoded.count <= budget {
                                    tail.append(encoded); tailBytes += encoded.count
                                    while tailBytes > budget {
                                        tailBytes -= tail[tailFirst].count; tailFirst += 1; byteOmitted += 1; omitted += 1
                                    }
                                    if tailFirst >= 1024 && tailFirst * 2 > tail.count { tail = Array(tail.dropFirst(tailFirst)); tailFirst = 0 }
                                } else { byteOmitted += 1; omitted += 1 }
                            }
                        } else { omitted += 1 }
                    }
                    start = end == range.upperBound ? end : end + 1
                }
            }
            var output = prefix
            if omitted > 0 {
                let gap = Data("[run-export-omissions] rows=\(omitted) within=bounded-byte-snapshot details=manifest\n".utf8)
                if gap.count <= remaining - output.count - tailBytes { output.append(gap) }
            }
            for row in tail.dropFirst(tailFirst) { output.append(row) }
            let lineLimit = rows > limits.lines, outputLimit = byteOmitted > 0
            let name = "sanitized/" + id + ".log"
            entries.append(.init(name: name, data: output)); used += output.count
            sources.append(["source": id, "entry": name, "state": "sanitized-bounded-snapshot", "originalBytes": snapshot.originalBytes,
                "capturedSourceBytes": snapshot.capturedBytes, "exportedBytes": output.count, "sourceByteTruncated": snapshot.truncated,
                "requestedByteWindows": snapshot.readWindows, "sourceBytesNotCaptured": snapshot.originalBytes - UInt64(snapshot.capturedBytes),
                "changedDuringRead": snapshot.changedDuringRead, "rowsInByteSnapshot": rows, "rowsScanned": scanned, "rowsOmitted": omitted,
                "rowsRedacted": changed, "overlongRowsOmitted": longRows, "lineBudgetReached": lineLimit,
                "rowsOmittedForOutputBudget": byteOmitted, "outputBudgetReached": outputLimit])
        }
        // Keep the existing typed VAC evidence before allocating the remaining
        // budget to broad text; a noisy alternate install cannot starve it.
        try checkCancellation()
        var typedState = "included-separate-bounded-typed-snapshot", typedSources: [[String: Any]] = []
        let typed = try SteamGameDiagnostics.collect(documents: documents)
        try checkCancellation()
        for entry in typed {
            let included = entry.data.count <= payloadBudget - used
            if included { entries.append(.init(name: "vac/" + entry.name, data: entry.data)); used += entry.data.count }
            else { typedState = "partially-omitted-total-byte-budget" }
            typedSources.append(["entry": "vac/" + entry.name, "bytes": entry.data.count, "state": included ? "included" : "omitted-total-byte-budget"])
        }
        try consume("madeira-session", "madeira-log.txt", limits.mainBytes)
        for (index, install) in ["Program Files (x86)/Steam", "Program Files/Steam"].enumerated() {
            let base = "wine/drive_c/" + install + "/", suffix = index == 0 ? "" : "-alternate-install"
            try consume("cs2-console" + suffix, base + "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log", limits.consoleBytes)
            for (id, filename) in [("console", "console_log.txt"), ("gameprocess", "gameprocess_log.txt"), ("service", "service_log.txt"),
                ("content", "content_log.txt"), ("connection", "connection_log.txt"), ("bootstrap", "bootstrap_log.txt"), ("cef", "cef_log.txt")] {
                try consume("steam-" + id + suffix, base + "logs/" + filename, limits.steamBytes)
            }
        }
        try checkCancellation()
        let markers: [[String: Any]] = CS2VACMarkers.snapshotLines().suffix(256).compactMap {
            guard let (tag, fields) = SteamGameDiagnostics.decode($0), tag == "cs2-user-marker-v1" else { return nil }
            return ["record": tag, "fields": fields]
        }
        let clocks: [String: Any] = ["exportUTC": ISO8601DateFormatter().string(from: now), "exportAppDispatchUptimeNanoseconds": String(uptimeNanoseconds),
            "markers": markers, "clockDomains": ["app-markers": "app-dispatch-uptime", "Wine-runtime": "wine-posix-clock-monotonic", "CS2-console": "console-MM/DD-wall-year-zone-unmeasured"],
            "correlation": "distinct-monotonic-domains; do-not-subtract-without-measured-calibration; file-order-and-wall-proximity-do-not-prove-causality"]
        let manifest: [String: Any] = ["schema": "madeira-run-diagnostics-v1", "collection": "explicit-user-export-read-only-allowlisted-owned-files",
            "compression": "ZIP-method-8-raw-DEFLATE", "sources": sources, "mainByteBudget": limits.mainBytes, "consoleByteBudget": limits.consoleBytes,
            "steamLogByteBudget": limits.steamBytes, "payloadByteBudget": payloadBudget, "totalPayloadByteBudget": limits.totalBytes,
            "lineBudgetPerSource": limits.lines, "lineByteBudget": limits.lineBytes, "typedVACSnapshot": typedState, "typedVACEntries": typedSources,
            "excluded": ["account-and-authentication-files", "cookies-and-credentials", "configuration-databases", "arbitrary-files", "symlinks-and-special-files", "external-library-links", "chat-and-secret-bearing-rows", "non-ASCII-or-overlong-rows"],
            "sanitization": "secret-bearing-and-chat-rows-omitted; quoted-text, URLs, endpoints, account-identifiers and opaque-values-redacted; source-text-never-copied-into-manifest",
            "runtimeCoverage": "broad-sanitized-Madeira-log-including-process-module-allocator-build-and-clock-rows-when-present; not-a-complete-live-inventory",
            "snapshot": "startup-prefix-plus-recent-suffix-when-source-budget-exceeded; partial-lines-excluded; live-files-may-grow-or-rotate",
            "rowSelection": "startup-quarter-and-recent-three-quarters; latest-sanitized-complete-rows-retained-if-output-budget-exceeded"]
        entries.append(.init(name: "metadata.json", data: try json(metadata(bundleInfo, now: now, uptime: uptimeNanoseconds))))
        entries.append(.init(name: "clocks-and-markers.json", data: try json(clocks)))
        entries.append(.init(name: "manifest.json", data: try json(manifest)))
        entries.append(.init(name: "README.txt", data: Data("Madeira run diagnostics\nSanitized session/CS2/Steam log snapshots plus build provenance, clocks and typed VAC observations. Read manifest.json for unavailable sources, byte/line limits, redactions and omissions. A middle-gap marker identifies joined startup/recent windows. Runtime module/process/allocator rows are preserved when logged; absent rows do not prove absence. vac/ is a separate bounded typed snapshot. No settings, game files or account data are changed.\n".utf8)))
        guard entries.reduce(0, { $0 + $1.data.count }) <= limits.totalBytes else { throw Failure.unavailable }
        return entries
    }
    static func export(documents: URL, temporaryDirectory: URL, bundleInfo: [String: Any] = [:],
                       limits: Limits = Limits(), cancelled: () -> Bool = { false }) throws -> URL {
        let entries = try collect(documents: documents, bundleInfo: bundleInfo, limits: limits, cancelled: cancelled)
        let fm = FileManager.default
        let temporary = open(temporaryDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard temporary >= 0 else { throw Failure.unavailable }
        defer { close(temporary) }
        var temporaryInfo = stat()
        guard fstat(temporary, &temporaryInfo) == 0, temporaryInfo.st_uid == getuid() else { throw Failure.unavailable }
        let directory = temporaryDirectory.appendingPathComponent("madeira-run-diagnostics-" + UUID().uuidString, isDirectory: true)
        var created = false, complete = false
        defer { if created && !complete { try? fm.removeItem(at: directory) } }
        guard !cancelled() else { throw Failure.cancelled }
        try fm.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); created = true
        let result = directory.appendingPathComponent("Madeira-Run-Diagnostics.zip")
        let fd = open(result.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Failure.unavailable }; close(fd)
        let writer = try SaveZipWriter(url: result)
        for entry in entries {
            guard !cancelled() else { throw Failure.cancelled }
            try writer.add(name: entry.name, data: entry.data, compression: .deflate)
        }
        try writer.finish()
        guard !cancelled() else { throw Failure.cancelled }
        guard let size = try result.resourceValues(forKeys: [.fileSizeKey]).fileSize,
              size <= limits.totalBytes + (1 << 20) else { throw Failure.unavailable }
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: result.path)
        complete = true
        return result
    }
}
