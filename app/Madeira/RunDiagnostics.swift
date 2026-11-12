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
    enum Failure: LocalizedError {
        case unavailable, cancelled
        /// The stage is an owned label, never a source path or OS description.
        case stage(String, Int)
        var errorDescription: String? {
            switch self {
            case .unavailable: return "Run diagnostics are unavailable. Your original files have not been changed."
            case .cancelled: return "Run export was cancelled."
            case .stage(let stage, let code):
                return "Run export failed during \(stage) (error \(code)). Your original files have not been changed."
            }
        }
    }
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
    private static let faultSiteSeal = try! NSRegularExpression(pattern: #" cookies=(unchanged|changed|unverifiable)(?= metadata=first-event$)"#)
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
        var line = original
        // This emitter's finite mapping-generation status is not a web cookie.
        if line.hasPrefix("[fault-site-v1] ") {
            line = faultSiteSeal.stringByReplacingMatches(in: line, range: NSRange(line.startIndex..., in: line), withTemplate: " code-seal=$1")
        }
        let range = NSRange(line.startIndex..., in: line)
        guard secret.firstMatch(in: line, range: range) == nil,
              chat.firstMatch(in: line, range: range) == nil,
              jwt.firstMatch(in: line, range: range) == nil,
              privateAssignment.firstMatch(in: line, range: range) == nil,
              accountAssignment.firstMatch(in: line, range: range) == nil else { return nil }
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
                    ["native-build-provenance-v1", "cs2-user-marker-v1", "steam-content-audit-v1", "startup-timeline-v1", "fex-code-buffer-guard-v1", "dynamic-memory-pressure-v1"].contains(word)
                let field = range.upperBound < line.endIndex && line[range.upperBound] == "=" &&
                    ["compiled-hard-image-arena-mb", "expected-hard-image-arena-mb"].contains(word)
                let policy = ["WINE_IOS_JIT_CODE_TAIL_LIMIT_MB", "WINE_IOS_JIT_HEAD_RESERVE_MB", "MADEIRA_POOL_HEAD_RESERVE_MB",
                              "WINE_IOS_JIT_IMAGE_ARENA_MB", "WINE_IOS_FEX_CODE_GUARD_V1"].contains(word)
                let address = word.hasPrefix("0x") && hex(String(word.dropFirst(2)).utf8)
                // Engine enum identifiers in this exact closure context are
                // diagnostic codes, not opaque connection/session payloads.
                let disconnect = line.contains("[Networking] Netchan ") && line.contains(" closed unexpectedly: ") &&
                    word.hasPrefix("NETWORK_DISCONNECT_") && word.utf8.count <= 96 &&
                    word.utf8.allSatisfy { (65...90).contains($0) || $0 == 95 }
                if !hash && !uuid && !tag && !field && !policy && !address && !disconnect { line.replaceSubrange(range, with: "[redacted-opaque-value]") }
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
    /// Stream selected source windows through a private spool. At most one
    /// 64 KiB read buffer and one capped line are resident; newest rows are
    /// reversed on disk, not retained as an in-memory array.
    private static func streamSource(_ fd: Int32, before: stat, maximum: Int, limits: Limits,
                                     output: FileHandle, recent: FileHandle,
                                     cancelled: () -> Bool) throws -> [String: Any] {
        let original = UInt64(before.st_size), chunkBytes = 64 << 10
        let outputBudget = max(0, maximum - 256)
        var exported = 0, prefixBytes = 0, prefixRows = 0, tailRows = 0
        var omitted = 0, redacted = 0, overlong = 0, outputOmitted = 0, readBytes = 0
        var prefixEnd: UInt64 = 0, firstTail: UInt64 = original, tailRecordBytes: UInt64 = 0
        var readWindows: [[String: UInt64]] = []
        func check() throws { if cancelled() { throw Failure.cancelled } }
        func read(_ offset: UInt64, _ count: Int) throws -> Data {
            try check()
            var bytes = Data(count: count)
            let actual = bytes.withUnsafeMutableBytes { raw in pread(fd, raw.baseAddress, count, off_t(offset)) }
            guard actual > 0 else { throw Failure.stage("reading a run log", actual < 0 ? Int(errno) : 0) }
            bytes.count = actual; readBytes += actual
            return bytes
        }
        func clean(_ reversed: [UInt8], reverse: Bool, dropped: Bool) -> Data? {
            if dropped { overlong += 1; omitted += 1; return nil }
            let bytes = reverse ? Array(reversed.reversed()) : reversed
            let raw = String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .newlines)
            let line: String?
            #if canImport(ObjectiveC)
            // Drain Foundation's temporary regex/string objects per row rather
            // than retaining them until a long background export finishes.
            line = autoreleasepool { sanitize(raw) }
            #else
            line = sanitize(raw)
            #endif
            guard let line else { omitted += 1; return nil }
            if raw != line { redacted += 1 }
            return Data((line + "\n").utf8)
        }
        func writeOutput(_ bytes: Data) throws {
            do {
                #if canImport(ObjectiveC)
                try autoreleasepool { try output.write(contentsOf: bytes) }
                #else
                try output.write(contentsOf: bytes)
                #endif
            }
            catch { throw Failure.stage("writing sanitized run evidence", (error as NSError).code) }
            exported += bytes.count
        }
        var trailingPartial = false
        if original > 0 { trailingPartial = try read(original - 1, 1).first != 10 }
        if trailingPartial { omitted += 1 }
        let prefixLimit = min(original, UInt64(maximum / 4)), prefixLineLimit = limits.lines / 4
        readWindows.append(["offset": 0, "requestedBytes": prefixLimit])
        var cursor: UInt64 = 0, pending: [UInt8] = [], dropping = false
        prefixLoop: while cursor < prefixLimit && prefixRows < prefixLineLimit {
            let data = try read(cursor, Int(min(UInt64(chunkBytes), prefixLimit - cursor)))
            for (index, byte) in data.enumerated() {
                if byte == 10 {
                    prefixRows += 1; prefixEnd = cursor + UInt64(index) + 1
                    if let encoded = clean(pending, reverse: false, dropped: dropping) {
                        if encoded.count <= outputBudget / 4 - prefixBytes {
                            try writeOutput(encoded); prefixBytes += encoded.count
                        } else { outputOmitted += 1; omitted += 1 }
                    }
                    pending.removeAll(keepingCapacity: true); dropping = false
                    if prefixRows == prefixLineLimit { break prefixLoop }
                } else if !dropping {
                    if pending.count < limits.lineBytes { pending.append(byte) }
                    else { pending.removeAll(keepingCapacity: true); dropping = true }
                }
            }
            cursor += UInt64(data.count)
        }
        pending.removeAll(keepingCapacity: true); dropping = false
        let rawTailBudget = UInt64(maximum) - prefixEnd
        let lower = max(prefixEnd, original > rawTailBudget ? original - rawTailBudget : 0)
        readWindows.append(["offset": lower, "requestedBytes": original - lower])
        var reverseCursor = original, terminal = false, rowEnd = original, tailStopped = false
        var tailPayloadBytes = 0
        let tailLineLimit = max(0, limits.lines - prefixRows)
        func tailLine(_ start: UInt64) throws -> Bool {
            tailRows += 1
            defer { pending.removeAll(keepingCapacity: true); dropping = false }
            guard let encoded = clean(pending, reverse: true, dropped: dropping) else { return true }
            guard encoded.count <= outputBudget - prefixBytes - tailPayloadBytes else {
                outputOmitted += 1; omitted += 1; return false
            }
            do {
                func writeRecord() throws {
                    try recent.write(contentsOf: encoded)
                    var length = UInt32(encoded.count).littleEndian
                    try recent.write(contentsOf: Data(bytes: &length, count: 4))
                }
                #if canImport(ObjectiveC)
                try autoreleasepool { try writeRecord() }
                #else
                try writeRecord()
                #endif
            } catch { throw Failure.stage("staging recent run evidence", (error as NSError).code) }
            tailRecordBytes += UInt64(encoded.count + 4)
            tailPayloadBytes += encoded.count
            firstTail = min(firstTail, start)
            return true
        }
        // Payload bytes are distinct from the four-byte on-disk row footers.
        tailLoop: while reverseCursor > lower && tailRows < tailLineLimit {
            let start = max(lower, reverseCursor > UInt64(chunkBytes) ? reverseCursor - UInt64(chunkBytes) : 0)
            let data = try read(start, Int(reverseCursor - start))
            // A concurrent truncation is an unavailable source snapshot, not
            // permission to export uninitialized or unrelated bytes.
            guard data.count == Int(reverseCursor - start) else { throw Failure.stage("reading a changed run log", 0) }
            for index in data.indices.reversed() {
                let byte = data[index], position = start + UInt64(index)
                if !terminal {
                    if byte == 10 { terminal = true; rowEnd = position + 1 }
                    continue
                }
                if byte == 10 {
                    if try !tailLine(position + 1) { tailStopped = true; break tailLoop }
                    rowEnd = position + 1
                    if tailRows == tailLineLimit { tailStopped = true; break tailLoop }
                } else if !dropping {
                    if pending.count < limits.lineBytes { pending.append(byte) }
                    else { pending.removeAll(keepingCapacity: true); dropping = true }
                }
            }
            reverseCursor = start
        }
        if !tailStopped && terminal && rowEnd > lower && tailRows < tailLineLimit {
            let boundary: Bool
            if lower == 0 || lower == prefixEnd { boundary = true }
            else { boundary = try read(lower - 1, 1).first == 10 }
            if boundary { _ = try tailLine(lower) }
        }
        let hasGap = firstTail > prefixEnd && prefixEnd < original || omitted > 0 || tailStopped
        if hasGap {
            let gap = Data("[run-export-gap] source-bytes=\(original) read-budget=\(maximum) middle-or-rows=omitted details=manifest\n".utf8)
            if gap.count <= maximum - prefixBytes - tailPayloadBytes { try writeOutput(gap) }
        }
        // Records were written newest-first. Read their bounded footers from
        // the end to append complete lines in original chronological order.
        var recordEnd = tailRecordBytes
        func copyRecord() throws {
            try check()
            try recent.seek(toOffset: recordEnd - 4)
            guard let footer = try recent.read(upToCount: 4), footer.count == 4 else { throw Failure.stage("reading staged run evidence", 0) }
            let length = footer.enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << UInt32($1.offset * 8) }
            guard length > 0, UInt64(length) <= recordEnd - 4, length <= UInt32(limits.lineBytes * 16) else {
                throw Failure.stage("validating staged run evidence", 0)
            }
            let start = recordEnd - 4 - UInt64(length)
            try recent.seek(toOffset: start)
            var remaining = Int(length)
            while remaining > 0 {
                guard let data = try recent.read(upToCount: min(chunkBytes, remaining)), !data.isEmpty else {
                    throw Failure.stage("reading staged run evidence", 0)
                }
                try writeOutput(data); remaining -= data.count
            }
            recordEnd = start
        }
        while recordEnd > 0 {
            #if canImport(ObjectiveC)
            try autoreleasepool { try copyRecord() }
            #else
            try copyRecord()
            #endif
        }
        var after = stat()
        let statFailed = fstat(fd, &after) != 0
        #if canImport(Darwin)
        let stampChanged = before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
            before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
        #else
        let stampChanged = before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
            before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec
        #endif
        let changed = statFailed || before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size || stampChanged
        return ["state": "sanitized-streamed-snapshot", "originalBytes": original, "exportedBytes": exported,
                "sourceReadBytes": readBytes, "requestedByteWindows": readWindows, "changedDuringRead": changed,
                "sourceByteTruncated": original > UInt64(maximum), "rowsScanned": prefixRows + tailRows,
                "rowsOmitted": omitted, "rowsRedacted": redacted, "overlongRowsOmitted": overlong,
                "rowsOmittedForOutputBudget": outputOmitted, "lineBudgetReached": prefixRows + tailRows >= limits.lines,
                "outputBudgetReached": outputOmitted > 0, "partialTrailingRowOmitted": trailingPartial,
                "ioBufferBytes": chunkBytes, "maxRawLineBytes": limits.lineBytes]
    }

    static func export(documents: URL, temporaryDirectory: URL, bundleInfo: [String: Any] = [:],
                       limits: Limits = Limits(), cancelled: () -> Bool = { false }) throws -> URL {
        guard limits.mainBytes > 0, limits.mainBytes <= 64 << 20, limits.consoleBytes > 0, limits.consoleBytes <= 8 << 20,
              limits.steamBytes > 0, limits.steamBytes <= 4 << 20, limits.totalBytes >= 4096, limits.totalBytes <= 96 << 20,
              limits.lines > 0, limits.lines <= 1_000_000, limits.lineBytes > 0, limits.lineBytes <= 16 << 10 else { throw Failure.unavailable }
        let fm = FileManager.default
        let temporary = open(temporaryDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard temporary >= 0 else { throw Failure.stage("opening temporary storage", Int(errno)) }
        defer { close(temporary) }
        var temporaryInfo = stat()
        guard fstat(temporary, &temporaryInfo) == 0, temporaryInfo.st_uid == getuid() else { throw Failure.unavailable }
        let root = open(documents.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw Failure.stage("opening run logs", Int(errno)) }
        defer { close(root) }
        var rootInfo = stat()
        guard fstat(root, &rootInfo) == 0, rootInfo.st_uid == getuid() else { throw Failure.unavailable }
        let directory = temporaryDirectory.appendingPathComponent("madeira-run-diagnostics-" + UUID().uuidString, isDirectory: true)
        var created = false, complete = false
        defer { if created && !complete { try? fm.removeItem(at: directory) } }
        func check() throws { if cancelled() { throw Failure.cancelled } }
        try check()
        do { try fm.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); created = true }
        catch { throw Failure.stage("creating private temporary storage", (error as NSError).code) }
        let result = directory.appendingPathComponent("Madeira-Run-Diagnostics.zip")
        let fd = open(result.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.stage("creating the run archive", Int(errno)) }
        var archiveIdentity = stat()
        guard fstat(fd, &archiveIdentity) == 0, archiveIdentity.st_uid == getuid(),
              archiveIdentity.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), fchmod(fd, 0o600) == 0 else {
            let code = Int(errno); close(fd); throw Failure.stage("protecting the run archive", code)
        }
        let writer = SaveZipWriter(handle: FileHandle(fileDescriptor: fd, closeOnDealloc: true))
        var sources: [[String: Any]] = [], typedSources: [[String: Any]] = [], identities: [String: String] = [:], used = 0
        let payloadBudget = max(0, limits.totalBytes - min(2 << 20, limits.totalBytes / 8))
        func add(_ name: String, _ data: Data) throws {
            try check()
            guard data.count <= limits.totalBytes - used else { throw Failure.stage("limiting run evidence", 0) }
            do { try writer.add(name: name, data: data, compression: .deflate) }
            catch is CancellationError { throw Failure.cancelled }
            catch { throw Failure.stage("compressing run metadata", (error as NSError).code) }
            used += data.count
        }
        var typedState = "included-separate-bounded-typed-snapshot"
        // The existing closed-schema package remains useful, but its read
        // budgets here are deliberately small and independent of large logs.
        let typed = try SteamGameDiagnostics.collect(documents: documents,
            limits: .init(mainBytes: min(1 << 20, limits.mainBytes), otherBytes: min(64 << 10, limits.steamBytes), records: 1024))
        for entry in typed {
            let included = entry.data.count <= payloadBudget - used
            if included { try add("vac/" + entry.name, entry.data) }
            else { typedState = "partially-omitted-total-byte-budget" }
            typedSources.append(["entry": "vac/" + entry.name, "bytes": entry.data.count, "state": included ? "included" : "omitted-total-byte-budget"])
        }
        func consume(_ id: String, _ relative: String, _ maximum: Int) throws {
            try check()
            let remaining = payloadBudget - used
            guard remaining > 256 else { sources.append(["source": id, "state": "omitted-total-byte-budget"]); return }
            let parts = relative.split(separator: "/").map(String.init)
            guard !parts.isEmpty, parts.allSatisfy({ $0 != "." && $0 != ".." && !$0.isEmpty }),
                  let input = SteamGameDiagnostics.openOwned(root, parts) else {
                sources.append(["source": id, "state": "unavailable-or-not-owned-regular-file"]); return
            }
            defer { close(input) }
            var info = stat()
            guard fstat(input, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), info.st_size >= 0 else {
                sources.append(["source": id, "state": "unavailable-or-not-owned-regular-file"]); return
            }
            let identity = "\(info.st_dev):\(info.st_ino)"
            if let previous = identities[identity] { sources.append(["source": id, "state": "same-file-as-earlier-source", "sameAsSource": previous]); return }
            identities[identity] = id
            func spool(_ name: String) throws -> FileHandle {
                let url = directory.appendingPathComponent(name)
                let fd = open(url.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                guard fd >= 0 else { throw Failure.stage("staging sanitized run evidence", Int(errno)) }
                return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            }
            let stageURL = directory.appendingPathComponent("source.tmp"), tailURL = directory.appendingPathComponent("recent.tmp")
            let stage = try spool("source.tmp"), tail = try spool("recent.tmp")
            defer { try? stage.close(); try? tail.close(); try? fm.removeItem(at: stageURL); try? fm.removeItem(at: tailURL) }
            var summary = try streamSource(input, before: info, maximum: min(maximum, remaining), limits: limits,
                                           output: stage, recent: tail, cancelled: cancelled)
            let bytes = summary["exportedBytes"] as! Int, name = "sanitized/" + id + ".log"
            do { try writer.add(name: name, file: stage, size: UInt64(bytes), cancelled: cancelled) }
            catch is CancellationError { throw Failure.cancelled }
            catch { throw Failure.stage("compressing run evidence", (error as NSError).code) }
            summary["source"] = id; summary["entry"] = name; sources.append(summary); used += bytes
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
        try check()
        let now = Date(), uptime = DispatchTime.now().uptimeNanoseconds
        let markers: [[String: Any]] = CS2VACMarkers.snapshotLines().suffix(256).compactMap {
            guard let (tag, fields) = SteamGameDiagnostics.decode($0), tag == "cs2-user-marker-v1" else { return nil }
            return ["record": tag, "fields": fields]
        }
        let clocks: [String: Any] = ["exportUTC": ISO8601DateFormatter().string(from: now), "exportAppDispatchUptimeNanoseconds": String(uptime),
            "markers": markers, "clockDomains": ["app-markers": "app-dispatch-uptime", "Wine-runtime": "wine-posix-clock-monotonic", "CS2-console": "console-MM/DD-wall-year-zone-unmeasured"],
            "correlation": "distinct-monotonic-domains; do-not-subtract-without-measured-calibration; file-order-and-wall-proximity-do-not-prove-causality"]
        let manifest: [String: Any] = ["schema": "madeira-run-diagnostics-v1", "collection": "explicit-user-export-read-only-allowlisted-owned-files",
            "compression": "ZIP-method-8-raw-DEFLATE", "io": "streamed-owned-files-with-fixed-64KiB-buffers-and-private-disk-spools", "sources": sources,
            "mainByteBudget": limits.mainBytes, "consoleByteBudget": limits.consoleBytes, "steamLogByteBudget": limits.steamBytes,
            "payloadByteBudget": payloadBudget, "totalPayloadByteBudget": limits.totalBytes, "lineBudgetPerSource": limits.lines, "lineByteBudget": limits.lineBytes,
            "typedVACSnapshot": typedState, "typedVACEntries": typedSources,
            "excluded": ["account-and-authentication-files", "cookies-and-credentials", "configuration-databases", "arbitrary-files", "symlinks-and-special-files", "external-library-links", "chat-and-secret-bearing-rows", "non-ASCII-or-overlong-rows"],
            "sanitization": "secret-bearing-and-chat-rows-omitted; identifiers-and-opaque-values-redacted; source-text-never-copied-into-manifest",
            "runtimeCoverage": "broad-sanitized-Madeira-log-including-process-module-allocator-build-and-clock-rows-when-present; not-a-complete-live-inventory",
            "snapshot": "bounded-startup-and-latest-complete-rows; live-files-may-grow-or-rotate; source-size-sampled-once-per-file"]
        try add("metadata.json", json(metadata(bundleInfo, now: now, uptime: uptime)))
        try add("clocks-and-markers.json", json(clocks))
        try add("manifest.json", json(manifest))
        try add("README.txt", Data("Madeira run diagnostics\nStreaming sanitized session/CS2/Steam evidence with bounded build metadata, clocks and typed VAC observations. manifest.json records unavailable sources, budgets, redactions, omissions and live-file changes. Gap markers separate selected windows. No installed files, settings or account data are changed.\n".utf8))
        do { try writer.finish() }
        catch { throw Failure.stage("finishing the run archive", (error as NSError).code) }
        try check()
        var published = stat()
        guard lstat(result.path, &published) == 0, published.st_uid == getuid(),
              published.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), published.st_mode & 0o777 == 0o600,
              published.st_dev == archiveIdentity.st_dev, published.st_ino == archiveIdentity.st_ino,
              published.st_size > 0, UInt64(published.st_size) <= UInt64(limits.totalBytes + (1 << 20)) else {
            throw Failure.stage("validating the completed run archive", 0)
        }
        complete = true
        return result
    }
}
