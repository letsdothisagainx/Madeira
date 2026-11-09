// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Madeira contributors
// Madeira Converter Exception: see LICENSE-EXCEPTION.md
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// An explicit user export, never a launch task or a security verdict. Raw log
/// bodies are not exported. Each accepted row is decoded with a closed schema
/// and encoded anew; unknown fields, values and trailing text reject the row.
enum SteamGameDiagnostics {
    struct Entry: Sendable { let name: String; let data: Data }
    struct Limits { var mainBytes = 8 << 20; var otherBytes = 256 << 10; var records = 2048 }
    enum Failure: Error { case unavailable }
    private struct Snapshot { let bytes: Data; let identity: String; let truncated: Bool }
    private static let paths: Set<String> = [
        "game/bin/win64/cs2.exe", "game/bin/win64/tier0.dll", "game/bin/win64/engine2.dll",
        "game/bin/win64/filesystem_stdio.dll", "game/bin/win64/rendersystemdx11.dll",
        "game/bin/win64/steam_api64.dll", "game/bin/win64/steamnetworkingsockets.dll",
        "game/csgo/bin/win64/client.dll", "game/csgo/bin/win64/server.dll",
        "game/csgo/pak01_dir.vpk", "game/core/pak01_dir.vpk"
    ]
    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "^(?:" + pattern + ")$", options: .regularExpression) != nil
    }
    private static func number(_ s: String, maximum: UInt64 = 1 << 40) -> Bool {
        matches(s, "[0-9]{1,13}") && UInt64(s).map { $0 <= maximum } == true
    }
    private static func oneOf(_ s: String, _ values: String) -> Bool { values.split(separator: " ").contains(Substring(s)) }
    private static func fields(_ text: String) -> [String: String]? {
        var result: [String: String] = [:]
        for item in text.split(separator: " ", omittingEmptySubsequences: false) {
            let pair = item.split(separator: "=", omittingEmptySubsequences: false)
            guard pair.count == 2, matches(String(pair[0]), "[a-z][a-z0-9-]{0,47}"),
                  !pair[1].isEmpty, result[String(pair[0])] == nil else { return nil }
            result[String(pair[0])] = String(pair[1])
        }
        return result
    }
    private static func keys(_ f: [String: String], _ text: String) -> Bool { Set(f.keys) == Set(text.split(separator: " ").map(String.init)) }
    private static func allNumbers(_ f: [String: String], _ names: String, maximum: UInt64 = 1 << 40) -> Bool {
        names.split(separator: " ").allSatisfy { f[String($0)].map { number($0, maximum: maximum) } == true }
    }
    private static func processIDs(_ f: [String: String]) -> Bool {
        ["pid", "tid"].allSatisfy { f[$0].map { matches($0, "[0-9a-fA-F]{4,8}") } == true }
    }
    /// Only logger prefixes with a fixed grammar are removed. A known tag
    /// embedded inside an arbitrary console line is never accepted.
    private static func payload(_ line: String) -> String? {
        guard !line.isEmpty, line.utf8.count <= 4096,
              line.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value <= 126 }) else { return nil }
        if let r = line.range(of: "^\\[[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\\.[0-9]{3}\\] \\[(INFO|OK|ERR|DBG)\\] ", options: .regularExpression) {
            return String(line[r.upperBound...])
        }
        if let r = line.range(of: "^[0-9a-fA-F]{4,8}:err:wintrust:WinVerifyTrust ", options: .regularExpression) {
            return String(line[r.upperBound...])
        }
        return line
    }
    static func decode(_ line: String) -> (String, [String: String])? {
        guard let p = payload(line), p.first == "[", let end = p.range(of: "] "),
              var f = fields(String(p[end.upperBound...])) else { return nil }
        let tag = String(p[p.index(after: p.startIndex)..<end.lowerBound])
        switch tag {
        case "steam-session-v1":
            guard keys(f, "source role pid tid event reported-token numeric-result-present numeric-result sequence monotonic-ms evidence auth-validation body"), processIDs(f),
                  sourceRole(f), oneOf(f["event"]!, "api-client-loaded api-initialization-failed auth-session-response vac-message steam-servers-connected-message steam-servers-disconnected-message steam-server-connect-failure network-problem-detected-locally network-closed-by-peer network-tos-control-missing network-error-message service-error-message"),
                  oneOf(f["reported-token"]!, "unavailable k_EAuthSessionResponseOK k_EAuthSessionResponseUserNotConnectedToSteam k_EAuthSessionResponseNoLicenseOrExpired k_EAuthSessionResponseVACBanned k_EAuthSessionResponseLoggedInElseWhere k_EAuthSessionResponseVACCheckTimedOut k_EAuthSessionResponseAuthTicketCanceled k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed k_EAuthSessionResponseAuthTicketInvalid k_EAuthSessionResponsePublisherIssuedBan"),
                  oneOf(f["numeric-result-present"]!, "0 1"), number(f["numeric-result"]!, maximum: 255), allNumbers(f, "sequence monotonic-ms"),
                  f["evidence"] == "application-log", f["auth-validation"] == "unclaimed", f["body"] == "excluded" else { return nil }
        case "steam-session-source-v1":
            guard keys(f, "source role pid tid successful-write-observed body authentication-result"), processIDs(f), sourceRole(f),
                  f["successful-write-observed"] == "1", f["body"] == "excluded", f["authentication-result"] == "unknown" else { return nil }
        case "steam-launch-v1":
            guard keys(f, "source app pid tid event task state-flags app-error-present app-error sequence"), processIDs(f), f["app"] == "730",
                  oneOf(f["source"]!, "content gameprocess console"), oneOf(f["event"]!, "game-action process-added process-removed content-state"),
                  oneOf(f["task"]!, "UpdatingAppInfo CheckingAppOwnership UpdatingApp Validating PreparingLaunch ProcessingInstallScript SynchronizingCloud SyncingCloud SiteLicenseSeatCheckout WaitingGameCommandLine CreatingProcess Launching Completing ShowError Waiting none unknown"),
                  matches(f["state-flags"]!, "0x[0-9a-fA-F]{1,8}"), oneOf(f["app-error-present"]!, "0 1"), allNumbers(f, "app-error sequence", maximum: UInt64(UInt32.max)) else { return nil }
        case "steam-service":
            guard f.count == 1, let (key, value) = f.first,
                  oneOf(key, "scm scm-call scm-started open-service service-state service-checkpoint service-wait-hint start-error result update-parent-exit update-witness pipe-enumeration-error service-type service-start-type"),
                  number(value, maximum: UInt64(UInt32.max)) else { return nil }
        case "startup-timeline-v1":
            if f["event"] == "origin" {
                guard keys(f, "event source clock t-ms mono-ns intervals cpu-time"),
                      oneOf(f["source"]!, "app-launch wine-entry first-observed-create"), f["clock"] == "monotonic",
                      number(f["t-ms"]!, maximum: 86_400_000), matches(f["mono-ns"]!, "[0-9]{1,20}"),
                      UInt64(f["mono-ns"]!) != nil, f["intervals"] == "overlap-allowed", f["cpu-time"] == "unmeasured" else { return nil }
                f.removeValue(forKey: "mono-ns") // Relative timing suffices; host uptime is excluded.
                return (tag, f)
            }
            guard keys(f, "event phase attempt creator pid t-ms duration-ms status create-ok intervals"),
                  oneOf(f["event"]!, "create-request server-created native-entry pe-start-dispatch create-return abort-request exit-request owner-quiesced owner-quiesced-status-unobserved"),
                  oneOf(f["phase"]!, "service-launcher steam-service steam-client chromium installscript vcredist-x86 vcredist-x64 msi directx-setup directx-plugin cs2 vcredist-x86-script vcredist-x64-script"),
                  matches(f["creator"]!, "[0-9a-fA-F]{4,8}"), matches(f["pid"]!, "[0-9a-fA-F]{4,8}"),
                  matches(f["status"]!, "[0-9a-fA-F]{8}"), allNumbers(f, "attempt t-ms duration-ms", maximum: 86_400_000),
                  oneOf(f["create-ok"]!, "0 1"), f["intervals"] == "overlap-allowed" else { return nil }
        case "steam-content-audit-v1":
            guard content(f) else { return nil }
        case "trust-result-v1":
            let publicNames = Set(paths.map { String($0.split(separator: "/").last!) })
                .union(["unknown", "steam.exe", "steamservice.exe", "steamclient64.dll", "wintrust.dll", "crypt32.dll", "kernel32.dll", "kernelbase.dll", "ntdll.dll"])
            guard keys(f, "pid action choice kind state result error path name limit"), number(f["pid"]!, maximum: UInt64(UInt32.max)),
                  oneOf(f["action"]!, "unknown 00aac56b-cd44-11d0-8cc2-00c04fc295ee 189a3842-3041-11d1-85e1-00c04fc295ee"),
                  number(f["choice"]!, maximum: 5), oneOf(f["kind"]!, "unknown file catalog blob signer cert"),
                  number(f["state"]!, maximum: 4), matches(f["result"]!, "[0-9a-fA-F]{8}"), number(f["error"]!, maximum: UInt64(UInt32.max)),
                  oneOf(f["path"]!, "unknown bare unc drive other"),
                  f["limit"] == "64-per-process-module" else { return nil }
            // The numeric verifier result remains useful for an unlisted
            // subject. Never export that subject's arbitrary filename.
            let name = f["name"]!.lowercased()
            f["name"] = publicNames.contains(name) ? name : "redacted-unlisted"
        case "cs2-launch-flags-v1":
            guard keys(f, "pid tid steam condebug joy insecure allow-third-party argument-count unknown-count known-sequence parse-complete coverage"), processIDs(f),
                  ["steam", "condebug", "joy", "insecure", "allow-third-party", "parse-complete"].allSatisfy({ oneOf(f[$0]!, "0 1") }),
                  allNumbers(f, "argument-count unknown-count", maximum: 128), f["coverage"] == "accepted-process-params" else { return nil }
            let sequence = f["known-sequence"] == "-" ? [] : f["known-sequence"]!.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard sequence.count <= 128, sequence.allSatisfy({ oneOf($0, "0 1 2 3 4") }),
                  sequence.count + Int(f["unknown-count"]!)! == Int(f["argument-count"]!)!,
                  ["steam", "condebug", "joy", "insecure", "allow-third-party"].enumerated().allSatisfy({
                      f[$0.element] == (sequence.contains(String($0.offset)) ? "1" : "0")
                  }) else { return nil }
        case "cs2-module-v1":
            guard keys(f, "pid tid path-class relative machine hybrid unknown-count dropped-observed sequence limit coverage path-source"), processIDs(f), modulePath(f),
                  oneOf(f["machine"]!, "014c 8664 aa64 a641 a64e unknown"), oneOf(f["hybrid"]!, "0 1 unmeasured"),
                  allNumbers(f, "unknown-count sequence", maximum: 256), number(f["dropped-observed"]!, maximum: 128),
                  UInt64(f["sequence"]!)! > 0, f["limit"] == "256",
                  f["coverage"] == "bounded-observed-load-events", oneOf(f["path-source"]!, "accepted-main-image section-name") else { return nil }
        default: return nil
        }
        return (tag, f)
    }
    private static func modulePath(_ f: [String: String]) -> Bool {
        guard let relative = f["relative"] else { return false }
        switch f["path-class"] {
        case "game": return paths.contains(relative) && !relative.hasSuffix(".vpk")
        case "steam-client": return relative == "steamclient64.dll"
        case "private", "unknown": return relative == "redacted"
        case "system", "search-root":
            let parts = relative.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2,
                  oneOf(parts[0], f["path-class"] == "system" ? "system32 sysx64 syswow64" : "aarch64-windows arm64ec-windows i386-windows") else { return false }
            return oneOf(parts[1], "ntdll.dll kernel32.dll kernelbase.dll wintrust.dll crypt32.dll bcrypt.dll advapi32.dll sechost.dll rpcrt4.dll ws2_32.dll ucrtbase.dll msvcrt.dll win32u.dll user32.dll gdi32.dll d3d11.dll dxgi.dll winemetal.dll setupapi.dll version.dll psapi.dll ole32.dll oleaut32.dll combase.dll coml2.dll winhttp.dll cryptnet.dll ncrypt.dll mswsock.dll shlwapi.dll shell32.dll shcore.dll imm32.dll uxtheme.dll comctl32.dll xtajit64.dll libarm64ecfex.dll")
        default: return false
        }
    }
    private static func sourceRole(_ f: [String: String]) -> Bool {
        switch f["role"] {
        case "cs2": return f["source"] == "cs2-console"
        case "service": return f["source"] == "steam-service"
        case "steam": return oneOf(f["source"] ?? "", "content gameprocess console steam-connection")
        default: return false
        }
    }
    private static func content(_ f: [String: String]) -> Bool {
        guard f["app"] == "730", f["trust"] == "unmeasured" else { return false }
        let states = "unmeasured bounded-comparison stopped-unmeasured install-record-unavailable depot-record-unavailable reference-unavailable reference-conflict time-budget-unmeasured steam-customized-unmeasured file-hash-unavailable byte-budget-unmeasured file-unavailable size-mismatch changed-during-read cache-hash-match cache-hash-mismatch read-incomplete-unmeasured"
        guard oneOf(f["state"] ?? "", states) else { return false }
        if f["phase"] == "summary" {
            return keys(f, "app phase state installed-depots cached-references files bytes reference authentication trust") && allNumbers(f, "installed-depots cached-references files bytes") && f["reference"] == "installed-cache" && f["authentication"] == "not-revalidated"
        }
        let base = "app relative state bytes certificate vpk-signature trust"
        guard paths.contains(f["relative"] ?? ""), number(f["bytes"] ?? ""),
              oneOf(f["certificate"] ?? "", "unmeasured not-pe pe-header-invalid absent table-out-of-file table-limit-unmeasured table-invalid table-present-unverified changed-unmeasured"),
              oneOf(f["vpk-signature"] ?? "", "not-vpk changed-unmeasured header-unmeasured header-invalid v1-section-unavailable format-unsupported-unmeasured section-out-of-file absent section-invalid length-limit-unmeasured section-incomplete-unmeasured section-present-unverified") else { return false }
        if keys(f, base) { return true } // Previous, less detailed producer.
        let extra = "vpk-format vpk-version vpk-type vpk-reserved vpk-offset vpk-declared vpk-key-bytes vpk-signature-bytes vpk-trailing-bytes vpk-tree-bytes vpk-table-offset vpk-table-bytes vpk-other-offset vpk-other-bytes vpk-reason vpk-tree-md5 vpk-table-md5 vpk-whole-md5 vpk-crypto vpk-extra-read-bytes key-provenance archive-payloads vac current-sha1 reference-sha1 hash-source"
        guard keys(f, base + " " + extra), f["relative"]!.hasSuffix("_dir.vpk"),
              oneOf(f["vpk-format"]!, "unknown descriptor20 legacy-inline"),
              oneOf(f["vpk-reason"]!, "not-vpk changed-during-read header-unreadable header-magic v1-no-signature-section version-unsupported v2-header-unreadable declared-section-bounds no-signature-section length-field-unreadable descriptor-size-unsupported descriptor-truncated negative-length descriptor-type-unsupported reserved-unsupported descriptor-key-truncated descriptor-signature-truncated legacy-key-bounds legacy-signature-length-unreadable legacy-payload-bounds trailing-bytes-unsupported audit-key-signature-limit unpaired-key-signature descriptor-without-signature bounded-known-layout"),
              ["vpk-tree-md5", "vpk-table-md5", "vpk-whole-md5"].allSatisfy({ oneOf(f[$0]!, "unmeasured match mismatch") }),
              oneOf(f["vpk-crypto"]!, "unmeasured checksum-preimage-unavailable byte-budget-unmeasured read-incomplete-unmeasured absent preimage-checksum-mismatch key-format-unmeasured key-import-unmeasured algorithm-unavailable consistent-embedded-key mismatch-embedded-key platform-api-unavailable"),
              f["key-provenance"] == "embedded-untrusted", f["archive-payloads"] == "not-read", f["vac"] == "unclaimed", oneOf(f["hash-source"]!, "current-file-read unmeasured") else { return false }
        for key in "vpk-version vpk-type vpk-reserved vpk-offset vpk-declared vpk-key-bytes vpk-signature-bytes vpk-trailing-bytes vpk-tree-bytes vpk-table-offset vpk-table-bytes vpk-other-offset vpk-other-bytes vpk-extra-read-bytes".split(separator: " ") {
            guard f[String(key)] == "unmeasured" || number(f[String(key)]!) else { return false }
        }
        return ["current-sha1", "reference-sha1"].allSatisfy { oneOf(f[$0]!, "unmeasured unavailable") || matches(f[$0]!, "[0-9a-f]{40}") }
    }
    private static func console(_ line: String) -> String? {
        // These exact complete public phrases are useful without exporting
        // arbitrary console text, server addresses, tickets or account names.
        switch line {
        case "VAC was unable to verify your game session.": return "vac-session-unverified-message"
        case "Some of your game files have been detected to have no signatures or invalid signatures. You will not be allowed to join VAC secure servers.",
             "Some of your game files have been detected to have no signatures or invalid signatures. You will not be allowed to join VAC secure servers. Please verify your launch options, check correctness of your game installation, restart the game and try again.":
            return "vac-signature-warning-message"
        case "SteamAPI_Init() failed": return "api-initialization-failed-message"
        case "SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam.": return "steam-client-unavailable-message"
        default: return nil
        }
    }
    /// Every path is a literal below an already opened, app-owned Documents
    /// directory. Neither directory nor final-file symlinks are followed.
    private static func snapshot(_ root: Int32, _ relative: String, maximum: Int, preserveStartup: Bool = false) -> Snapshot? {
        let parts = relative.split(separator: "/").map(String.init)
        guard maximum > 0, !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return nil }
        guard let fd = openOwned(root, parts) else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), info.st_size >= 0 else { return nil }
        let size = UInt64(info.st_size), limit = UInt64(maximum)
        func read(_ offset: UInt64, _ length: Int, cutStart: Bool, cutEnd: Bool) -> Data? {
            var data = Data(count: length)
            let got = data.withUnsafeMutableBytes { raw in pread(fd, raw.baseAddress, length, off_t(offset)) }
            guard got >= 0 else { return nil }
            data.count = got
            if cutStart { if let newline = data.firstIndex(of: 10) { data.removeSubrange(...newline) } else { data.removeAll() } }
            if cutEnd || data.last != 10 { if let newline = data.lastIndex(of: 10) { data.removeSubrange(data.index(after: newline)..<data.endIndex) } else { data.removeAll() } }
            return data
        }
        let data: Data
        if size > limit {
            let head = preserveStartup ? min(maximum * 3 / 4, 6 << 20) : min(maximum / 8, 512 << 10)
            let tail = maximum - head
            guard let first = read(0, head, cutStart: false, cutEnd: true),
                  let last = read(size - UInt64(tail), tail, cutStart: true, cutEnd: false) else { return nil }
            data = first + last
        } else {
            guard let all = read(0, Int(size), cutStart: false, cutEnd: false) else { return nil }; data = all
        }
        return Snapshot(bytes: data, identity: "\(info.st_dev):\(info.st_ino)", truncated: size > limit)
    }
    private static func openOwned(_ root: Int32, _ parts: [String]) -> Int32? {
        var fd = dup(root)
        guard fd >= 0 else { return nil }
        for (i, part) in parts.enumerated() {
            let next = openat(fd, part, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (i == parts.count - 1 ? 0 : O_DIRECTORY))
            close(fd); fd = next
            guard fd >= 0 else { return nil }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == getuid() else { close(fd); return nil }
        }
        return fd
    }
    /// Header-only snapshots of fixed service candidates help distinguish an
    /// on-disk machine mismatch. They do not claim the files were loaded,
    /// signed, trusted, authentic, or used by the current process.
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
    private static func servicePEs(_ root: Int32) -> [[String: String]] {
        let steam = "wine/drive_c/Program Files (x86)/"
        let candidates = [("steam-bin-service-dll-official-case", steam + "Steam/bin/SteamService.dll"),
                          ("steam-bin-service-dll", steam + "Steam/bin/steamservice.dll"),
                          ("steam-bin-service-exe", steam + "Steam/bin/SteamService.exe"),
                          ("common-service-exe", steam + "Common Files/Steam/SteamService.exe")]
        var identities: [String: String] = [:]
        return candidates.map { id, relative in
            var record = ["candidate": id, "evidence": "disk-header-snapshot-not-loaded-image", "machine": "unknown", "state": "unavailable-or-not-owned-regular-file"]
            guard let fd = openOwned(root, relative.split(separator: "/").map(String.init)) else { return record }
            defer { close(fd) }
            var before = stat()
            guard fstat(fd, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), before.st_size >= 64 else { return record }
            let identity = "\(before.st_dev):\(before.st_ino)"
            if let earlier = identities[identity] {
                record["state"] = "same-file-as-earlier-candidate"
                record["sameAsCandidate"] = earlier
                return record
            }
            identities[identity] = id
            func read(_ offset: UInt64, _ count: Int) -> [UInt8]? {
                guard offset <= UInt64(before.st_size), UInt64(count) <= UInt64(before.st_size) - offset else { return nil }
                var data = [UInt8](repeating: 0, count: count)
                let got = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(offset)) }
                return got == count ? data : nil
            }
            guard let dos = read(0, 64), dos[0] == 0x4d, dos[1] == 0x5a else { record["state"] = "invalid-dos-header"; return record }
            let offset = UInt64(dos[60]) | UInt64(dos[61]) << 8 | UInt64(dos[62]) << 16 | UInt64(dos[63]) << 24
            guard offset >= 64, offset <= 1 << 20, let coff = read(offset, 24), Array(coff[0..<4]) == [0x50, 0x45, 0, 0] else { record["state"] = "invalid-pe-header"; return record }
            var after = stat()
            guard fstat(fd, &after) == 0, unchanged(before, after) else { record["state"] = "changed-unmeasured"; return record }
            let machine = String(format: "%04x", UInt16(coff[4]) | UInt16(coff[5]) << 8)
            record["machine"] = oneOf(machine, "014c 8664 aa64 a641 a64e") ? machine : "unknown"
            record["state"] = "header-read-only-not-authenticated"
            return record
        }
    }
    static func collect(documents: URL, limits: Limits = Limits()) throws -> [Entry] {
        guard limits.mainBytes > 0, limits.mainBytes <= 16 << 20, limits.otherBytes > 0,
              limits.otherBytes <= 1 << 20, limits.records > 0, limits.records <= 4096 else { throw Failure.unavailable }
        let root = open(documents.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw Failure.unavailable }
        defer { close(root) }
        var rootInfo = stat()
        guard fstat(root, &rootInfo) == 0, rootInfo.st_uid == getuid() else { throw Failure.unavailable }
        var observations: [[String: Any]] = [], sources: [[String: Any]] = [], identities: [String: String] = [:]
        var omitted = 0, scanned = 0, scanLimitReached = false
        var alias: String?, build = "unmeasured"
        func consume(_ id: String, _ path: String, _ maximum: Int) {
            guard let file = snapshot(root, path, maximum: maximum, preserveStartup: id == "madeira-session") else {
                sources.append(["source": id, "state": "unavailable-or-not-owned-regular-file"]); return
            }
            if let original = identities[file.identity] {
                var source = ["source": id, "state": "same-file-as-earlier-source", "sameAsSource": original]
                if id == "cs2-session-alias" && original == "madeira-session" {
                    source["provenance"] = "session-alias-is-main-runtime-log-not-game-console"
                }
                sources.append(source); return
            }
            identities[file.identity] = id
            var captured = 0, lineStart = file.bytes.startIndex
            // Incremental scan: Data.split would allocate one subsequence per
            // newline before any record cap (millions for an 8-MiB blank log).
            while lineStart < file.bytes.endIndex {
                guard scanned < 131072 else { scanLimitReached = true; break }
                guard let newline = file.bytes[lineStart...].firstIndex(of: 10) else { break }
                var bytes = file.bytes[lineStart..<newline]
                lineStart = file.bytes.index(after: newline)
                scanned += 1
                if bytes.last == 13 { bytes = bytes.dropLast() }
                guard bytes.count <= 4096, let line = String(bytes: bytes, encoding: .utf8) else { omitted += 1; continue }
                if id == "madeira-session", let p = payload(line) {
                    let prefix = "[session-log] Steam game cs2.exe: logs/"
                    if p.hasPrefix(prefix) {
                        let name = String(p.dropFirst(prefix.count))
                        if matches(name, "cs2\\.exe-[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}\\.txt") { alias = "logs/" + name }
                    }
                    if matches(p, "\\[build\\] v[0-9.]{1,16} \\([0-9]{1,5}\\) source=[0-9a-f]{40}") { build = String(p.suffix(40)) }
                }
                guard observations.count < limits.records else { omitted += 1; continue }
                // Native structured producers write the runtime log. Official
                // console bodies cannot impersonate an audit/hash/module row.
                if id == "madeira-session", let (tag, fields) = decode(line) {
                    observations.append(["source": id, "record": tag, "fields": fields]); captured += 1
                } else if id != "madeira-session", let event = console(line) {
                    observations.append(["source": id, "record": "fixed-console-message", "fields": ["event": event, "evidence": "application-message-not-security-verdict"]]); captured += 1
                } else { omitted += 1 }
            }
            sources.append(["source": id, "state": "bounded-snapshot", "bytesRead": file.bytes.count, "truncated": file.truncated, "capturedRecords": captured])
        }
        consume("madeira-session", "madeira-log.txt", limits.mainBytes)
        if let alias { consume("cs2-session-alias", alias, limits.otherBytes) }
        let steam = "wine/drive_c/Program Files (x86)/Steam/"
        for (id, path) in [("steam-console", "logs/console_log.txt"), ("steam-gameprocess", "logs/gameprocess_log.txt"),
                           ("steam-connection", "logs/connection_log.txt"), ("steam-service", "logs/service_log.txt"),
                           ("cs2-console", "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log")] {
            consume(id, steam + path, limits.otherBytes)
        }
        func coverage(_ tag: String) -> String {
            observations.contains { $0["record"] as? String == tag } ? "observed-allowlisted-events" : "no-observed-dedicated-events-unmeasured"
        }
        let manifest: [String: Any] = ["schema": "madeira-steam-cs2-diagnostics-v1", "sourceCommit": build,
            "collection": "explicit-user-action-bounded-head-and-tail-snapshot", "sources": sources,
            "mainByteBudget": limits.mainBytes, "mainPrefixBudget": min(limits.mainBytes * 3 / 4, 6 << 20),
            "mainSuffixBudget": limits.mainBytes - min(limits.mainBytes * 3 / 4, 6 << 20),
            "recordsCaptured": observations.count, "rowsScanned": scanned, "rowsOmittedWithinScan": omitted,
            "scanLimitReached": scanLimitReached, "maxRowsScanned": 131072,
            "rawLogBodies": "excluded", "accountAndAuthenticationData": "excluded-by-closed-schema",
            "moduleCoverage": "observed-allowlisted-loader-events-only-not-complete-inventory",
            "effectiveArguments": "only-dedicated-flag-observations-no-raw-command-lines",
            "knownArgumentIDs": ["0": "-steam", "1": "-condebug", "2": "-joy", "3": "-insecure", "4": "-allow_third_party_software"],
            "argumentCompleteness": "complete-only-when-parse-complete-1-and-unknown-count-0",
            "flagSemantics": "observed-tokens-not-engine-option-interpretation-zeros-unobserved-when-incomplete",
            "machineInterpretation": "raw-PE-machine-plus-separate-hybrid-observation-8664-does-not-imply-pure-AMD64",
            "launchFlagObservations": coverage("cs2-launch-flags-v1"),
            "moduleObservations": coverage("cs2-module-v1"),
            "trustObservations": coverage("trust-result-v1"),
            "sessionObservations": coverage("steam-session-v1"),
            "authenticationVerdict": "unmeasured", "vacVerdict": "unmeasured",
            "trustVerdict": "unmeasured",
            "trustObservationScope": "application-reported-WinVerifyTrust-results-not-independent-validation",
            "structuredProducerRows": "accepted-from-main-runtime-log-only",
            "numericSessionResultDomain": "unknown-do-not-infer-authentication-status",
            "externalGameLibraries": "not-followed-unmeasured",
            "consoleCoverage": "exact-known-messages-only-unknown-lines-omitted",
            "serviceDiskPEObservations": servicePEs(root)]
        func json(_ object: Any) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) }
        let explanation = """
        Madeira Steam/CS2 diagnostic observations
        This archive contains newly encoded allowlisted events, not raw logs.
        It cannot establish VAC eligibility, authentication success or file trust.
        Sources are bounded snapshots taken only when Export is pressed. Missing,
        unknown, modified-schema and sensitive lines are omitted. External library
        symlinks are not followed. Module events are a lower-bound observation.
        Timestamped cs2.exe session logs are aliases/hardlinks of the Madeira
        runtime log; they are not independent game-console evidence. Source2's
        actual console.log is a distinct source when present and safely readable.
        No installation, runtime, game, account or registry file is changed.
        """
        return [Entry(name: "manifest.json", data: try json(manifest)), Entry(name: "observations.json", data: try json(observations)), Entry(name: "README.txt", data: Data(explanation.utf8))]
    }
}

#if canImport(SwiftUI) && canImport(UIKit)
import SwiftUI
import UIKit

struct SteamGameDiagnosticsExportButton: View {
    private struct Export: Identifiable { let id = UUID(); let url: URL }
    @State private var preparing = false
    @State private var export: Export?
    @State private var failed = false
    var body: some View {
        Button {
            preparing = true
            Task {
                do { export = Export(url: try await LogStore.shared.exportSteamGameDiagnostics()) }
                catch { failed = true }
                preparing = false
            }
        } label: {
            HStack {
                Label("Export Steam/CS2 Diagnostics", systemImage: "square.and.arrow.up")
                if preparing { Spacer(); ProgressView() }
            }
        }
        .disabled(preparing)
        .sheet(item: $export) { ActivitySheet(items: [$0.url]) }
        .alert("Diagnostics unavailable", isPresented: $failed) {
            Button("OK", role: .cancel) { }
        } message: { Text("The diagnostic package could not be prepared. Your existing logs and game files are unchanged.") }
    }
}
#endif
