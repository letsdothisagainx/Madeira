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
    private struct ConsoleCandidate {
        var fields: [String: String]
        let row: Int
        let priority: Int
        let markerDistance: Int?
    }
    private struct MarkerWallClock { let second: Int; let leapYear: Bool }
    private static let paths: Set<String> = [
        "game/bin/win64/cs2.exe", "game/bin/win64/tier0.dll", "game/bin/win64/engine2.dll",
        "game/bin/win64/filesystem_stdio.dll", "game/bin/win64/rendersystemdx11.dll",
        "game/bin/win64/steam_api64.dll", "game/bin/win64/steamnetworkingsockets.dll",
        "game/csgo/bin/win64/client.dll", "game/csgo/bin/win64/server.dll",
        "game/csgo/pak01_dir.vpk", "game/core/pak01_dir.vpk"
    ]
    // Diagnostic layout candidates only. Matching a literal accepted loader
    // path identifies a catalog entry, never its publisher or file trust.
    // Keep this separate from the content audit's deliberately smaller list.
    private static let moduleGamePaths = Set(paths.filter { !$0.hasSuffix(".vpk") }).union([
        "game/bin/win64/sdl3.dll", "game/bin/win64/inputsystem.dll", "game/bin/win64/imemanager.dll",
        "game/bin/win64/gameinput.dll", "game/bin/win64/localize.dll", "game/bin/win64/amd_ags_x64.dll",
        "game/bin/win64/d3dcompiler_47.dll", "game/bin/win64/resourcesystem.dll"
    ])
    private static let moduleSteamNames: Set<String> = [
        "steamclient64.dll", "tier0_s64.dll", "vstdlib_s64.dll", "crashhandler64.dll", "gameoverlayrenderer64.dll"
    ]
    private static let moduleSystemNames: Set<String> = [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "wintrust.dll", "crypt32.dll", "bcrypt.dll",
        "advapi32.dll", "sechost.dll", "rpcrt4.dll", "ws2_32.dll", "ucrtbase.dll", "msvcrt.dll",
        "win32u.dll", "user32.dll", "gdi32.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll", "winemetal.dll", "nvapi64.dll",
        "setupapi.dll", "version.dll", "psapi.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
        "coml2.dll", "winhttp.dll", "cryptnet.dll", "ncrypt.dll", "mswsock.dll", "shlwapi.dll",
        "shell32.dll", "shcore.dll", "imm32.dll", "uxtheme.dll", "comctl32.dll", "xtajit64.dll", "libarm64ecfex.dll",
        "cryptbase.dll", "winmm.dll", "msacm32.dll", "iphlpapi.dll", "dnsapi.dll", "nsi.dll",
        "dbghelp.dll", "imagehlp.dll", "cfgmgr32.dll", "secur32.dll", "wininet.dll", "mpr.dll",
        "hid.dll", "dwmapi.dll", "dinput8.dll", "wsock32.dll", "mmdevapi.dll", "avrt.dll", "schannel.dll", "rsaenh.dll"
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
    /// The old loader row contains a speculative comment. Match its exact
    /// producer grammar, but retain only the actual Wine result, not that
    /// comment's proposed cause. The prefix identifies a TID, never a PID.
    private static func serviceLoader(_ line: String) -> [String: String]? {
        let introducer = ":err:module:load_dll [dll-missing] rev=ml336 #"
        guard let marker = line.range(of: introducer) else { return nil }
        let tid = String(line[..<marker.lowerBound])
        guard matches(tid, "[0-9a-fA-F]{4,8}") else { return nil }
        let remainder = line[marker.upperBound...]
        guard let space = remainder.firstIndex(of: " ") else { return nil }
        let occurrence = String(remainder[..<space])
        guard matches(occurrence, "[1-9][0-9]?"), number(occurrence, maximum: 60) else { return nil }
        let detail = String(remainder[remainder.index(after: space)...])
        let suffix = " -- if the webhelper dies right after this, it is the delay-load Chromium kills the process over"
        let location: String, status: String
        if detail == #"L"C:\\Program Files (x86)\\Steam\\bin\\steamservice.dll" status=c000007b"# + suffix {
            location = "steam-bin"; status = "c000007b"
        } else if detail == #"L"steamservice.dll" status=c0000135"# + suffix {
            location = "bare"; status = "c0000135"
        } else { return nil }
        return ["tid": tid.lowercased(), "pid": "unmeasured", "status": status,
                "dll": "steamservice.dll", "location": location, "occurrence": occurrence,
                "evidence": "wine-loader-result"]
    }
    static func decode(_ line: String) -> (String, [String: String])? {
        guard let p = payload(line) else { return nil }
        if let result = serviceLoader(p) { return ("steam-service-loader-v1", result) }
        guard p.first == "[", let end = p.range(of: "] "),
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
                f["clock-domain"] = "wine-posix-monotonic-relative-to-startup-origin"
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
        case "native-steam-verify-v1":
            guard keys(f, "app phase mechanism result completion"), f["app"] == "730",
                  f["phase"] == "requested", f["mechanism"] == "steam-validate",
                  f["result"] == "unobserved", f["completion"] == "steam-ui" else { return nil }
        case "cs2-user-marker-v1":
            guard keys(f, "kind source input app context pid session sequence utc utc-offset-min monotonic-ms evidence"),
                  oneOf(f["kind"]!, "session-begin session-end process-observed test-begin error-reported input"),
                  oneOf(f["source"]!, "library runtime user input-layer"),
                  oneOf(f["input"]!, "none pointer keyboard controller touch"), oneOf(f["app"]!, "730 unmeasured"),
                  oneOf(f["context"]!, "cs2-requested cs2-observed unmeasured"),
                  f["pid"] == "unmeasured" || matches(f["pid"]!, "[0-9a-fA-F]{4,8}"),
                  allNumbers(f, "session sequence", maximum: 4096), UInt64(f["sequence"]!)! > 0,
                  matches(f["utc"]!, #"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z"#),
                  matches(f["utc-offset-min"]!, "-?(?:0|[1-9][0-9]{0,2})"),
                  let offset = Int(f["utc-offset-min"]!), (-840...840).contains(offset),
                  number(f["monotonic-ms"]!, maximum: 1 << 52) else { return nil }
            let identity = [f["kind"]!, f["source"]!, f["evidence"]!].joined(separator: ":")
            guard oneOf(identity, "session-begin:library:library-lifecycle session-end:library:library-lifecycle process-observed:runtime:accepted-process-observation test-begin:user:user-report error-reported:user:user-report input:input-layer:input-dispatch"),
                  (f["kind"] == "input") == (f["input"] != "none") else { return nil }
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
            let base = "pid tid path-class relative machine hybrid unknown-count dropped-observed sequence limit coverage path-source"
            guard keys(f, base) || keys(f, base + " wine-builtin header-source") else { return nil }
            guard processIDs(f), modulePath(f),
                  oneOf(f["machine"]!, "014c 8664 aa64 a641 a64e unknown"), oneOf(f["hybrid"]!, "0 1 unmeasured"),
                  allNumbers(f, "unknown-count sequence", maximum: 256), number(f["dropped-observed"]!, maximum: 128),
                  UInt64(f["sequence"]!)! > 0, f["limit"] == "256",
                  f["coverage"] == "bounded-observed-load-events", oneOf(f["path-source"]!, "accepted-main-image section-name") else { return nil }
            if let builtin = f["wine-builtin"] {
                guard oneOf(builtin, "0 1 unmeasured"), f["header-source"] == "accepted-image-info" else { return nil }
            } else {
                f["wine-builtin"] = "unmeasured"
                f["header-source"] = "legacy-machine-hybrid-only"
            }
            f["catalog-role"] = moduleCatalogRole(f)
        case "cs2-guest-debug-v1":
            guard keys(f, "pid tid being-debugged nt-global-flag limit coverage evidence scope"), processIDs(f),
                  oneOf(f["being-debugged"]!, "0 1 unmeasured"),
                  f["nt-global-flag"] == "unmeasured" || matches(f["nt-global-flag"]!, "[0-9a-f]{8}"),
                  f["limit"] == "1-per-process", f["coverage"] == "accepted-post-server-init-snapshot",
                  f["evidence"] == "fault-safe-peb-read-only", f["scope"] == "guest-peb-fields-only" else { return nil }
        default: return nil
        }
        if tag == "cs2-user-marker-v1" { f["monotonic-clock-domain"] = "app-dispatch-uptime" }
        if tag == "steam-session-v1" { f["monotonic-clock-domain"] = "wine-posix-clock-monotonic" }
        if tag == "startup-timeline-v1" { f["clock-domain"] = "wine-posix-monotonic-relative-to-startup-origin" }
        return (tag, f)
    }
    private static func modulePath(_ f: [String: String]) -> Bool {
        guard let relative = f["relative"] else { return false }
        switch f["path-class"] {
        case "game": return moduleGamePaths.contains(relative)
        case "steam-client": return moduleSteamNames.contains(relative)
        case "private", "unknown": return relative == "redacted"
        case "system", "search-root":
            let parts = relative.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2,
                  oneOf(parts[0], f["path-class"] == "system" ? "system32 sysx64 syswow64" : "aarch64-windows arm64ec-windows i386-windows") else { return false }
            return moduleSystemNames.contains(parts[1])
        default: return false
        }
    }
    private static func moduleCatalogRole(_ f: [String: String]) -> String {
        switch f["path-class"] {
        case "game": return "cs2-game-layout"
        case "steam-client": return "steam-client-layout"
        case "system", "search-root":
            let name = f["relative"]!.split(separator: "/").last!
            if ["xtajit64.dll", "libarm64ecfex.dll"].contains(String(name)) { return "fex-runtime-name" }
            if ["d3d9.dll", "d3d11.dll", "dxgi.dll", "winemetal.dll", "nvapi64.dll"].contains(String(name)) { return "dxmt-runtime-name" }
            return "windows-runtime-name"
        default: return "unclassified"
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
    /// Real Source2 console messages are decoded from their own source. The
    /// optional MM/DD wall clock has no year or zone; it is never silently
    /// equated to a UTC runtime marker. Identifiers captured to recognize the
    /// grammar are discarded, not copied or redacted by a permissive regex.
    private static func captures(_ text: String, _ pattern: String) -> [String]? {
        guard let expression = try? NSRegularExpression(pattern: "^(?:" + pattern + ")$"),
              let match = expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              match.range.length == text.utf16.count else { return nil }
        return (1..<match.numberOfRanges).map { index in
            guard let range = Range(match.range(at: index), in: text) else { return "" }
            return String(text[range])
        }
    }
    static func decodeConsole(_ original: String) -> [String: String]? {
        var line = original
        if line.first == "\u{feff}" { line.removeFirst() }
        guard !line.isEmpty, line.utf8.count <= 4096,
              line.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value <= 126 }) else { return nil }
        var body = line, timestamp = "unmeasured"
        if let parts = captures(line, #"((?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]) (.+)"#) {
            timestamp = parts[0]; body = parts[1]
        }
        var result = ["event": "", "console-time": timestamp, "clock": "console-wall-year-zone-unmeasured",
                      "evidence": "application-console-message-not-security-verdict"]
        func finish(_ event: String, _ values: [String: String] = [:]) -> [String: String] {
            result["event"] = event; result.merge(values) { _, next in next }; return result
        }
        switch body {
        case "VAC was unable to verify your game session.": return finish("vac-session-unverified-message")
        case "Some of your game files have been detected to have no signatures or invalid signatures. You will not be allowed to join VAC secure servers.",
             "Some of your game files have been detected to have no signatures or invalid signatures. You will not be allowed to join VAC secure servers. Please verify your launch options, check correctness of your game installation, restart the game and try again.":
            return finish("vac-signature-warning-message")
        case "SteamAPI_Init() failed": return finish("api-initialization-failed-message")
        case "SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam.": return finish("steam-client-unavailable-message")
        case "PIX/NSIGHT WAS detected.": return finish("engine-pix-nsight-reported", ["actual-instrumentation": "unmeasured", "vac-causality": "unmeasured"])
        case "Source2Init OK": return finish("source2-initialized")
        case "ChangeGameUIState: CSGO_GAME_UI_STATE_INVALID -> CSGO_GAME_UI_STATE_MAINMENU":
            return finish("main-menu-state-reported")
        case "[Steam] Running SteamAPI_RunCallbacks for first time": return finish("steam-callbacks-started")
        case "[SteamNetSockets] Initialized low level socket/threading support.": return finish("networking-support-initialized")
        case "[Server] SV:  Executing listen server config file": return finish("listen-server-config", ["connection-scope": "local-not-secure-proof"])
        case "[Client] CL:  CCreateGameClientJob creating client connection to 'loopback'":
            return finish("connection-attempt", ["connection-scope": "local-loopback"])
        case "[Client] CL:  Connected to 'loopback:1'": return finish("local-loopback-connected", ["connection-scope": "local-not-secure-proof"])
        case "[Client] CL:  CGameClientConnectPrerequisite connection succeeded": return finish("client-connection-reported", ["connection-scope": "unmeasured"])
        case "[Localization System] CLocalize::CompileString failed to localize: '#GenericConfirmText_Label'":
            return finish("generic-confirm-localization-warning", ["popup-association": "unmeasured"])
        default: break
        }
        if let values = captures(body, #"\[SteamNetSockets\] AuthStatus \(steamid:[0-9]{17}\):  (Attempting|OK)  \((Requesting cert|OK)\)"#),
           (values[0] == "Attempting" && values[1] == "Requesting cert") || (values[0] == "OK" && values[1] == "OK") {
            return finish("network-auth-status", ["network-auth-status": values[0] == "OK" ? "ok" : "requesting-certificate", "vac-approval": "unmeasured"])
        }
        if let values = captures(body, #"\[SteamNetSockets\] Certificate expires in ([0-9]{1,3})h([0-5]?[0-9])m at [0-9]{1,20} \(current time [0-9]{1,20}\), will renew in ([0-9]{1,3})h([0-5]?[0-9])m"#) {
            return finish("network-certificate-renewal-scheduled", ["expires-in-minutes": String(Int(values[0])! * 60 + Int(values[1])!),
                "renew-in-minutes": String(Int(values[2])! * 60 + Int(values[3])!), "vac-approval": "unmeasured"])
        }
        if let values = captures(body, #"\[SteamNetSockets\] SDR network config fetch attempt #([0-9]{1,3}) failed\.  HTTP ([1-5][0-9]{2})\.  \.  Trying again\."#) {
            return finish("relay-config-retry", ["attempt": values[0], "http-status": values[1], "vac-causality": "unmeasured"])
        }
        if captures(body, #"\[SteamNetSockets\] Got SDR network config\.  Loaded revision [0-9]{1,13} OK"#) != nil {
            return finish("relay-config-loaded")
        }
        if let values = captures(body, #"\[SteamNetSockets\] SDR RelayNetworkStatus:  avail=OK  config=OK  anyrelay=OK   \(OK\.  Relays: ([0-9]{1,6}) valid, [0-9]{1,6} great, [0-9]{1,6} good\+, [0-9]{1,6} ok\+, [0-9]{1,6} ignored\)"#) {
            return finish("relay-network-ready", ["available": "ok", "config": "ok", "any-relay": "ok", "valid-relays": values[0], "vac-approval": "unmeasured"])
        }
        if captures(body, #"\[Networking\] Connected loopback client=[0-9a-fA-F]{8}@loopback:1 <-> server=[0-9a-fA-F]{8}@loopback:0"#) != nil {
            return finish("local-loopback-connected", ["connection-scope": "local-not-secure-proof"])
        }
        if let values = captures(body, #"\[SteamNetSockets\] Waited ([0-9]{1,5}(?:\.[0-9])?)ms for SteamNetworkingSockets lock \[(ServiceThread|ReceiveMessagesOnChannel)\]"#),
           let duration = Double(values[0]), duration <= 60_000 {
            return finish("network-lock-wait", ["duration-ms": values[0], "context": values[1], "vac-causality": "unmeasured"])
        }
        if let values = captures(body, #"\[SteamNetSockets\] SteamNetworkingSockets lock held for ([0-9]{1,5}(?:\.[0-9])?)ms\.  \(Performance warning\.\)  ([A-Za-z0-9_:(),]+)"#),
           let duration = Double(values[0]), duration <= 60_000 {
            let publicTraceNames: Set<String> = ["ServiceThread", "SteamDatagramClientThinker::Think", "EnsureDataCenterRoutesValid",
                "ThinkPingProbes", "FindServerDataForCluster", "SendUDPacket", "SteamNetworkingSocketsCert_t", "AsyncCertRequestFinished",
                "BeginFetchNetworkConfig", "HTTPRequestCompleted_t", "RecvUDPPacket", "CreateSocketPair", "Base::BInitConnection",
                "FinalizeLocalCrypto", "BRecvCryptoHandshake", "BFinishCryptoHandshake", "CSteamNetworkConnectionBase::Think", "SendMessages"]
            let names = values[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard !names.isEmpty, names.count <= 32, names.allSatisfy({
                publicTraceNames.contains($0.replacingOccurrences(of: #"\(x[24]\)$"#, with: "", options: .regularExpression))
            }) else { return nil }
            return finish("network-lock-held", ["duration-ms": values[0], "vac-causality": "unmeasured"])
        }
        if let values = captures(body, #"\[SteamNetSockets\] src\\steamnetworkingsockets\\clientlib\\steamnetworkingsockets_lowlevel\.cpp\(2874\): SteamnetworkingSockets service thread waited ([0-9]{1,5})ms for lock!  This directly adds to network latency!  It could be a bug, but it's usually caused by general performance problem such as thread starvation or a debug output handler taking too long\."#),
           let duration = Double(values[0]), duration <= 60_000 {
            return finish("network-service-thread-delayed", ["duration-ms": values[0], "vac-causality": "unmeasured"])
        }
        return nil
    }
    // Console year/zone are unknown. This coordinate is used only to prefer
    // nearby records under an explicit device-local-wall-clock assumption;
    // it never assigns a UTC instant or proves a shared clock or causality.
    private static func wallSecond(_ text: String, leapYear: Bool) -> Int? {
        let parts = text.split(whereSeparator: { $0 == "/" || $0 == " " || $0 == ":" })
        guard parts.count == 5 else { return nil }
        let numbers = parts.compactMap { Int($0) }
        let days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard numbers.count == 5, (1...12).contains(numbers[0]), (1...days[numbers[0] - 1]).contains(numbers[1]),
              (0...23).contains(numbers[2]), (0...59).contains(numbers[3]), (0...59).contains(numbers[4]) else { return nil }
        return (((days.prefix(numbers[0] - 1).reduce(0, +) + numbers[1] - 1) * 24 + numbers[2]) * 60 + numbers[3]) * 60 + numbers[4]
    }
    private static func markerWallSecond(_ fields: [String: String]) -> MarkerWallClock? {
        guard fields["kind"] == "error-reported", fields["app"] == "730", let utc = fields["utc"],
              let offset = fields["utc-offset-min"].flatMap(Int.init) else { return nil }
        let format = ISO8601DateFormatter()
        format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = format.date(from: utc) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date.addingTimeInterval(Double(offset * 60)))
        guard let year = c.year, let month = c.month, let day = c.day, let hour = c.hour, let minute = c.minute, let second = c.second else { return nil }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        guard let value = wallSecond(String(format: "%02d/%02d %02d:%02d:%02d", month, day, hour, minute, second), leapYear: leap) else { return nil }
        return MarkerWallClock(second: value, leapYear: leap)
    }
    private static func preferred(_ lhs: ConsoleCandidate, _ rhs: ConsoleCandidate) -> Bool {
        if lhs.priority != rhs.priority { return lhs.priority > rhs.priority }
        let left = lhs.markerDistance ?? Int.max, right = rhs.markerDistance ?? Int.max
        if left != right { return left < right }
        return lhs.row > rhs.row
    }
    private static func retain(_ candidate: ConsoleCandidate, in selected: inout [ConsoleCandidate], limit: Int) {
        guard limit > 0 else { return }
        if selected.count == limit, let last = selected.last, !preferred(candidate, last) { return }
        var low = 0, high = selected.count
        while low < high {
            let middle = (low + high) / 2
            if preferred(candidate, selected[middle]) { high = middle } else { low = middle + 1 }
        }
        selected.insert(candidate, at: low)
        if selected.count > limit { selected.removeLast() }
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
        var markerIDs: Set<String> = []
        var alias: String?, build = "unmeasured"
        func append(_ id: String, _ record: String, _ fields: [String: String], row: Int?) -> Bool {
            guard observations.count < limits.records else { return false }
            if record == "cs2-user-marker-v1" {
                let identity = (fields["session"] ?? "") + ":" + (fields["sequence"] ?? "")
                guard markerIDs.insert(identity).inserted else { return false }
            }
            var event: [String: Any] = ["source": id, "record": record, "fields": fields]
            if let row { event["rowInBoundedSnapshot"] = row }
            observations.append(event)
            return true
        }
        // The in-memory ring reserves recent user/input markers independently
        // of a noisy runtime log. Repeated stderr copies are deduplicated.
        let markerCap = min(256, max(1, limits.records / 8))
        var markerCaptured = 0
        for line in CS2VACMarkers.snapshotLines().suffix(markerCap) {
            if let (tag, fields) = decode(line), tag == "cs2-user-marker-v1",
               append("madeira-marker-ring", tag, fields, row: nil) { markerCaptured += 1 }
        }
        sources.append(["source": "madeira-marker-ring", "state": "bounded-memory-snapshot",
                        "provenance": "app-owned-marker-ring-not-game-security-verdict", "capturedRecords": markerCaptured])
        func consume(_ id: String, _ path: String, _ maximum: Int, _ recordCap: Int, _ rowCap: Int) {
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
            var captured = 0, rows = 0, budgetOmitted = 0, lineStart = file.bytes.startIndex
            var rowLimitReached = false
            let console = id == "cs2-console"
            let performanceBudget = console ? min(32, recordCap / 8) : 0
            var selectedEvents: [ConsoleCandidate] = [], selectedPerformance: [ConsoleCandidate] = []
            var decodedConsole = 0, sampledPerformance = 0, performanceCounts: [String: Int] = [:]
            let markerClocks = console ? observations.compactMap { event -> MarkerWallClock? in
                guard event["record"] as? String == "cs2-user-marker-v1", let fields = event["fields"] as? [String: String] else { return nil }
                return markerWallSecond(fields)
            }.suffix(8) : []
            // Source-local row and record caps prevent a giant main log from
            // starving the actual console. Never allocate Data.split's one
            // subsequence per newline before applying those caps.
            while lineStart < file.bytes.endIndex {
                guard rows < rowCap else { rowLimitReached = true; scanLimitReached = true; break }
                guard let newline = file.bytes[lineStart...].firstIndex(of: 10) else { break }
                var bytes = file.bytes[lineStart..<newline]
                lineStart = file.bytes.index(after: newline)
                rows += 1; scanned += 1
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
                if console, var fields = decodeConsole(line) {
                    decodedConsole += 1
                    let event = fields["event"]!
                    let performance = ["network-lock-held", "network-lock-wait", "network-service-thread-delayed"].contains(event)
                    if performance { performanceCounts[event, default: 0] += 1 }
                    let distance = fields["console-time"].flatMap { time in
                        markerClocks.compactMap { anchor -> Int? in
                            guard let second = wallSecond(time, leapYear: anchor.leapYear) else { return nil }
                            let raw = abs(second - anchor.second)
                            return min(raw, (anchor.leapYear ? 366 : 365) * 86400 - raw)
                        }.min()
                    }
                    let nearby = distance.map { $0 <= 30 } == true
                    if nearby {
                        fields["marker-wall-proximity-seconds"] = String(distance!)
                        fields["marker-wall-proximity-basis"] = "assumes-console-matches-marker-device-local-wall-clock"
                    }
                    let critical = ["vac-session-unverified-message", "vac-signature-warning-message", "api-initialization-failed-message", "steam-client-unavailable-message"].contains(event)
                    let priority = critical ? 4 : event == "generic-confirm-localization-warning" ? 3 : nearby ? 2 : 1
                    let candidate = ConsoleCandidate(fields: fields, row: rows, priority: priority, markerDistance: distance)
                    if performance { retain(candidate, in: &selectedPerformance, limit: performanceBudget) }
                    else { retain(candidate, in: &selectedEvents, limit: recordCap - performanceBudget) }
                    continue
                }
                guard captured < recordCap, observations.count < limits.records else { budgetOmitted += 1; omitted += 1; continue }
                // Structured producers are accepted only from the runtime
                // log/ring; official console text cannot impersonate them.
                if id == "madeira-session", let (tag, fields) = decode(line) {
                    if append(id, tag, fields, row: rows) { captured += 1 }
                } else { omitted += 1 }
            }
            if console {
                for candidate in (selectedEvents + selectedPerformance).sorted(by: { $0.row < $1.row }) {
                    if append(id, "application-console-event", candidate.fields, row: candidate.row) {
                        captured += 1
                        if performanceCounts[candidate.fields["event"]!] != nil { sampledPerformance += 1 }
                    } else { budgetOmitted += 1 }
                }
                omitted += decodedConsole - captured
            }
            var source: [String: Any] = ["source": id, "state": "bounded-snapshot", "bytesRead": file.bytes.count,
                "truncated": file.truncated, "capturedRecords": captured, "recordBudget": recordCap,
                "rowsScanned": rows, "rowBudget": rowCap, "rowLimitReached": rowLimitReached,
                "rowsOmittedByRecordBudget": budgetOmitted]
            if console {
                source["selection"] = "fixed-event-priority-and-assumed-marker-wall-proximity-within-byte-snapshot"
                source["performanceSampleBudget"] = performanceBudget
                source["performanceEventsObserved"] = performanceCounts
                source["performanceEventsSampled"] = sampledPerformance
                source["rowsOmittedBySelection"] = decodedConsole - selectedEvents.count - selectedPerformance.count
                source["markerWindowSeconds"] = 30
                source["markerWindowPrecision"] = "console-whole-seconds-marker-truncated-to-second-for-ranking"
                source["markerClockAssumption"] = "console-year-zone-unmeasured-assume-device-local-wall-clock-for-selection-only"
                source["usableErrorMarkerCount"] = markerClocks.count
            } else if id != "madeira-session" {
                source["typedDecoder"] = "unmeasured-no-proven-source-specific-grammar"
            }
            sources.append(source)
        }
        let mainCap = max(1, limits.records / 2), consoleCap = max(1, limits.records / 4)
        consume("madeira-session", "madeira-log.txt", limits.mainBytes, mainCap, 131072)
        let steam = "wine/drive_c/Program Files (x86)/Steam/"
        // Read the real game console before Steam logs consume residual
        // records. It is independent from timestamp-named hardlink aliases.
        consume("cs2-console", steam + "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log",
                limits.otherBytes, consoleCap, 65536)
        for (id, path) in [("steam-console", "logs/console_log.txt"), ("steam-gameprocess", "logs/gameprocess_log.txt"),
                           ("steam-connection", "logs/connection_log.txt"), ("steam-service", "logs/service_log.txt"),
                           ("steam-content", "logs/content_log.txt")] {
            consume(id, steam + path, limits.otherBytes, max(1, limits.records / 16), 8192)
        }
        if let alias { consume("cs2-session-alias", alias, limits.otherBytes, max(1, limits.records / 16), 8192) }
        func coverage(_ tag: String) -> String {
            observations.contains { $0["record"] as? String == tag } ? "observed-allowlisted-events" : "no-observed-dedicated-events-unmeasured"
        }
        let consoleEvents = observations.filter { $0["source"] as? String == "cs2-console" }
        func seenConsole(_ name: String) -> Bool {
            consoleEvents.contains { ($0["fields"] as? [String: String])?["event"] == name }
        }
        func seenRecord(_ tag: String, _ key: String, _ value: String) -> Bool {
            observations.contains { $0["record"] as? String == tag && ($0["fields"] as? [String: String])?[key] == value }
        }
        let networkOK = consoleEvents.contains {
            let f = $0["fields"] as? [String: String]
            return f?["event"] == "network-auth-status" && f?["network-auth-status"] == "ok"
        }
        let summary: [String: Any] = [
            "scope": "observations-from-bounded-export-not-security-validation",
            "confirmedObservationBooleanSemantics": "false-means-not-observed-not-the-opposite-state",
            "serviceStateObservation": seenRecord("steam-service", "service-state", "4") ? "running-reported" : "unmeasured",
            "confirmedObservations": [
                "mainMenuStateReported": seenConsole("main-menu-state-reported"),
                "source2InitializationReported": seenConsole("source2-initialized"),
                "networkCertificateAuthOKReported": networkOK,
                "relayNetworkReadyReported": seenConsole("relay-network-ready"),
                "localLoopbackConnectionReported": seenConsole("local-loopback-connected"),
                "enginePIXNsightMessageReported": seenConsole("engine-pix-nsight-reported"),
                "genericConfirmLocalizationWarningReported": seenConsole("generic-confirm-localization-warning"),
                "signatureWarningTextObserved": seenConsole("vac-signature-warning-message"),
                "userErrorMarkerObserved": seenRecord("cs2-user-marker-v1", "kind", "error-reported"),
                "serviceRunningReported": seenRecord("steam-service", "service-state", "4"),
                "serviceDLLInvalidImageReported": seenRecord("steam-service-loader-v1", "status", "c000007b"),
                "guestPEBBeingDebuggedSetObserved": seenRecord("cs2-guest-debug-v1", "being-debugged", "1"),
                "cachedReferenceMismatchObserved": seenRecord("steam-content-audit-v1", "state", "cache-hash-mismatch"),
                "embeddedVPKConsistencyObserved": seenRecord("steam-content-audit-v1", "vpk-crypto", "consistent-embedded-key")
            ],
            "hypotheses": [
                "specific-rejected-file": "unidentified-from-these-observations",
                "service-dll-error-causes-vac-warning": "unproven",
                "pix-nsight-message-causes-vac-warning": "unproven",
                "generic-confirm-warning-is-vac-popup": "unproven-generic-warning-and-user-marker-do-not-identify-dialog-body",
                "secure-launch-environment-compatibility": "not-established-by-network-authentication"
            ],
            "unmeasured": ["independent-Valve-file-trust", "VAC-secure-server-acceptance", "complete-module-inventory", "complete-guest-and-host-debugger-state"],
            "interpretation": "network-authentication-relay-readiness-and-local-loopback-never-establish-VAC-approval",
            "warningAbsence": "not-observed-in-bounded-console-is-not-proof-of-no-popup",
            "clockCorrelation": "console-MM/DD-year-zone-unmeasured; marker-wall-window-assumes-device-local-time; app-DispatchTime-and-Wine-CLOCK_MONOTONIC-are-distinct-domains; proximity-does-not-establish-causality"
        ]
        let manifest: [String: Any] = ["schema": "madeira-steam-cs2-diagnostics-v2", "sourceCommit": build,
            "collection": "explicit-user-action-bounded-source-priority-snapshot", "sources": sources,
            "mainByteBudget": limits.mainBytes, "mainPrefixBudget": min(limits.mainBytes * 3 / 4, 6 << 20),
            "mainSuffixBudget": limits.mainBytes - min(limits.mainBytes * 3 / 4, 6 << 20),
            "recordsCaptured": observations.count, "recordBudget": limits.records,
            "mainRecordBudget": mainCap, "consoleRecordBudget": consoleCap, "markerRecordBudget": markerCap,
            "rowsScanned": scanned, "rowsOmittedWithinScan": omitted,
            "scanLimitReached": scanLimitReached, "maxRowsScanned": 245760,
            "rawLogBodies": "excluded", "accountAndAuthenticationData": "excluded-by-closed-schema",
            "moduleCoverage": "observed-allowlisted-loader-events-only-not-complete-inventory",
            "effectiveArguments": "only-dedicated-flag-observations-no-raw-command-lines",
            "knownArgumentIDs": ["0": "-steam", "1": "-condebug", "2": "-joy", "3": "-insecure", "4": "-allow_third_party_software"],
            "argumentCompleteness": "complete-only-when-parse-complete-1-and-unknown-count-0",
            "flagSemantics": "observed-tokens-not-engine-option-interpretation-zeros-unobserved-when-incomplete",
            "machineInterpretation": "raw-PE-machine-plus-separate-hybrid-observation-8664-does-not-imply-pure-AMD64",
            "moduleCatalogInterpretation": "fixed-layout-or-name-match-only-not-original-publisher-implementation-signature-or-trust",
            "wineBuiltinInterpretation": "loader-observed-Wine-DOS-header-marker-not-a-cryptographic-signature",
            "launchFlagObservations": coverage("cs2-launch-flags-v1"),
            "moduleObservations": coverage("cs2-module-v1"),
            "guestDebugObservations": coverage("cs2-guest-debug-v1"),
            "guestDebugScope": "one-startup-guest-PEB-snapshot-not-host-attachment-later-state-or-complete-debugger-detection",
            "trustObservations": coverage("trust-result-v1"),
            "sessionObservations": coverage("steam-session-v1"),
            "authenticationVerdict": "unmeasured", "vacVerdict": "unmeasured", "trustVerdict": "unmeasured",
            "trustObservationScope": "application-reported-WinVerifyTrust-results-not-independent-validation",
            "structuredProducerRows": "accepted-from-main-runtime-log-or-app-marker-ring-only",
            "numericSessionResultDomain": "unknown-do-not-infer-authentication-status",
            "externalGameLibraries": "not-followed-unmeasured",
            "consoleCoverage": "typed-sanitized-known-event-excerpt-not-complete-console",
            "consoleSelection": "critical-events-and-conditional-marker-wall-window-before-bounded-performance-samples-within-byte-snapshot",
            "steamLogCoverage": "bounded-read-no-proven-source-specific-typed-decoder",
            "monotonicClockCorrelation": "app-dispatch-uptime-and-wine-posix-clock-monotonic-must-not-be-subtracted-without-measured-calibration",
            "serviceDiskPEObservations": servicePEs(root)]
        func json(_ object: Any) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) }
        let explanation = """
        Madeira CS2 VAC diagnostic observations
        cs2-console.json is a sanitized typed excerpt of the real game/csgo/console.log,
        not a raw or complete console copy. Console timestamps preserve the app-reported
        MM/DD wall clock; their year and timezone are unknown. Identifiers, endpoints,
        certificate contents, credentials and arbitrary text are never copied.
        UTC input/error markers are observations from Madeira or the user, not a VAC
        verdict. Source-local quotas prevent giant runtime logs from starving them.
        Console selection favors fixed warning events and a conditional 30-second
        device-local marker window within the byte snapshot. Console year/zone and
        shared-clock agreement are unmeasured. App DispatchTime and Wine's POSIX
        monotonic values have distinct domains; do not subtract them. Repetitive
        performance rows are sampled and counted. Steam log grammars are unmeasured.
        Summary hypotheses are not causes. AuthStatus OK and relay readiness concern
        networking certificates; loopback connections are local. None establish
        VAC-secure acceptance, independent Valve file trust or a working secure game.
        Module catalog roles identify fixed layouts or names, not the original
        publisher or implementation. Wine builtin is a DOS-header marker, not a
        cryptographic signature. Guest PEB debugger fields are a single startup
        snapshot; unreadable fields remain unmeasured and host state is unmeasured.
        Unknown, sensitive, unavailable and out-of-budget content is explicitly omitted.
        Timestamped cs2.exe session logs are aliases/hardlinks of the runtime log,
        not independent game-console evidence. No installed game/account file changes.
        """
        return [Entry(name: "manifest.json", data: try json(manifest)), Entry(name: "observations.json", data: try json(observations)),
                Entry(name: "cs2-console.json", data: try json(consoleEvents)), Entry(name: "summary.json", data: try json(summary)),
                Entry(name: "README.txt", data: Data(explanation.utf8))]
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
                Label("Export CS2 VAC Diagnostics", systemImage: "square.and.arrow.up")
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
