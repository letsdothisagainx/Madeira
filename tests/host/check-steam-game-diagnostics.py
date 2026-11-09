#!/usr/bin/env python3
"""Execute the actual export parser/reader and stored ZIP writer, never log-copy mocks."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--require-swift', action='store_true')
args = p.parse_args()
source = ROOT / 'app/Madeira/SteamGameDiagnostics.swift'
store = (ROOT / 'app/Madeira/LogStore.swift').read_text()
ui = (ROOT / 'app/Madeira/Library.swift').read_text()
project = (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert 'SteamGameDiagnosticsExportButton()' in ui
assert 'SteamGameDiagnostics.swift in Sources' in project
assert 'Export CS2 VAC Diagnostics' in source.read_text()
assert 'CS2VACMarkers.snapshotLines()' in source.read_text()
assert 'DispatchQueue.global(qos: .utility).async' in store
assert 'SteamGameDiagnostics.collect(documents: documents)' in store
assert 'O_EXCL | O_NOFOLLOW' in store and 'if createdDirectory' in store
assert not any(x in source.read_text() for x in ['loginusers.vdf', 'ssfn', 'config.vdf', 'URLSession', 'contentsOfDirectory'])
swift = shutil.which('swiftc')
if not swift:
    assert not args.require_swift, 'Swift compiler required for production export tests'
    print('PASS diagnostic export/UI wiring; production parser, nofollow reader and ZIP behavior require Swift CI')
    raise SystemExit(0)

code = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let output = URL(fileURLWithPath: CommandLine.arguments[2])
let fm = FileManager.default
func put(_ relative: String, _ text: String) {
    let url = root.appendingPathComponent(relative)
    try! fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! Data(text.utf8).write(to: url)
}
let session = "[steam-session-v1] source=cs2-console role=cs2 pid=033c tid=03b8 event=network-tos-control-missing reported-token=unavailable numeric-result-present=0 numeric-result=0 sequence=1 monotonic-ms=573093097 evidence=application-log auth-validation=unclaimed body=excluded"
assert(SteamGameDiagnostics.decode(session) != nil)
assert(SteamGameDiagnostics.decode("[00:01:24.869] [INFO] " + session) != nil)
let service = "[steam-service] result=1053"
assert(SteamGameDiagnostics.decode(service)?.1["result"] == "1053")
let verificationRequest = "[native-steam-verify-v1] app=730 phase=requested mechanism=steam-validate result=unobserved completion=steam-ui"
assert(SteamGameDiagnostics.decode(verificationRequest) != nil)
assert(SteamGameDiagnostics.decode(verificationRequest.replacingOccurrences(of: "result=unobserved", with: "result=success")) == nil)
assert(SteamGameDiagnostics.decode(verificationRequest + " ticket=PRIVATE_AUTH_SENTINEL") == nil)
let content = "[steam-content-audit-v1] app=730 relative=game/bin/win64/cs2.exe state=cache-hash-match bytes=2967704 certificate=table-present-unverified vpk-signature=not-vpk trust=unmeasured"
assert(SteamGameDiagnostics.decode(content) != nil)
let origin = "[startup-timeline-v1] event=origin source=first-observed-create clock=monotonic t-ms=1095 mono-ns=572814511435000 intervals=overlap-allowed cpu-time=unmeasured"
assert(SteamGameDiagnostics.decode(origin)?.1["mono-ns"] == nil)
let retirement = "[startup-timeline-v1] event=owner-quiesced-status-unobserved phase=cs2 attempt=3 creator=0020 pid=033c t-ms=100 duration-ms=20 status=00000000 create-ok=0 intervals=overlap-allowed"
assert(SteamGameDiagnostics.decode(retirement) != nil)
let trust = "033c:err:wintrust:WinVerifyTrust [trust-result-v1] pid=828 action=00aac56b-cd44-11d0-8cc2-00c04fc295ee choice=1 kind=file state=0 result=800b0100 error=0 path=drive name=cs2.exe limit=64-per-process-module"
assert(SteamGameDiagnostics.decode(trust) != nil)
// Exact captured loader rows: prefix is a TID, never a process identity.
let loaderFull = #"00b0:err:module:load_dll [dll-missing] rev=ml336 #3 L"C:\\Program Files (x86)\\Steam\\bin\\steamservice.dll" status=c000007b -- if the webhelper dies right after this, it is the delay-load Chromium kills the process over"#
let loaderBare = #"00b0:err:module:load_dll [dll-missing] rev=ml336 #5 L"steamservice.dll" status=c0000135 -- if the webhelper dies right after this, it is the delay-load Chromium kills the process over"#
let loaderFields = SteamGameDiagnostics.decode(loaderFull)!.1
assert(loaderFields["tid"] == "00b0" && loaderFields["pid"] == "unmeasured")
assert(loaderFields["status"] == "c000007b" && loaderFields["dll"] == "steamservice.dll" && loaderFields["location"] == "steam-bin")
assert(loaderFields["evidence"] == "wine-loader-result")
assert(SteamGameDiagnostics.decode(loaderBare)?.1["status"] == "c0000135")
assert(SteamGameDiagnostics.decode(loaderBare)?.1["location"] == "bare")
let vpk = "[steam-content-audit-v1] app=730 relative=game/csgo/pak01_dir.vpk state=cache-hash-match bytes=7713879 certificate=not-pe vpk-signature=section-present-unverified vpk-format=descriptor20 vpk-version=2 vpk-type=1 vpk-reserved=0 vpk-offset=7713123 vpk-declared=20 vpk-key-bytes=294 vpk-signature-bytes=256 vpk-trailing-bytes=0 vpk-tree-bytes=300 vpk-table-offset=328 vpk-table-bytes=28 vpk-other-offset=356 vpk-other-bytes=48 vpk-reason=bounded-known-layout vpk-tree-md5=match vpk-table-md5=match vpk-whole-md5=match vpk-crypto=consistent-embedded-key vpk-extra-read-bytes=1000 key-provenance=embedded-untrusted archive-payloads=not-read vac=unclaimed current-sha1=" + String(repeating: "b", count: 40) + " reference-sha1=" + String(repeating: "c", count: 40) + " hash-source=current-file-read trust=unmeasured"
assert(SteamGameDiagnostics.decode(vpk) != nil)
let flags = "[cs2-launch-flags-v1] pid=033c tid=0340 steam=1 condebug=1 joy=1 insecure=0 allow-third-party=0 argument-count=3 unknown-count=0 known-sequence=0,1,2 parse-complete=1 coverage=accepted-process-params"
assert(SteamGameDiagnostics.decode(flags) != nil)
let module = "[cs2-module-v1] pid=033c tid=0340 path-class=game relative=game/bin/win64/cs2.exe machine=8664 hybrid=unmeasured unknown-count=0 dropped-observed=0 sequence=1 limit=256 coverage=bounded-observed-load-events path-source=accepted-main-image"
assert(SteamGameDiagnostics.decode(module) != nil)
assert(SteamGameDiagnostics.decode(module)?.1["wine-builtin"] == "unmeasured")
assert(SteamGameDiagnostics.decode(module)?.1["header-source"] == "legacy-machine-hybrid-only")
assert(SteamGameDiagnostics.decode(module)?.1["catalog-role"] == "cs2-game-layout")
let moduleHeaders = module + " wine-builtin=0 header-source=accepted-image-info"
assert(SteamGameDiagnostics.decode(moduleHeaders)?.1["wine-builtin"] == "0")
assert(SteamGameDiagnostics.decode(moduleHeaders)?.1["header-source"] == "accepted-image-info")
for invalid in [module + " wine-builtin=1", module + " header-source=accepted-image-info",
                moduleHeaders.replacingOccurrences(of: "wine-builtin=0", with: "wine-builtin=2"),
                moduleHeaders.replacingOccurrences(of: "header-source=accepted-image-info", with: "header-source=trusted"),
                moduleHeaders + " catalog-role=cs2-game-layout"] {
    assert(SteamGameDiagnostics.decode(invalid) == nil)
}
let debug = "[cs2-guest-debug-v1] pid=033c tid=0340 being-debugged=1 nt-global-flag=00000070 limit=1-per-process coverage=accepted-post-server-init-snapshot evidence=fault-safe-peb-read-only scope=guest-peb-fields-only"
assert(SteamGameDiagnostics.decode(debug)?.1["being-debugged"] == "1")
assert(SteamGameDiagnostics.decode(debug.replacingOccurrences(of: "being-debugged=1 nt-global-flag=00000070", with: "being-debugged=unmeasured nt-global-flag=unmeasured")) != nil)
for invalid in [debug + " token=SECRET", debug.replacingOccurrences(of: "being-debugged=1", with: "being-debugged=false"),
                debug.replacingOccurrences(of: "nt-global-flag=00000070", with: "nt-global-flag=0"),
                debug.replacingOccurrences(of: "scope=guest-peb-fields-only", with: "scope=all-debugger-state"),
                debug.replacingOccurrences(of: "evidence=fault-safe-peb-read-only", with: "evidence=IsDebuggerPresent-called")] {
    assert(SteamGameDiagnostics.decode(invalid) == nil)
}
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "unknown-count=0", with: "unknown-count=256").replacingOccurrences(of: "sequence=1", with: "sequence=256")) != nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "sequence=1", with: "sequence=257")) == nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "dropped-observed=0", with: "dropped-observed=129")) == nil)
let systemModule = module.replacingOccurrences(of: "path-class=game relative=game/bin/win64/cs2.exe", with: "path-class=system relative=system32/wintrust.dll").replacingOccurrences(of: "hybrid=unmeasured", with: "hybrid=1")
assert(SteamGameDiagnostics.decode(systemModule) != nil)
let searchModule = systemModule.replacingOccurrences(of: "path-class=system relative=system32", with: "path-class=search-root relative=arm64ec-windows")
assert(SteamGameDiagnostics.decode(searchModule) != nil)
for name in ["d3d9.dll", "nvapi64.dll"] {
    assert(SteamGameDiagnostics.decode(systemModule.replacingOccurrences(of: "wintrust.dll", with: name)) != nil)
    assert(SteamGameDiagnostics.decode(searchModule.replacingOccurrences(of: "wintrust.dll", with: name)) != nil)
}
for (name, role) in [("xtajit64.dll", "fex-runtime-name"), ("libarm64ecfex.dll", "fex-runtime-name"),
                     ("d3d11.dll", "dxmt-runtime-name"), ("winemetal.dll", "dxmt-runtime-name"),
                     ("cryptbase.dll", "windows-runtime-name"), ("mmdevapi.dll", "windows-runtime-name")] {
    assert(SteamGameDiagnostics.decode(systemModule.replacingOccurrences(of: "wintrust.dll", with: name))?.1["catalog-role"] == role)
    assert(SteamGameDiagnostics.decode(searchModule.replacingOccurrences(of: "wintrust.dll", with: name))?.1["catalog-role"] == role)
}
for path in ["game/bin/win64/sdl3.dll", "game/bin/win64/inputsystem.dll", "game/bin/win64/imemanager.dll",
             "game/bin/win64/gameinput.dll", "game/bin/win64/localize.dll", "game/bin/win64/amd_ags_x64.dll",
             "game/bin/win64/d3dcompiler_47.dll", "game/bin/win64/resourcesystem.dll"] {
    assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: path))?.1["catalog-role"] == "cs2-game-layout")
    assert(SteamGameDiagnostics.decode(content.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: path)) == nil,
           "module catalog must not broaden content audit paths")
}
for name in ["steamclient64.dll", "tier0_s64.dll", "vstdlib_s64.dll", "crashhandler64.dll", "gameoverlayrenderer64.dll"] {
    assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "path-class=game relative=game/bin/win64/cs2.exe", with: "path-class=steam-client relative=" + name))?.1["catalog-role"] == "steam-client-layout")
}
assert(SteamGameDiagnostics.decode(systemModule.replacingOccurrences(of: "system32/wintrust.dll", with: "system32/unlisted.dll")) == nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: "game/bin/win64/unlisted.dll")) == nil)

assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "path-class=game relative=game/bin/win64/cs2.exe", with: "path-class=private relative=redacted")) != nil)
assert(SteamGameDiagnostics.decode(flags.replacingOccurrences(of: "known-sequence=0,1,2", with: "known-sequence=0,2")) == nil)
assert(SteamGameDiagnostics.decode(flags.replacingOccurrences(of: "joy=1", with: "joy=0")) == nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "sequence=1", with: "sequence=00")) == nil)
// Reproduce the useful public shapes in the actual November9 console.
// IDs/endpoints identify a grammar only and must not appear in the export.
let consoleRows: [(String, String)] = [
    ("11/09 03:30:21 PIX/NSIGHT WAS detected.", "engine-pix-nsight-reported"),
    ("11/09 03:32:36 ChangeGameUIState: CSGO_GAME_UI_STATE_INVALID -> CSGO_GAME_UI_STATE_MAINMENU", "main-menu-state-reported"),
    ("11/09 03:32:36 Source2Init OK", "source2-initialized"),
    ("11/09 03:30:27 [SteamNetSockets] AuthStatus (steamid:76561198000000000):  Attempting  (Requesting cert)", "network-auth-status"),
    ("11/09 03:32:41 [SteamNetSockets] AuthStatus (steamid:76561198000000000):  OK  (OK)", "network-auth-status"),
    ("11/09 03:32:40 [SteamNetSockets] Certificate expires in 37h24m at 1794347803 (current time 1794213160), will renew in 35h24m", "network-certificate-renewal-scheduled"),
    ("11/09 03:32:40 [SteamNetSockets] SDR network config fetch attempt #1 failed.  HTTP 504.  .  Trying again.", "relay-config-retry"),
    ("11/09 03:32:41 [SteamNetSockets] Got SDR network config.  Loaded revision 1793736599 OK", "relay-config-loaded"),
    ("11/09 03:32:47 [SteamNetSockets] SDR RelayNetworkStatus:  avail=OK  config=OK  anyrelay=OK   (OK.  Relays: 25 valid, 0 great, 4 good+, 10 ok+, 19 ignored)", "relay-network-ready"),
    ("11/09 03:33:38 [Client] CL:  CCreateGameClientJob creating client connection to 'loopback'", "connection-attempt"),
    ("11/09 03:33:39 [Networking] Connected loopback client=a1b2c3d4@loopback:1 <-> server=e5f60718@loopback:0", "local-loopback-connected"),
    ("11/09 03:33:39 [Client] CL:  Connected to 'loopback:1'", "local-loopback-connected"),
    ("11/09 03:35:16 [Localization System] CLocalize::CompileString failed to localize: '#GenericConfirmText_Label'", "generic-confirm-localization-warning"),
    ("11/09 03:34:28 [SteamNetSockets] Waited 51.0ms for SteamNetworkingSockets lock [ServiceThread]", "network-lock-wait"),
    ("11/09 03:34:28 [SteamNetSockets] SteamNetworkingSockets lock held for 196.0ms.  (Performance warning.)  ServiceThread,RecvUDPPacket", "network-lock-held"),
    (#"11/09 03:34:28 [SteamNetSockets] src\steamnetworkingsockets\clientlib\steamnetworkingsockets_lowlevel.cpp(2874): SteamnetworkingSockets service thread waited 140ms for lock!  This directly adds to network latency!  It could be a bug, but it's usually caused by general performance problem such as thread starvation or a debug output handler taking too long."#, "network-service-thread-delayed")
]
for (row, expected) in consoleRows {
    let f = SteamGameDiagnostics.decodeConsole(row)!
    assert(f["event"] == expected && f["console-time"] != "unmeasured")
    assert(f["clock"] == "console-wall-year-zone-unmeasured")
    assert(!String(describing: f).contains("76561198000000000"))
}
assert(SteamGameDiagnostics.decodeConsole("\u{feff}" + consoleRows[0].0)?["event"] == "engine-pix-nsight-reported")
assert(SteamGameDiagnostics.decodeConsole("99/09 03:32:36 Source2Init OK") == nil)
assert(SteamGameDiagnostics.decodeConsole("11/09 25:32:36 Source2Init OK") == nil)
assert(SteamGameDiagnostics.decodeConsole(consoleRows[14].0.replacingOccurrences(of: "196.0ms", with: "99999.0ms")) == nil)
assert(SteamGameDiagnostics.decodeConsole(consoleRows[14].0.replacingOccurrences(of: "RecvUDPPacket", with: "SECRET_TRACE")) == nil)
assert(SteamGameDiagnostics.decodeConsole(consoleRows[4].0.replacingOccurrences(of: "(OK)", with: "(Requesting cert)")) == nil)
let marker = "[cs2-user-marker-v1] kind=error-reported source=user input=none app=730 context=cs2-observed pid=033c session=1 sequence=5 utc=2026-11-09T08:35:16.123Z utc-offset-min=-300 monotonic-ms=572814511 evidence=user-report"
assert(SteamGameDiagnostics.decode(marker)?.1["utc-offset-min"] == "-300")
for invalid in [marker + " token=SECRET", marker.replacingOccurrences(of: "source=user", with: "source=runtime"),
    marker.replacingOccurrences(of: "utc-offset-min=-300", with: "utc-offset-min=-841"),
    marker.replacingOccurrences(of: "sequence=5", with: "sequence=0"),
    marker.replacingOccurrences(of: "input=none", with: "input=keyboard")] {
    assert(SteamGameDiagnostics.decode(invalid) == nil)
}
// Exercise the actual app-owned ring, not injected rows or a fake collector.
CS2VACMarkers.shared.begin(appID: 730)
CS2VACMarkers.shared.observeProcess(pid: "033c")
assert(CS2VACMarkers.shared.beginTest())
CS2VACMarkers.shared.noteInput(.pointer)
assert(CS2VACMarkers.shared.markError())
assert(CS2VACMarkers.snapshotLines().count == 5)
assert(CS2VACMarkers.snapshotLines().allSatisfy { SteamGameDiagnostics.decode($0) != nil })
let secrets = ["OPAQUE_SENTINEL_TICKET_6a9c", "PRIVATE_SENTINEL_KEY_7b2d", "76561198000000000", "203.0.113.42", "private@example.org", "/private/var/mobile/SECRET_PATH"]
let bad = [
    loaderFull + " private=" + secrets[0], loaderBare + " " + secrets[0], "prefix " + loaderFull,
    loaderFull.replacingOccurrences(of: "Program Files (x86)", with: secrets[5]),
    loaderBare.replacingOccurrences(of: "steamservice.dll", with: secrets[0] + ".dll"),
    loaderFull.replacingOccurrences(of: "status=c000007b", with: "status=c0000017"),
    loaderFull.replacingOccurrences(of: "#3 ", with: "#61 "),
    loaderFull.replacingOccurrences(of: "rev=ml336", with: "rev=ml337"),
    loaderFull.replacingOccurrences(of: "delay-load Chromium", with: "delay-load " + secrets[0]),
    flags + " ticket=" + secrets[0], module + " token=" + secrets[0],
    module.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: secrets[5]),
    systemModule.replacingOccurrences(of: "system32/wintrust.dll", with: "system32/" + secrets[0]),
    session + " token=" + secrets[0], session + " opaque=" + secrets[0],
    session.replacingOccurrences(of: "reported-token=unavailable", with: "reported-token=" + secrets[0]),
    session.replacingOccurrences(of: "numeric-result=0", with: "numeric-result=" + secrets[2]),
    session.replacingOccurrences(of: "numeric-result=0", with: "numeric-result=0SECRET"),
    session + " numeric-result=0", "untrusted-prefix " + session, "[VAC] " + secrets[0],
    "[SteamAPI] " + secrets[0], "[steam-service] result=0 auth=" + secrets[0],
    "[steam-service] result=0 " + secrets[0], "[steam-service] result=-1",
    content.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: "../" + secrets[0]),
    content.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: secrets[5]),
    content.replacingOccurrences(of: "game/bin/win64/cs2.exe", with: "%2e%2e/console.log"),
    content.replacingOccurrences(of: "state=cache-hash-match", with: "state=" + secrets[0]),
    session + " url=https://example.org/?ticket=" + secrets[0],
    trust + " token=" + secrets[0], vpk + " private=" + secrets[1],
    vpk.replacingOccurrences(of: "vpk-crypto=consistent-embedded-key", with: "vpk-crypto=" + secrets[0]),
    session + " public_key=" + secrets[1], session + " private=" + secrets[1],
    session + "\0", session + "\r" + secrets[0], session + "\u{202e}", String(repeating: "x", count: 4100) + session
]
for line in bad { assert(SteamGameDiagnostics.decode(line) == nil, "unknown or sensitive row accepted") }
for (row, _) in consoleRows {
    assert(SteamGameDiagnostics.decodeConsole(row + " token=" + secrets[0]) == nil)
    assert(SteamGameDiagnostics.decodeConsole("prefix " + row) == nil)
}
assert(SteamGameDiagnostics.decodeConsole("[SteamNetSockets] Certificate blob=" + secrets[1]) == nil)
assert(SteamGameDiagnostics.decodeConsole("11/09 03:35:16 [SteamNetSockets] " + secrets.joined(separator: " ")) == nil)

// An unlisted subject must not erase the actual verifier error. Only its
// arbitrary filename is canonicalized; unknown fields still reject the row.
let unknownTrust = trust.replacingOccurrences(of: "name=cs2.exe", with: "name=" + secrets[0])
let unknownTrustFields = SteamGameDiagnostics.decode(unknownTrust)!.1
assert(unknownTrustFields["name"] == "redacted-unlisted")
assert(unknownTrustFields["result"] == "800b0100" && unknownTrustFields["choice"] == "1")
assert(!String(describing: unknownTrustFields).contains(secrets[0]))
assert(SteamGameDiagnostics.decode(unknownTrust + " private=" + secrets[1]) == nil)
put("madeira-log.txt", "[00:00:01.001] [INFO] [build] v0.1.3 (4) source=" + String(repeating: "a", count: 40) + "\n" + content + "\n" + service + "\n" + session + "\n" + unknownTrust + "\n" + loaderFull + "\n" + loaderBare + "\n" + bad.joined(separator: "\n") + "\n[session-log] Steam game cs2.exe: logs/cs2.exe-2026-11-09_00-03-55.txt\n")
try! fm.createDirectory(at: root.appendingPathComponent("logs"), withIntermediateDirectories: true)
try! fm.linkItem(at: root.appendingPathComponent("madeira-log.txt"), to: root.appendingPathComponent("logs/cs2.exe-2026-11-09_00-03-55.txt"))
let steam = "wine/drive_c/Program Files (x86)/Steam/"
let signatureWarning = "Some of your game files have been detected to have no signatures or invalid signatures. You will not be allowed to join VAC secure servers."
let signatureWarningHelp = signatureWarning + " Please verify your launch options, check correctness of your game installation, restart the game and try again."
put(steam + "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log",
    "VAC was unable to verify your game session.\n" + signatureWarning + "\n" + signatureWarningHelp + "\n" + consoleRows.map { $0.0 }.joined(separator: "\n") + "\n" +
    signatureWarning + " " + secrets[0] + "\n" + signatureWarningHelp + " private=" + secrets[1] + "\nprefix " + signatureWarning + "\nVAC " + secrets[0] + "\nSteamAPI " + secrets[1] + "\n" + secrets.joined(separator: " ") + "\n")
put(steam + "logs/console_log.txt", session + "\n" + loaderFull + "\n" + loaderBare + "\n" + marker + "\n" + String(repeating: "X", count: 5000) + service + "\n")
let outside = root.deletingLastPathComponent().appendingPathComponent("outside-console.txt")
try! Data(("[steam-service] result=999\n" + secrets[0]).utf8).write(to: outside)
try! fm.createSymbolicLink(at: root.appendingPathComponent(steam + "logs/connection_log.txt"), withDestinationURL: outside)
var pe = Data(count: 128)
pe[0] = 0x4d; pe[1] = 0x5a; pe[60] = 64
pe[64] = 0x50; pe[65] = 0x45; pe[68] = 0x64; pe[69] = 0x86
let serviceDLL = root.appendingPathComponent(steam + "bin/steamservice.dll")
let officialDLL = root.appendingPathComponent(steam + "bin/SteamService.dll")
try! fm.createDirectory(at: serviceDLL.deletingLastPathComponent(), withIntermediateDirectories: true)
var pe32 = pe; pe32[68] = 0x4c; pe32[69] = 0x01
try! pe32.write(to: officialDLL)
func serviceRecords(_ entries: [SteamGameDiagnostics.Entry]) -> [[String: String]] {
    (try! JSONSerialization.jsonObject(with: entries[0].data) as! [String: Any])["serviceDiskPEObservations"] as! [[String: String]]
}
let officialOnly = serviceRecords(try! SteamGameDiagnostics.collect(documents: root))
assert(officialOnly.contains { $0["candidate"] == "steam-bin-service-dll-official-case" && $0["machine"] == "014c" })
try! fm.removeItem(at: officialDLL)
try! pe.write(to: serviceDLL)
let lowercaseOnly = serviceRecords(try! SteamGameDiagnostics.collect(documents: root))
assert(lowercaseOnly.contains { $0["machine"] == "8664" && $0["state"] == "header-read-only-not-authenticated" })
// On a case-sensitive volume these are independent conflicting candidates;
// on Apple's case-folded test volume the second spelling is the same inode.
// Report both candidate observations and prove sameness only by dev/inode.
try! pe32.write(to: officialDLL)
var officialInfo = stat(), lowerInfo = stat()
assert(lstat(officialDLL.path, &officialInfo) == 0 && lstat(serviceDLL.path, &lowerInfo) == 0)
let distinctSpellings = officialInfo.st_dev != lowerInfo.st_dev || officialInfo.st_ino != lowerInfo.st_ino
let invalidHandle = try! FileHandle(forWritingTo: root.appendingPathComponent("madeira-log.txt"))
try! invalidHandle.seekToEnd(); try! invalidHandle.write(contentsOf: Data([0xff, 0xfe, 0x0a])); try! invalidHandle.close()
let entries = try! SteamGameDiagnostics.collect(documents: root)
assert(entries.map(\.name) == ["manifest.json", "observations.json", "cs2-console.json", "summary.json", "README.txt"])
let text = entries.map { String(decoding: $0.data, as: UTF8.self) }.joined()
for secret in secrets { assert(!text.contains(secret), "secret leaked") }
assert(!text.contains("successful-login") && !text.contains("auth-validation=unclaimed")) // re-encoded values, no raw source line
let manifest = try! JSONSerialization.jsonObject(with: entries[0].data) as! [String: Any]
let sources = manifest["sources"] as! [[String: Any]]
let disk = manifest["serviceDiskPEObservations"] as! [[String: String]]
assert(disk.contains { $0["candidate"] == "steam-bin-service-dll-official-case" && $0["machine"] == "014c" && $0["evidence"] == "disk-header-snapshot-not-loaded-image" })
if distinctSpellings {
    assert(disk.contains { $0["candidate"] == "steam-bin-service-dll" && $0["machine"] == "8664" && $0["state"] == "header-read-only-not-authenticated" })
} else {
    assert(disk.contains { $0["candidate"] == "steam-bin-service-dll" && $0["state"] == "same-file-as-earlier-candidate" && $0["sameAsCandidate"] == "steam-bin-service-dll-official-case" })
}
assert(manifest["moduleObservations"] as? String == "no-observed-dedicated-events-unmeasured")
assert(manifest["guestDebugObservations"] as? String == "no-observed-dedicated-events-unmeasured")
assert(sources.contains { $0["source"] as? String == "cs2-session-alias" && $0["state"] as? String == "same-file-as-earlier-source" })
assert(sources.contains { $0["source"] as? String == "steam-connection" && $0["state"] as? String == "unavailable-or-not-owned-regular-file" })
let events = try! JSONSerialization.jsonObject(with: entries[1].data) as! [[String: Any]]
assert(events.count == 14 + consoleRows.count)
let consoleExcerpt = try! JSONSerialization.jsonObject(with: entries[2].data) as! [[String: Any]]
assert(consoleExcerpt.count == 3 + consoleRows.count)
let summary = try! JSONSerialization.jsonObject(with: entries[3].data) as! [String: Any]
let confirmed = summary["confirmedObservations"] as! [String: Bool]
assert(confirmed["networkCertificateAuthOKReported"] == true && confirmed["relayNetworkReadyReported"] == true)
assert(confirmed["localLoopbackConnectionReported"] == true && confirmed["mainMenuStateReported"] == true)
assert(confirmed["userErrorMarkerObserved"] == true && confirmed["signatureWarningTextObserved"] == true)
assert((summary["unmeasured"] as! [String]).contains("VAC-secure-server-acceptance"))
let markerEvents = events.filter { $0["record"] as? String == "cs2-user-marker-v1" }
assert(markerEvents.count == 5 && markerEvents.allSatisfy { $0["source"] as? String == "madeira-marker-ring" })
assert(!text.contains("a1b2c3d4") && !text.contains("e5f60718") && !text.contains("1794347803"))
let loaderEvents = events.filter { $0["record"] as? String == "steam-service-loader-v1" }
assert(loaderEvents.count == 2 && loaderEvents.allSatisfy { $0["source"] as? String == "madeira-session" })
assert(Set(loaderEvents.compactMap { ($0["fields"] as? [String: String])?["status"] }) == Set(["c000007b", "c0000135"]))
assert(loaderEvents.allSatisfy { ($0["fields"] as? [String: String])?["pid"] == "unmeasured" && ($0["fields"] as? [String: String])?["tid"] == "00b0" })
assert(!text.contains("delay-load Chromium kills"), "speculative loader comment was exported")
assert(events.filter { ($0["fields"] as? [String: String])?["event"] == "vac-signature-warning-message" }.count == 2)
assert(!text.contains(signatureWarning), "raw warning body was exported instead of a fixed event")
assert(events.contains { ($0["fields"] as? [String: String])?["name"] == "redacted-unlisted" && ($0["fields"] as? [String: String])?["result"] == "800b0100" })
assert(!events.contains { $0["source"] as? String == "steam-console" }, "raw console impersonated a structured native producer")
assert(events.contains { ($0["fields"] as? [String: String])?["event"] == "vac-session-unverified-message" })
assert(!events.contains { ($0["fields"] as? [String: String])?["result"] == "999" })
var small = SteamGameDiagnostics.Limits(); small.records = 2
let limited = try! SteamGameDiagnostics.collect(documents: root, limits: small)
assert((try! JSONSerialization.jsonObject(with: limited[1].data) as! [[String: Any]]).count == 2)
// Intermediate directory links and final links are both rejected, without
// consulting content at their targets. A poisoned Source2 line cannot become
// a valid prefix by exceeding the line-size limit.
let wine = root.appendingPathComponent("wine"), saved = root.appendingPathComponent("wine-owned")
try! fm.moveItem(at: wine, to: saved)
try! fm.createSymbolicLink(at: wine, withDestinationURL: saved)
let symlinked = try! SteamGameDiagnostics.collect(documents: root)
let symlinkSources = (try! JSONSerialization.jsonObject(with: symlinked[0].data) as! [String: Any])["sources"] as! [[String: Any]]
assert(symlinkSources.filter { ($0["source"] as? String)?.hasPrefix("steam-") == true }.allSatisfy { $0["state"] as? String == "unavailable-or-not-owned-regular-file" })
try! fm.removeItem(at: wine); try! fm.moveItem(at: saved, to: wine)
var bounded = SteamGameDiagnostics.Limits(); bounded.mainBytes = 2048
put("madeira-log.txt", service + "\n" + String(repeating: "secret-row\n", count: 2000) + session + "\n")
let boundedEntries = try! SteamGameDiagnostics.collect(documents: root, limits: bounded)
let boundedManifest = try! JSONSerialization.jsonObject(with: boundedEntries[0].data) as! [String: Any]
assert((boundedManifest["sources"] as! [[String: Any]]).first { $0["source"] as? String == "madeira-session" }?["truncated"] as? Bool == true)
// Preserve the actual early CS2 mapping/flags near5MiB as well as late
// verifier errors after the runtime log grows beyond the8MiB input budget.
let fillerLine = String(repeating: "x", count: 1023) + "\n"
let dedicatedRows = [flags, module, moduleHeaders, debug].joined(separator: "\n") + "\n"
put("madeira-log.txt", String(repeating: fillerLine, count: 5 * 1024) + dedicatedRows + String(repeating: fillerLine, count: 4 * 1024) + unknownTrust + "\n")
let longLog = try! SteamGameDiagnostics.collect(documents: root)
let longEvents = try! JSONSerialization.jsonObject(with: longLog[1].data) as! [[String: Any]]
assert(longEvents.contains { $0["record"] as? String == "cs2-launch-flags-v1" })
assert(longEvents.contains { $0["record"] as? String == "cs2-module-v1" })
assert(longEvents.contains { $0["record"] as? String == "cs2-guest-debug-v1" && ($0["fields"] as? [String: String])?["being-debugged"] == "1" })
let longManifest = try! JSONSerialization.jsonObject(with: longLog[0].data) as! [String: Any]
assert(longManifest["guestDebugObservations"] as? String == "observed-allowlisted-events")
assert((try! JSONSerialization.jsonObject(with: longLog[3].data) as! [String: Any])["confirmedObservations"] as? [String: Bool] != nil)
assert(longEvents.contains { ($0["fields"] as? [String: String])?["name"] == "redacted-unlisted" })
// An input-byte cap must not amplify8MiB of newlines into millions of
// Data subsequences before applying the row cap.
put("madeira-log.txt", String(repeating: "\n", count: 8 << 20))
let flood = try! SteamGameDiagnostics.collect(documents: root)
let floodManifest = try! JSONSerialization.jsonObject(with: flood[0].data) as! [String: Any]
assert(floodManifest["scanLimitReached"] as? Bool == true)
assert((floodManifest["sources"] as! [[String: Any]]).first { $0["source"] as? String == "madeira-session" }?["rowsScanned"] as? Int == 131072)
assert((floodManifest["rowsScanned"] as! Int) <= (floodManifest["maxRowsScanned"] as! Int))
let floodConsole = try! JSONSerialization.jsonObject(with: flood[2].data) as! [[String: Any]]
assert(floodConsole.contains { ($0["fields"] as? [String: String])?["event"] == "relay-network-ready" })
put("madeira-log.txt", String(repeating: service + "\n", count: 4000))
let noisy = try! SteamGameDiagnostics.collect(documents: root)
let noisyEvents = try! JSONSerialization.jsonObject(with: noisy[1].data) as! [[String: Any]]
assert(noisyEvents.count <= 2048)
assert(noisyEvents.contains { $0["source"] as? String == "madeira-marker-ring" })
assert(noisyEvents.contains { $0["source"] as? String == "cs2-console" && ($0["fields"] as? [String: String])?["event"] == "relay-network-ready" })
// Main-runtime producer strings embedded in the real console remain untrusted.
assert(!noisyEvents.contains { $0["source"] as? String == "steam-console" && $0["record"] as? String == "steam-service-loader-v1" })

// Use the actual existing ZIP writer, including its CRC32 and central directory.
let writer = try! SaveZipWriter(url: output)
for entry in entries { try! writer.add(name: entry.name, data: entry.data) }
try! writer.finish()
print("PASS production export: closed schemas, secret/opaque-token rejection, strict nofollow reader, hardlink provenance, bounded snapshots/records, exact console messages, real ZIP writer")
'''
with tempfile.TemporaryDirectory(prefix='madeira-export-') as folder:
    tmp = Path(folder).resolve()
    docs = tmp / 'Documents'; docs.mkdir()
    writer_source = (ROOT / 'app/Madeira/SavesAndShortcuts.swift').read_text()
    writer = writer_source[writer_source.index('final class SaveZipWriter {'):writer_source.index('// MARK: - Zip reading')]
    (tmp / 'Writer.swift').write_text('import Foundation\nimport zlib\n' + writer)
    (tmp / 'main.swift').write_text(code)
    # Apple already exports the SDK's zlib Clang module; redefining it poisons
    # CoreFoundation imports. Linux Swift may need a module for system zlib.
    include = []
    if sys.platform != 'darwin':
        module = tmp / 'zlib'; module.mkdir()
        (module / 'shim.h').write_text('#include <zlib.h>\n')
        (module / 'module.modulemap').write_text('module zlib [system] { header "shim.h" export * }\n')
        include = ['-I', str(module)]
    exe = tmp / 'export-test'
    subprocess.run([swift, '-swift-version', '5', '-sanitize=address', *include, str(ROOT / 'app/Madeira/CS2VACMarkers.swift'), str(source), str(tmp / 'Writer.swift'), str(tmp / 'main.swift'), '-lz', '-o', str(exe)], check=True)
    archive = tmp / 'diagnostics.zip'
    subprocess.run([str(exe), str(docs), str(archive)], check=True)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert z.namelist() == ['manifest.json', 'observations.json', 'cs2-console.json', 'summary.json', 'README.txt']
        manifest = json.loads(z.read('manifest.json'))
        assert manifest['vacVerdict'] == 'unmeasured'
        assert manifest['authenticationVerdict'] == 'unmeasured'
        assert manifest['trustVerdict'] == 'unmeasured'
        assert manifest['structuredProducerRows'] == 'accepted-from-main-runtime-log-or-app-marker-ring-only'
        assert manifest['sourceCommit'] == 'a' * 40
        body = b'\n'.join(z.read(n) for n in z.namelist())
        assert b'OPAQUE_SENTINEL' not in body and b'PRIVATE_SENTINEL' not in body
        assert b'76561198000000000' not in body and b'/private/var' not in body
print('PASS actual stored ZIP: safe five-entry inventory, CRC/readback, typed metadata and no raw source bodies or secret sentinels')
