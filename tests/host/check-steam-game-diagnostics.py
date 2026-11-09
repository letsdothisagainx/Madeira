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
let content = "[steam-content-audit-v1] app=730 relative=game/bin/win64/cs2.exe state=cache-hash-match bytes=2967704 certificate=table-present-unverified vpk-signature=not-vpk trust=unmeasured"
assert(SteamGameDiagnostics.decode(content) != nil)
let origin = "[startup-timeline-v1] event=origin source=first-observed-create clock=monotonic t-ms=1095 mono-ns=572814511435000 intervals=overlap-allowed cpu-time=unmeasured"
assert(SteamGameDiagnostics.decode(origin)?.1["mono-ns"] == nil)
let retirement = "[startup-timeline-v1] event=owner-quiesced-status-unobserved phase=cs2 attempt=3 creator=0020 pid=033c t-ms=100 duration-ms=20 status=00000000 create-ok=0 intervals=overlap-allowed"
assert(SteamGameDiagnostics.decode(retirement) != nil)
let trust = "033c:err:wintrust:WinVerifyTrust [trust-result-v1] pid=828 action=00aac56b-cd44-11d0-8cc2-00c04fc295ee choice=1 kind=file state=0 result=800b0100 error=0 path=drive name=cs2.exe limit=64-per-process-module"
assert(SteamGameDiagnostics.decode(trust) != nil)
let vpk = "[steam-content-audit-v1] app=730 relative=game/csgo/pak01_dir.vpk state=cache-hash-match bytes=7713879 certificate=not-pe vpk-signature=section-present-unverified vpk-format=descriptor20 vpk-version=2 vpk-type=1 vpk-reserved=0 vpk-offset=7713123 vpk-declared=20 vpk-key-bytes=294 vpk-signature-bytes=256 vpk-trailing-bytes=0 vpk-tree-bytes=300 vpk-table-offset=328 vpk-table-bytes=28 vpk-other-offset=356 vpk-other-bytes=48 vpk-reason=bounded-known-layout vpk-tree-md5=match vpk-table-md5=match vpk-whole-md5=match vpk-crypto=consistent-embedded-key vpk-extra-read-bytes=1000 key-provenance=embedded-untrusted archive-payloads=not-read vac=unclaimed current-sha1=" + String(repeating: "b", count: 40) + " reference-sha1=" + String(repeating: "c", count: 40) + " hash-source=current-file-read trust=unmeasured"
assert(SteamGameDiagnostics.decode(vpk) != nil)
let flags = "[cs2-launch-flags-v1] pid=033c tid=0340 steam=1 condebug=1 joy=1 insecure=0 allow-third-party=0 argument-count=3 unknown-count=0 known-sequence=0,1,2 parse-complete=1 coverage=accepted-process-params"
assert(SteamGameDiagnostics.decode(flags) != nil)
let module = "[cs2-module-v1] pid=033c tid=0340 path-class=game relative=game/bin/win64/cs2.exe machine=8664 hybrid=unmeasured unknown-count=0 dropped-observed=0 sequence=1 limit=128 coverage=bounded-observed-load-events path-source=accepted-main-image"
assert(SteamGameDiagnostics.decode(module) != nil)
let systemModule = module.replacingOccurrences(of: "path-class=game relative=game/bin/win64/cs2.exe", with: "path-class=system relative=system32/wintrust.dll").replacingOccurrences(of: "hybrid=unmeasured", with: "hybrid=1")
assert(SteamGameDiagnostics.decode(systemModule) != nil)
let searchModule = systemModule.replacingOccurrences(of: "path-class=system relative=system32", with: "path-class=search-root relative=arm64ec-windows")
assert(SteamGameDiagnostics.decode(searchModule) != nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "path-class=game relative=game/bin/win64/cs2.exe", with: "path-class=private relative=redacted")) != nil)
assert(SteamGameDiagnostics.decode(flags.replacingOccurrences(of: "known-sequence=0,1,2", with: "known-sequence=0,2")) == nil)
assert(SteamGameDiagnostics.decode(flags.replacingOccurrences(of: "joy=1", with: "joy=0")) == nil)
assert(SteamGameDiagnostics.decode(module.replacingOccurrences(of: "sequence=1", with: "sequence=00")) == nil)
let secrets = ["OPAQUE_SENTINEL_TICKET_6a9c", "PRIVATE_SENTINEL_KEY_7b2d", "76561198000000000", "203.0.113.42", "private@example.org", "/private/var/mobile/SECRET_PATH"]
let bad = [
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
// An unlisted subject must not erase the actual verifier error. Only its
// arbitrary filename is canonicalized; unknown fields still reject the row.
let unknownTrust = trust.replacingOccurrences(of: "name=cs2.exe", with: "name=" + secrets[0])
let unknownTrustFields = SteamGameDiagnostics.decode(unknownTrust)!.1
assert(unknownTrustFields["name"] == "redacted-unlisted")
assert(unknownTrustFields["result"] == "800b0100" && unknownTrustFields["choice"] == "1")
assert(!String(describing: unknownTrustFields).contains(secrets[0]))
assert(SteamGameDiagnostics.decode(unknownTrust + " private=" + secrets[1]) == nil)
put("madeira-log.txt", "[00:00:01.001] [INFO] [build] v0.1.3 (4) source=" + String(repeating: "a", count: 40) + "\n" + content + "\n" + service + "\n" + session + "\n" + unknownTrust + "\n" + bad.joined(separator: "\n") + "\n[session-log] Steam game cs2.exe: logs/cs2.exe-2026-11-09_00-03-55.txt\n")
try! fm.createDirectory(at: root.appendingPathComponent("logs"), withIntermediateDirectories: true)
try! fm.linkItem(at: root.appendingPathComponent("madeira-log.txt"), to: root.appendingPathComponent("logs/cs2.exe-2026-11-09_00-03-55.txt"))
let steam = "wine/drive_c/Program Files (x86)/Steam/"
put(steam + "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log",
    "VAC was unable to verify your game session.\nVAC " + secrets[0] + "\nSteamAPI " + secrets[1] + "\n" + secrets.joined(separator: " ") + "\n")
put(steam + "logs/console_log.txt", session + "\n" + String(repeating: "X", count: 5000) + service + "\n")
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
assert(entries.map(\.name) == ["manifest.json", "observations.json", "README.txt"])
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
assert(sources.contains { $0["source"] as? String == "cs2-session-alias" && $0["state"] as? String == "same-file-as-earlier-source" })
assert(sources.contains { $0["source"] as? String == "steam-connection" && $0["state"] as? String == "unavailable-or-not-owned-regular-file" })
let events = try! JSONSerialization.jsonObject(with: entries[1].data) as! [[String: Any]]
assert(events.count == 5)
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
assert((boundedManifest["sources"] as! [[String: Any]])[0]["truncated"] as? Bool == true)
// Preserve the actual early CS2 mapping/flags near5MiB as well as late
// verifier errors after the runtime log grows beyond the8MiB input budget.
let fillerLine = String(repeating: "x", count: 1023) + "\n"
put("madeira-log.txt", String(repeating: fillerLine, count: 5 * 1024) + flags + "\n" + module + "\n" + String(repeating: fillerLine, count: 4 * 1024) + unknownTrust + "\n")
let longLog = try! SteamGameDiagnostics.collect(documents: root)
let longEvents = try! JSONSerialization.jsonObject(with: longLog[1].data) as! [[String: Any]]
assert(longEvents.contains { $0["record"] as? String == "cs2-launch-flags-v1" })
assert(longEvents.contains { $0["record"] as? String == "cs2-module-v1" })
assert(longEvents.contains { ($0["fields"] as? [String: String])?["name"] == "redacted-unlisted" })
// An input-byte cap must not amplify8MiB of newlines into millions of
// Data subsequences before applying the row cap.
put("madeira-log.txt", String(repeating: "\n", count: 8 << 20))
let flood = try! SteamGameDiagnostics.collect(documents: root)
let floodManifest = try! JSONSerialization.jsonObject(with: flood[0].data) as! [String: Any]
assert(floodManifest["scanLimitReached"] as? Bool == true)
assert(floodManifest["rowsScanned"] as? Int == 131072)
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
    subprocess.run([swift, '-swift-version', '5', '-sanitize=address', *include, str(source), str(tmp / 'Writer.swift'), str(tmp / 'main.swift'), '-lz', '-o', str(exe)], check=True)
    archive = tmp / 'diagnostics.zip'
    subprocess.run([str(exe), str(docs), str(archive)], check=True)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert z.namelist() == ['manifest.json', 'observations.json', 'README.txt']
        manifest = json.loads(z.read('manifest.json'))
        assert manifest['vacVerdict'] == 'unmeasured'
        assert manifest['authenticationVerdict'] == 'unmeasured'
        assert manifest['trustVerdict'] == 'unmeasured'
        assert manifest['structuredProducerRows'] == 'accepted-from-main-runtime-log-only'
        assert manifest['sourceCommit'] == 'a' * 40
        body = b'\n'.join(z.read(n) for n in z.namelist())
        assert b'OPAQUE_SENTINEL' not in body and b'PRIVATE_SENTINEL' not in body
        assert b'76561198000000000' not in body and b'/private/var' not in body
print('PASS actual stored ZIP: safe three-entry inventory, CRC/readback, typed metadata and no raw source bodies or secret sentinels')
