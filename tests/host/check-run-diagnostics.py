#!/usr/bin/env python3
"""Exercise the real bounded run collector, sanitizer and compressed ZIP writer.

Only isolated synthetic Documents/Steam trees are read. A missing Swift compiler
is reported SKIP; CI must pass --require-swift to require actual execution.
"""
from pathlib import Path
import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (ROOT / 'app/Madeira/RunDiagnostics.swift').read_text()
writer_source = (ROOT / 'app/Madeira/SavesAndShortcuts.swift').read_text()
writer = writer_source[writer_source.index('final class SaveZipWriter {'):writer_source.index('// MARK: - Zip reading')]
assert 'SteamGameDiagnostics.snapshot(' in source
assert 'compression: .deflate' in source
assert 'O_EXCL | O_NOFOLLOW' in source
assert 'if created && !complete' in source
assert 'SteamGameDiagnostics.collect(documents: documents)' in source
assert all(name not in source for name in ['loginusers.vdf', 'ssfn', 'config.vdf', 'URLSession'])
assert 'annotateGap: Bool = false' in (ROOT / 'app/Madeira/SteamGameDiagnostics.swift').read_text()
print('PASS run export source scope: fixed-source snapshots, typed VAC remains separate, compressed ZIP, owned-directory failure cleanup')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
    print('SKIP run collector/ZIP execution: no Swift toolchain; actual-source harness is ready for CI --require-swift')
    raise SystemExit(0)

code = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@main struct Check {
    static func main() throws {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true).resolvingSymlinksInPath()
        let documents = base.appendingPathComponent("Documents", isDirectory: true)
        let output = base.appendingPathComponent("Exports", isDirectory: true)
        try fm.createDirectory(at: documents, withIntermediateDirectories: true)
        try fm.createDirectory(at: output, withIntermediateDirectories: true)
        func checkpoint(_ text: String) { FileHandle.standardError.write(Data(("[run-diagnostics-test] " + text + "\n").utf8)) }
        func put(_ relative: String, _ text: String, root: URL? = nil) throws {
            let url = (root ?? documents).appendingPathComponent(relative)
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(text.utf8).write(to: url)
        }
        func fails(_ label: String, _ operation: () throws -> Void) {
            do { try operation(); fatalError("accepted: " + label) } catch {}
        }
        func json(_ entries: [SteamGameDiagnostics.Entry], _ name: String) throws -> [String: Any] {
            let bytes = entries.first { $0.name == name }!.data
            return try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        }
        func text(_ entries: [SteamGameDiagnostics.Entry], _ name: String) -> String {
            String(decoding: entries.first { $0.name == name }!.data, as: UTF8.self)
        }
        let revision = String(repeating: "a", count: 40), virtualHash = String(repeating: "b", count: 64)
        let jitHash = String(repeating: "c", count: 64)
        let compactUUID = "00112233445566778899aabbccddeeff"
        let nativeUUID = "00112233-4455-6677-8899-aabbccddeeff"
        let flags = "[cs2-launch-flags-v1] pid=033c tid=0340 steam=1 condebug=1 joy=1 insecure=0 allow-third-party=0 argument-count=3 unknown-count=0 known-sequence=0,1,2 parse-complete=1 coverage=accepted-process-params"
        let provenance = "[native-build-provenance-v1] package-source=\(revision) native-uuid=\(compactUUID) packaged-uuid=\(nativeUUID) uuid-status=match virtual-source=\(virtualHash) expected-virtual=\(virtualHash) virtual-build=\(revision) virtual-status=match jit-source=\(jitHash) expected-jit=\(jitHash) jit-build=\(revision) jit-status=match compiled-code-tail-mb=512 expected-code-tail-mb=512 policy-status=match"
        let faultPrefix = "[fault-site-v1] family=exclusive tracked-rank=1 hits=42 pc=0x7c01234560 code-pe=0x71c0000000 code-rva=123456 "
        let faultRows = ["unchanged", "changed", "unverifiable"].map { faultPrefix + "cookies=" + $0 + " metadata=first-event" }
        let useful = ["[build] source=\(revision)", provenance,
            "[dynamic-memory-pressure-v1] cache-detached=151010992 entries=2430 coherent=202 physical-freed=unmeasured",
            "[allocator] event=code-buffer-capacity reserved-mb=4096 committed-mb=512 free-mb=3584",
            "[process] pid=033c parent=0020 image=cs2.exe machine=8664 status=00000000",
            "[module] pid=033c module=libarm64ecfex.dll image-size=1048576 base=0x12345678",
            "[steam-service] result=1053", flags]
        let privateRows = [
            "Authorization: Bearer BEARER_PRIVATE_SENTINEL",
            "refresh_token=REFRESH_PRIVATE_SENTINEL", "Set-Cookie: COOKIE_PRIVATE_SENTINEL",
            "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQUklWQVRFIn0.c2lnbmF0dXJl",
            "row status=ready person=\"QUOTED_PRIVATE_NAME\"",
            "Connected to private-host.example.com:27015", "remote=203.0.113.7:27015",
            "remote=[2001:db8::1234]:27015", "SteamID=76561198012345678",
            #"file=C:\Users\PRIVATE_WINDOWS_USER\Documents\save.dat"#,
            "file=/Users/PRIVATE_MAC_USER/Documents/save.dat",
            #"file=C:\Steam\userdata\72345678\730\cache.dat"#,
            "[Client] PRIVATE_CHAT_NAME: PRIVATE_CHAT_BODY", "Account ID: 87654321",
            "[ALL] PRIVATE_ALL_CHAT", "say_team PRIVATE_TEAM_CHAT",
            "payload=ABCDEFGHIJKLMNOPQRSTUVWX0123456789",
            "unknown=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        ]
        let rejectedFaultRows = [
            "cookies=unchanged metadata=first-event", "[other-site-v1] cookies=unchanged metadata=first-event",
            faultPrefix + "cookies=REAL_COOKIE_PRIVATE_SENTINEL metadata=first-event",
            faultPrefix + "Cookie: REAL_COOKIE_PRIVATE_SENTINEL cookies=unchanged metadata=first-event",
            faultPrefix + "cookies=unchanged metadata=first-event Cookie: REAL_COOKIE_PRIVATE_SENTINEL",
            faultPrefix + "password=PASSWORD_PRIVATE_SENTINEL cookies=unchanged metadata=first-event",
            faultPrefix + "Authorization: Bearer AUTH_PRIVATE_SENTINEL cookies=unchanged metadata=first-event",
            faultPrefix + "access_token=TOKEN_PRIVATE_SENTINEL cookies=unchanged metadata=first-event"
        ]
        for row in rejectedFaultRows { assert(RunDiagnostics.sanitize(row) == nil, "secret row accepted") }
        assert(RunDiagnostics.sanitize("[unrecognized-diagnostic-marker-v1] status=ready") == "[[redacted-opaque-value]] status=ready")
        let closure = "11/12 14:53:04 [Networking] Netchan client closed unexpectedly: NETWORK_DISCONNECT_TIMEOUT"
        assert(RunDiagnostics.sanitize(closure) == closure)
        assert(RunDiagnostics.sanitize("payload=NETWORK_DISCONNECT_TIMEOUT") == "payload=[redacted-opaque-value]")
        assert(RunDiagnostics.sanitize(closure + " Cookie: PRIVATE_COOKIE") == nil)
        assert(RunDiagnostics.sanitize(closure + " access_token=PRIVATE_TOKEN") == nil)
        assert(RunDiagnostics.sanitize(closure + " UNKNOWN_CONNECTION_PAYLOAD_1234567890")!.hasSuffix("[redacted-opaque-value]"))
        let repeated = String(repeating: "[allocator] event=sample reserved-mb=4096 committed-mb=512 status=ready\n", count: 8_000)
        let main = (useful + faultRows + privateRows + rejectedFaultRows + [String(repeating: "x", count: 20_000), "non-ascii=\u{00e9}"]).joined(separator: "\n") + "\n" + repeated
        try put("madeira-log.txt", main)
        let steam = "wine/drive_c/Program Files (x86)/Steam/"
        let console = steam + "steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log"
        try put(console, "11/10 12:34:56 VAC was unable to verify your game session.\n[Client] console-status=ready frame=123\n[Client] PRIVATE_CONSOLE_CHAT: PRIVATE_CONSOLE_MESSAGE\n")
        for name in ["console", "gameprocess", "service", "content", "connection"] {
            try put(steam + "logs/" + name + "_log.txt", "[Steam] component=\(name) status=ready result=0\n" + privateRows.joined(separator: "\n") + "\n")
        }
        let privateFiles = ["wine/drive_c/Program Files (x86)/Steam/config/loginusers.vdf",
            "wine/drive_c/Program Files (x86)/Steam/config/config.vdf", "wine/drive_c/Program Files (x86)/Steam/ssfn123456",
            "wine/drive_c/Program Files (x86)/Steam/userdata/72345678/config/localconfig.vdf", "arbitrary.txt"]
        for name in privateFiles { try put(name, "PRIVATE_CONFIG_CONTENT_DONT_READ:" + name + "\n") }
        let external = base.appendingPathComponent("External", isDirectory: true)
        try fm.createDirectory(at: external, withIntermediateDirectories: true)
        try put("logs/bootstrap_log.txt", "PRIVATE_EXTERNAL_LINK_CONTENT\n", root: external)
        let linked = documents.appendingPathComponent(steam + "logs/bootstrap_log.txt")
        try fm.createSymbolicLink(at: linked, withDestinationURL: external.appendingPathComponent("logs/bootstrap_log.txt"))
        let fifo = documents.appendingPathComponent(steam + "logs/cef_log.txt")
        guard mkfifo(fifo.path, 0o600) == 0 else { fatalError("could not create FIFO fixture") }
        let alternateParent = documents.appendingPathComponent("wine/drive_c/Program Files", isDirectory: true)
        try fm.createDirectory(at: alternateParent, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: alternateParent.appendingPathComponent("Steam"), withDestinationURL: external)
        let originals = try (["madeira-log.txt", console] + privateFiles).map {
            ($0, try Data(contentsOf: documents.appendingPathComponent($0)))
        }
        let info: [String: Any] = ["CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "456", "MadeiraBuild": "fixture-build",
            "UnapprovedBundleField": "PRIVATE_BUNDLE_FIELD",
            "MadeiraNativeBuildProvenance": ["packageSourceRevision": revision, "virtualBuildRevision": revision,
                "jitallocatorBuildRevision": revision, "expectedVirtualSourceSHA256": virtualHash,
                "expectedJITAllocatorSourceSHA256": jitHash, "nativeImageUUID": nativeUUID,
                "expectedJITCodeTailLimitMB": 512, "unapproved": "PRIVATE_PROVENANCE_FIELD"]]
        CS2VACMarkers.shared.begin(appID: 730)
        _ = CS2VACMarkers.shared.beginTest()
        _ = CS2VACMarkers.shared.markError()
        checkpoint("collect broad/default")
        let entries = try RunDiagnostics.collect(documents: documents, bundleInfo: info,
            now: Date(timeIntervalSince1970: 1_800_000_000), uptimeNanoseconds: 424242)
        assert(Set(entries.map(\.name)).count == entries.count)
        let names = Set(entries.map(\.name))
        assert(["manifest.json", "metadata.json", "clocks-and-markers.json", "sanitized/madeira-session.log", "sanitized/cs2-console.log", "sanitized/steam-console.log", "vac/observations.json", "vac/cs2-console.json", "vac/summary.json"].allSatisfy(names.contains))
        let sanitized = text(entries, "sanitized/madeira-session.log")
        for row in useful { assert(sanitized.contains(row), "useful row lost: " + row) }
        for row in faultRows {
            let expected = row.replacingOccurrences(of: " cookies=", with: " code-seal=")
            assert(RunDiagnostics.sanitize(row) == expected)
            assert(sanitized.contains(expected), "fault module/RVA row lost")
        }
        assert(text(entries, "sanitized/cs2-console.log").contains("VAC was unable to verify your game session."))
        assert(!text(entries, "vac/observations.json").contains("code-buffer-capacity"))
        assert(text(entries, "vac/observations.json").contains("cs2-launch-flags-v1"))
        let manifest = try json(entries, "manifest.json")
        assert(manifest["schema"] as? String == "madeira-run-diagnostics-v1")
        assert(manifest["compression"] as? String == "ZIP-method-8-raw-DEFLATE")
        let sources = manifest["sources"] as! [[String: Any]]
        let mainSource = sources.first { $0["source"] as? String == "madeira-session" }!
        assert((mainSource["rowsOmitted"] as! NSNumber).intValue > 0)
        assert((mainSource["rowsRedacted"] as! NSNumber).intValue > 0)
        assert((mainSource["overlongRowsOmitted"] as! NSNumber).intValue == 1)
        assert(sources.first { $0["source"] as? String == "steam-bootstrap" }?["state"] as? String == "unavailable-or-not-owned-regular-file")
        assert(sources.first { $0["source"] as? String == "steam-cef" }?["state"] as? String == "unavailable-or-not-owned-regular-file")
        assert(!names.contains("sanitized/steam-bootstrap.log") && !names.contains("sanitized/steam-cef.log"))
        let metadata = try json(entries, "metadata.json")
        assert(metadata["CFBundleShortVersionString"] as? String == "1.2.3")
        assert(metadata["exportAppDispatchUptimeNanoseconds"] as? String == "424242")
        assert(metadata["UnapprovedBundleField"] == nil)
        let provenanceInfo = metadata["packagedNativeBuildProvenance"] as! [String: Any]
        assert(provenanceInfo["packageSourceRevision"] as? String == revision)
        assert(provenanceInfo["nativeImageUUID"] as? String == nativeUUID && provenanceInfo["unapproved"] == nil)
        let clocks = try json(entries, "clocks-and-markers.json")
        assert(!(clocks["markers"] as! [[String: Any]]).isEmpty)
        checkpoint("export broad/default")
        let archive = try RunDiagnostics.export(documents: documents, temporaryDirectory: output, bundleInfo: info)
        // Small line/byte quotas must retain both provenance/start and the
        // recent failure end, with explicit omissions in the manifest.
        let boundedDocs = base.appendingPathComponent("BoundedDocuments", isDirectory: true)
        try fm.createDirectory(at: boundedDocs, withIntermediateDirectories: true)
        let boundedBody = "[allocator] STARTUP_ROW_PRESENT status=ready\n" + String(repeating: "[allocator] sample=ready\n", count: 2_000) + "[process] RECENT_END_PRESENT status=failed\n"
        try put("madeira-log.txt", boundedBody, root: boundedDocs)
        var bounded = RunDiagnostics.Limits()
        bounded.mainBytes = 4096; bounded.consoleBytes = 1024; bounded.steamBytes = 1024
        bounded.totalBytes = 256 << 10; bounded.lines = 4; bounded.lineBytes = 4096
        checkpoint("collect startup/recent four-row budget")
        let limited = try RunDiagnostics.collect(documents: boundedDocs, limits: bounded)
        let limitedText = text(limited, "sanitized/madeira-session.log")
        assert(limitedText.contains("STARTUP_ROW_PRESENT") && limitedText.contains("RECENT_END_PRESENT"))
        let limitedManifest = try json(limited, "manifest.json")
        let limitedMain = (limitedManifest["sources"] as! [[String: Any]]).first { $0["source"] as? String == "madeira-session" }!
        assert(limitedMain["sourceByteTruncated"] as? Bool == true)
        assert(limitedMain["lineBudgetReached"] as? Bool == true)
        assert((limitedMain["capturedSourceBytes"] as! NSNumber).intValue <= bounded.mainBytes)
        assert(limited.reduce(0) { $0 + $1.data.count } <= bounded.totalBytes)
        assert(text(limited, "vac/manifest.json").contains("rawLogBodies"))
        var priority = RunDiagnostics.Limits()
        priority.mainBytes = 256 << 10; priority.consoleBytes = 1024; priority.steamBytes = 1024; priority.totalBytes = 256 << 10
        checkpoint("collect typed VAC priority under total budget")
        let prioritized = try RunDiagnostics.collect(documents: documents, limits: priority)
        let priorityManifest = try json(prioritized, "manifest.json")
        assert(priorityManifest["typedVACSnapshot"] as? String == "included-separate-bounded-typed-snapshot")
        assert(["vac/manifest.json", "vac/observations.json", "vac/cs2-console.json", "vac/summary.json", "vac/README.txt"].allSatisfy { wanted in prioritized.contains { $0.name == wanted } })
        assert(prioritized.reduce(0) { $0 + $1.data.count } <= priority.totalBytes)
        // Cancellation observes only this request's private destination after
        // its first compressed member wrote bytes. Its sibling is retained.
        let cancelRoot = base.appendingPathComponent("CancelExports", isDirectory: true)
        let keep = cancelRoot.appendingPathComponent("unrelated/keep.txt")
        try fm.createDirectory(at: keep.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("unrelated-kept".utf8).write(to: keep)
        var observedArchiveBytes = false
        let stop: () -> Bool = {
            for name in (try? fm.contentsOfDirectory(atPath: cancelRoot.path)) ?? [] where name.hasPrefix("madeira-run-diagnostics-") {
                let file = cancelRoot.appendingPathComponent(name).appendingPathComponent("Madeira-Run-Diagnostics.zip")
                if let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 0 {
                    observedArchiveBytes = true; return true
                }
            }
            return false
        }
        checkpoint("cancel after first ZIP member")
        do {
            _ = try RunDiagnostics.export(documents: documents, temporaryDirectory: cancelRoot, cancelled: stop)
            fatalError("cancelled archive was returned")
        } catch RunDiagnostics.Failure.cancelled {}
        assert(observedArchiveBytes)
        assert(try fm.contentsOfDirectory(atPath: cancelRoot.path) == ["unrelated"])
        assert(try Data(contentsOf: keep) == Data("unrelated-kept".utf8))
        let retry = try RunDiagnostics.export(documents: documents, temporaryDirectory: cancelRoot, bundleInfo: info)
        let noOutput = base.appendingPathComponent("not-a-directory")
        try Data("write-failure-input-kept".utf8).write(to: noOutput)
        fails("unavailable output directory") { _ = try RunDiagnostics.export(documents: documents, temporaryDirectory: noOutput) }
        assert(try Data(contentsOf: noOutput) == Data("write-failure-input-kept".utf8))
        let unavailableRoot = base.appendingPathComponent("UnavailableExports", isDirectory: true)
        try fm.createDirectory(at: unavailableRoot, withIntermediateDirectories: true)
        fails("unavailable Documents") { _ = try RunDiagnostics.export(documents: base.appendingPathComponent("missing-documents"), temporaryDirectory: unavailableRoot) }
        assert(try fm.contentsOfDirectory(atPath: unavailableRoot.path).isEmpty)
        let docsLink = base.appendingPathComponent("LinkedDocuments")
        try fm.createSymbolicLink(at: docsLink, withDestinationURL: documents)
        fails("linked Documents root") { _ = try RunDiagnostics.collect(documents: docsLink) }
        for (name, bytes) in originals { assert(try Data(contentsOf: documents.appendingPathComponent(name)) == bytes) }
        assert(try fm.destinationOfSymbolicLink(atPath: linked.path) == external.appendingPathComponent("logs/bootstrap_log.txt").path)
        let result: [String: Any] = ["archive": archive.path, "retry": retry.path, "totalUncompressed": entries.reduce(0) { $0 + $1.data.count }]
        try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]).write(to: base.appendingPathComponent("result.json"))
        print("PASS actual run diagnostics: broad runtime/real console/Steam retention, fixed-source nofollow reads, metadata clocks and typed VAC, bounded startup/recent evidence, cancellation cleanup/retry, input preservation")
    }
}
'''
# Foundation throwing reads must be evaluated before assert's autoclosure.
replacements = {
    'assert(try fm.contentsOfDirectory(atPath: cancelRoot.path) == ["unrelated"])': 'let cancelRemaining = try fm.contentsOfDirectory(atPath: cancelRoot.path); assert(cancelRemaining == ["unrelated"])',
    'assert(try Data(contentsOf: keep) == Data("unrelated-kept".utf8))': 'let kept = try Data(contentsOf: keep); assert(kept == Data("unrelated-kept".utf8))',
    'assert(try Data(contentsOf: noOutput) == Data("write-failure-input-kept".utf8))': 'let keptOutput = try Data(contentsOf: noOutput); assert(keptOutput == Data("write-failure-input-kept".utf8))',
    'assert(try fm.contentsOfDirectory(atPath: unavailableRoot.path).isEmpty)': 'let unavailableRemaining = try fm.contentsOfDirectory(atPath: unavailableRoot.path); assert(unavailableRemaining.isEmpty)',
    'for (name, bytes) in originals { assert(try Data(contentsOf: documents.appendingPathComponent(name)) == bytes) }': 'for (name, bytes) in originals { let actual = try Data(contentsOf: documents.appendingPathComponent(name)); assert(actual == bytes) }',
    'assert(try fm.destinationOfSymbolicLink(atPath: linked.path) == external.appendingPathComponent("logs/bootstrap_log.txt").path)': 'let linkTarget = try fm.destinationOfSymbolicLink(atPath: linked.path); assert(linkTarget == external.appendingPathComponent("logs/bootstrap_log.txt").path)',
}
for before, after in replacements.items():
    assert before in code
    code = code.replace(before, after)

with tempfile.TemporaryDirectory(prefix='madeira-run-export-') as temporary:
    p = Path(temporary).resolve()
    if os.uname().sysname != 'Darwin':
        (p / 'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" export * link "z" }')
    (p / 'Writer.swift').write_text('import Foundation\nimport zlib\nenum LibraryError: Error { case message(String) }\n' + writer)
    (p / 'Check.swift').write_text(code)
    executable = p / 'check'
    subprocess.run([swift, '-swift-version', '5', '-parse-as-library', '-I', str(p),
                    str(ROOT / 'app/Madeira/CS2VACMarkers.swift'), str(ROOT / 'app/Madeira/SteamGameDiagnostics.swift'),
                    str(ROOT / 'app/Madeira/RunDiagnostics.swift'), str(p / 'Writer.swift'), str(p / 'Check.swift'), '-o', str(executable)], check=True)
    subprocess.run([str(executable), str(p)], check=True, timeout=180)
    result = json.loads((p / 'result.json').read_text())
    private = ['BEARER_PRIVATE_SENTINEL', 'REFRESH_PRIVATE_SENTINEL', 'COOKIE_PRIVATE_SENTINEL',
               'eyJhbGciOiJIUzI1NiJ9', 'QUOTED_PRIVATE_NAME', 'private-host.example.com', '203.0.113.7',
               '2001:db8::1234', '76561198012345678', 'PRIVATE_WINDOWS_USER', 'PRIVATE_MAC_USER', '72345678', '87654321',
               'PRIVATE_CHAT_NAME', 'PRIVATE_CHAT_BODY', 'PRIVATE_CONSOLE_CHAT', 'PRIVATE_CONSOLE_MESSAGE',
               'PRIVATE_ALL_CHAT', 'PRIVATE_TEAM_CHAT', 'ABCDEFGHIJKLMNOPQRSTUVWX0123456789', 'd' * 64,
               'PRIVATE_CONFIG_CONTENT_DONT_READ', 'PRIVATE_EXTERNAL_LINK_CONTENT', 'PRIVATE_BUNDLE_FIELD', 'PRIVATE_PROVENANCE_FIELD']
    for filename in ['archive', 'retry']:
        path = Path(result[filename])
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            assert all(item.compress_type == zipfile.ZIP_DEFLATED for item in archive.infolist())
            assert all(not name.startswith('/') and '..' not in name.split('/') for name in archive.namelist())
            body = b'\n'.join(archive.read(name) for name in archive.namelist()).decode()
            for secret in private:
                assert secret not in body, 'Private fixture leaked: ' + secret
            assert 'event=code-buffer-capacity' in archive.read('sanitized/madeira-session.log').decode()
            assert 'libarm64ecfex.dll' in archive.read('sanitized/madeira-session.log').decode()
            assert 'VAC was unable to verify your game session.' in archive.read('sanitized/cs2-console.log').decode()
            assert len(archive.read('vac/observations.json')) > 2
            main = archive.getinfo('sanitized/madeira-session.log')
            assert main.compress_size < main.file_size // 10, 'Repetitive runtime log was not compressed'
            manifest = json.loads(archive.read('manifest.json'))
            assert manifest['schema'] == 'madeira-run-diagnostics-v1'
            assert manifest['typedVACSnapshot'] == 'included-separate-bounded-typed-snapshot'
            assert not any('config/' in name or 'ssfn' in name for name in archive.namelist())
    print('PASS Python run ZIP readback: actual method8 compression, private fixtures absent, broad and typed diagnostics retained, private output permissions and cancellation retry archive valid')
