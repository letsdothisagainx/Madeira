#!/usr/bin/env python3
"""Run the production streaming exporter against an owned 256 MiB run log.

The fixture is generated outside the Swift process, so measured RSS includes
only the exporter/runtime. No Wine prefix, Steam account or user log is read.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (ROOT / 'app/Madeira/RunDiagnostics.swift').read_text()
production = source[source.index('    static func export(documents:'):]
assert 'try collect(' not in production and 'let entries = try collect' not in production
assert 'streamSource(' in production and 'file: stage' in production
assert 'SaveZipWriter(handle: FileHandle(fileDescriptor: fd, closeOnDealloc: true))' in production
assert 'SaveZipWriter(url: result)' not in production
assert '64 << 10' in source and 'autoreleasepool { sanitize(raw) }' in source
writer_source = (ROOT / 'app/Madeira/SavesAndShortcuts.swift').read_text()
writer = writer_source[writer_source.index('final class SaveZipWriter {'):writer_source.index('// MARK: - Zip reading')]
assert 'func add(name: String, file: FileHandle' in writer
assert '0x0807_4b50' in writer and 'while remaining > 0' in writer
swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
    print('SKIP actual streaming/RSS execution: Swift is unavailable; source scope passed')
    raise SystemExit(0)

main = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@main struct Check {
    static func peakBytes() -> UInt64 {
        var usage = rusage()
        #if canImport(Darwin)
        precondition(getrusage(RUSAGE_SELF, &usage) == 0)
        return UInt64(usage.ru_maxrss)
        #else
        precondition(getrusage(RUSAGE_SELF.rawValue, &usage) == 0)
        return UInt64(usage.ru_maxrss) * 1024
        #endif
    }
    static func main() throws {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: CommandLine.arguments[1]).resolvingSymlinksInPath()
        let docs = base.appendingPathComponent("Documents"), exports = base.appendingPathComponent("Exports")
        try fm.createDirectory(at: exports, withIntermediateDirectories: true)
        var limits = RunDiagnostics.Limits()
        limits.mainBytes = 64 << 20; limits.totalBytes = 96 << 20; limits.lines = 1_000_000
        // Initialize Foundation/regex/metadata paths using an empty owned run,
        // without reading the large fixture into the baseline measurement.
        let initialize = base.appendingPathComponent("InitializeDocuments")
        try fm.createDirectory(at: initialize, withIntermediateDirectories: true)
        _ = RunDiagnostics.sanitize("[allocator] initialize=ready")
        _ = try RunDiagnostics.export(documents: initialize, temporaryDirectory: exports)
        let baseline = peakBytes()
        let archive = try RunDiagnostics.export(documents: docs, temporaryDirectory: exports, limits: limits)
        let peak = peakBytes()
        precondition(peak < 128 << 20, "streaming export unexpectedly retained large log buffers")
        precondition(peak - baseline <= 32 << 20, "streaming export added more than its bounded working-memory allowance")
        var small = limits
        small.mainBytes = 4096; small.totalBytes = 256 << 10; small.lines = 4
        let compact = try RunDiagnostics.export(documents: docs, temporaryDirectory: exports, limits: small)
        // Cancellation during source streaming, not just before ZIP creation.
        let cancellation = base.appendingPathComponent("Cancel")
        try fm.createDirectory(at: cancellation, withIntermediateDirectories: true)
        var observedSpool = false
        func stop() -> Bool {
            for name in (try? fm.contentsOfDirectory(atPath: cancellation.path)) ?? [] {
                let spool = cancellation.appendingPathComponent(name).appendingPathComponent("source.tmp")
                if let count = try? spool.resourceValues(forKeys: [.fileSizeKey]).fileSize, count > 128 << 10 {
                    observedSpool = true; return true
                }
            }
            return false
        }
        do {
            _ = try RunDiagnostics.export(documents: docs, temporaryDirectory: cancellation, limits: limits, cancelled: stop)
            preconditionFailure("cancelled export was returned")
        } catch RunDiagnostics.Failure.cancelled {}
        precondition(observedSpool)
        let cancelledFiles = try fm.contentsOfDirectory(atPath: cancellation.path)
        precondition(cancelledFiles.isEmpty)
        // Append between the producer's snapshot and final stat. A live log
        // remains exportable, and the manifest must disclose the change.
        let raceDocs = base.appendingPathComponent("RaceDocs")
        try fm.createDirectory(at: raceDocs, withIntermediateDirectories: true)
        let raceFile = raceDocs.appendingPathComponent("madeira-log.txt")
        try Data(String(repeating: "[allocator] race=ready\n", count: 32_000).utf8).write(to: raceFile)
        var appended = false
        func appendDuringRead() -> Bool {
            if !appended {
                for name in (try? fm.contentsOfDirectory(atPath: exports.path)) ?? [] where name.hasPrefix("madeira-run-diagnostics-") {
                    let spool = exports.appendingPathComponent(name).appendingPathComponent("source.tmp")
                    if let count = try? spool.resourceValues(forKeys: [.fileSizeKey]).fileSize, count > 0 {
                        if let handle = try? FileHandle(forWritingTo: raceFile) {
                            _ = try? handle.seekToEnd()
                            try? handle.write(contentsOf: Data("[process] appended-after-snapshot status=ready\n".utf8))
                            try? handle.close(); appended = true
                        }
                    }
                }
            }
            return false
        }
        let race = try RunDiagnostics.export(documents: raceDocs, temporaryDirectory: exports, cancelled: appendDuringRead)
        precondition(appended)
        // Useful failure stages contain no container or input file path.
        do {
            _ = try RunDiagnostics.export(documents: docs, temporaryDirectory: base.appendingPathComponent("missing"))
            preconditionFailure("missing temporary storage accepted")
        } catch let error as RunDiagnostics.Failure {
            guard case .stage(let stage, let code) = error else { preconditionFailure("missing stage") }
            precondition(stage == "opening temporary storage" && code != 0)
            precondition(!error.localizedDescription.contains(base.path))
        }
        let result: [String: Any] = ["archive": archive.path, "compact": compact.path, "race": race.path,
                                    "baselineRSSBytes": baseline, "peakRSSBytes": peak]
        try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]).write(to: base.appendingPathComponent("result.json"))
        print("PASS actual streamed export:64MiB selected from256MiB source, bounded RSS, complete ZIP, small row limits, cancellation cleanup and live-file change reporting")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-run-streaming-') as temporary:
    p = Path(temporary).resolve()
    documents = p / 'Documents'
    documents.mkdir()
    log = documents / 'madeira-log.txt'
    row = b'[allocator] stage=stream status=ready ' + b'v=0 ' * 115 + b'\n'
    block = row * max(1, (1 << 20) // len(row))
    with log.open('wb') as file:
        file.write(b'[process] STARTUP_PRESENT status=ready\n')
        file.write(b'access_token=DO_NOT_EXPORT_TOKEN\n')
        for _ in range(256):
            file.write(block)
        file.write(b'password=DO_NOT_EXPORT_PASSWORD\n')
        file.write(b'[process] RECENT_END_PRESENT status=failed\n')
    with log.open('rb') as file:
        before = hashlib.file_digest(file, 'sha256').hexdigest()
    if os.uname().sysname != 'Darwin':
        (p / 'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" export * link "z" }')
    (p / 'Writer.swift').write_text('import Foundation\nimport zlib\n' + writer)
    (p / 'Check.swift').write_text(main)
    executable = p / 'check'
    subprocess.run([swift, '-swift-version', '5', '-parse-as-library', '-I', str(p),
                    str(ROOT / 'app/Madeira/CS2VACMarkers.swift'), str(ROOT / 'app/Madeira/SteamGameDiagnostics.swift'),
                    str(ROOT / 'app/Madeira/RunDiagnostics.swift'), str(p / 'Writer.swift'), str(p / 'Check.swift'), '-o', str(executable)], check=True)
    # This is a bounded-memory/correctness stress case, not a host-speed gate.
    # The debug Swift fixture can exceed four minutes on a loaded Apple runner.
    subprocess.run([str(executable), str(p)], check=True, timeout=600)
    result = json.loads((p / 'result.json').read_text())
    with log.open('rb') as file:
        assert before == hashlib.file_digest(file, 'sha256').hexdigest(), 'Exporter changed source log'
    for name in ['archive', 'compact', 'race']:
        path = Path(result[name])
        assert list(path.parent.iterdir()) == [path], 'Private spools were retained'
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            assert all(entry.compress_type == zipfile.ZIP_DEFLATED for entry in archive.infolist())
            assert all('tmp' not in entry.filename for entry in archive.infolist())
            manifest = json.loads(archive.read('manifest.json'))
            source = next(item for item in manifest['sources'] if item['source'] == 'madeira-session')
            assert source['ioBufferBytes'] == 65536
            assert source['state'] == 'sanitized-streamed-snapshot'
            if name != 'race':
                body = archive.read('sanitized/madeira-session.log')
                assert b'STARTUP_PRESENT' in body and b'RECENT_END_PRESENT' in body
                assert b'DO_NOT_EXPORT_TOKEN' not in body and b'DO_NOT_EXPORT_PASSWORD' not in body
                assert b'[run-export-gap]' in body
                assert source['sourceByteTruncated']
            else:
                assert source['changedDuringRead']
                assert b'appended-after-snapshot' not in archive.read('sanitized/madeira-session.log')
            if name == 'compact':
                assert source['rowsScanned'] <= 4
                assert len(archive.read('sanitized/madeira-session.log')) <= 4096
    print('PASS streaming memory measurement: baseline=%d peak=%d delta=%d bytes for256MiB source/64MiB selected' %
          (result['baselineRSSBytes'], result['peakRSSBytes'], result['peakRSSBytes'] - result['baselineRSSBytes']))
    print('PASS independent ZIP readback: streaming descriptors/CRC, startup/latest evidence, secret exclusions, source preservation, closed spools and useful private errors')
