#!/usr/bin/env python3
"""Compile the actual shared ZIP writer and inspect its output with zipfile.

No diagnostics, saves, account files or Wine process are accessed. Missing Swift
is an explicit SKIP unless --require-swift is requested by CI.
"""
from pathlib import Path
import argparse
import binascii
import io
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (ROOT / 'app/Madeira/SavesAndShortcuts.swift').read_text()
writer = source[source.index('final class SaveZipWriter {'):source.index('// MARK: - Zip reading')]
assert 'compression: Compression = .stored' in writer
assert 'case stored = 0, deflate = 8' in writer
assert 'deflateInit2_' in writer and 'Z_DEFLATED, -15' in writer
assert 'deflateBound(&stream' in writer
assert 'try Task.checkCancellation()' in writer
assert writer.count('Self.le16(compression.rawValue)') == 2
assert writer.count('Self.le32(compressedSize)') == 2
assert 'catch { failed = true; throw error }' in writer
saves = source[source.index('enum SaveBackup {'):source.index('struct ActivitySheet:')]
assert 'try zip.add(name: base + "/" + rel, data: data)' in saves
print('PASS writer source boundaries: compression is opt-in; save backups retain the default STORE call')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
    print('SKIP ZIP execution: no Swift toolchain; raw DEFLATE/STORE interoperability harness is ready for CI --require-swift')
    raise SystemExit(0)

text = (b'2026-11-10T12:34:56Z run=fixture frame=1234 phase=present renderer=software status=ready\n' * 12_000)
generator = random.Random(125)
random_bytes = bytes(generator.getrandbits(8) for _ in range(256 * 1024))
entries = [('logs/render.txt', text), ('empty.txt', b''), ('binary/random.bin', random_bytes), ('logs/診断.txt', 'UTF-8 fixture\n'.encode())]

# Exact pre-change STORE layout, independently encoded with struct. zipfile
# separately validates readability, names, methods, sizes, decompression/CRC.
def legacy_stored(items):
    body, central = bytearray(), bytearray()
    for name, payload in items:
        encoded = name.encode()
        checksum = binascii.crc32(payload)
        local = struct.pack('<IHHHHHIIIHH', 0x04034B50, 20, 0x800, 0, 0, 0x21,
                            checksum, len(payload), len(payload), len(encoded), 0) + encoded
        central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, 20, 20, 0x800, 0, 0, 0x21,
                               checksum, len(payload), len(payload), len(encoded), 0, 0, 0, 0, 0, len(body)) + encoded
        body += local + payload
    end = struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, len(items), len(items), len(central), len(body), 0)
    return bytes(body + central + end)

main = r'''
import Foundation
@main struct Check {
    static func main() async throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1]).resolvingSymlinksInPath()
        let fm = FileManager.default
        let names = ["logs/render.txt", "empty.txt", "binary/random.bin", "logs/診断.txt"]
        let payloads = try (0..<names.count).map { try Data(contentsOf: root.appendingPathComponent("payload-" + String($0))) }
        func fails(_ name: String, _ operation: () throws -> Void) {
            do { try operation(); fatalError("accepted: " + name) } catch {}
        }
        var stats: [String: [String: UInt64]] = [:]
        for compressed in [false, true] {
            let filename = compressed ? "deflated.zip" : "stored.zip"
            let zip = try SaveZipWriter(url: root.appendingPathComponent(filename))
            for index in names.indices {
                if compressed { try zip.add(name: names[index], data: payloads[index], compression: .deflate) }
                else { try zip.add(name: names[index], data: payloads[index]) }
            }
            stats[filename] = ["count": UInt64(zip.count), "offset": zip.offset]
            try zip.finish()
            let before = try Data(contentsOf: root.appendingPathComponent(filename))
            fails("entry after finish") { try zip.add(name: "extra", data: Data()) }
            fails("finish after finish") { try zip.finish() }
            assert(try Data(contentsOf: root.appendingPathComponent(filename)) == before)
        }
        let mixed = try SaveZipWriter(url: root.appendingPathComponent("mixed.zip"))
        try mixed.add(name: names[0], data: payloads[0])
        try mixed.add(name: names[1], data: payloads[1], compression: .deflate)
        try mixed.add(name: names[2], data: payloads[2], compression: .deflate)
        try mixed.finish()
        // Invalid metadata and pre-compression cancellation have not written
        // any ZIP header. A caller can still complete a new valid entry.
        let bounds = try SaveZipWriter(url: root.appendingPathComponent("bounds-recovered.zip"))
        fails("oversized UTF-8 filename") { try bounds.add(name: String(repeating: "x", count: 65_536), data: Data(), compression: .deflate) }
        assert(bounds.count == 0 && bounds.offset == 0)
        try bounds.add(name: "recovered.txt", data: payloads[0], compression: .deflate)
        try bounds.finish()
        // The test extension closes the actual FileHandle to inject a real
        // write error. The poisoned writer cannot append a completion record.
        let failedURL = root.appendingPathComponent("failed-unpublished.zip")
        let failed = try SaveZipWriter(url: failedURL)
        try failed.closeOutputForTesting()
        fails("closed output handle") { try failed.add(name: "failed.txt", data: payloads[0], compression: .deflate) }
        assert(failed.count == 0 && failed.offset == 0)
        fails("failed archive cannot be completed") { try failed.finish() }
        assert((try failedURL.resourceValues(forKeys: [.fileSizeKey])).fileSize == 0)
        let recovered = try SaveZipWriter(url: root.appendingPathComponent("write-recovered.zip"))
        try recovered.add(name: "recovered.txt", data: payloads[0], compression: .deflate)
        try recovered.finish()
        let cancelled = Task.detached { () throws -> Bool in
            let zip = try SaveZipWriter(url: root.appendingPathComponent("cancelled-recovered.zip"))
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                try zip.add(name: "cancelled.txt", data: payloads[0], compression: .deflate)
                return false
            } catch is CancellationError {}
            assert(zip.count == 0 && zip.offset == 0)
            // The default STORE path keeps its preexisting cancellation behavior.
            try zip.add(name: "stored-after-cancel.txt", data: payloads[0])
            try zip.finish()
            return true
        }
        let observedCancellation = try await cancelled.value
        assert(observedCancellation)
        let result = try JSONSerialization.data(withJSONObject: stats, options: [.sortedKeys])
        try result.write(to: root.appendingPathComponent("writer-stats.json"))
        assert(fm.fileExists(atPath: root.appendingPathComponent("write-recovered.zip").path))
        print("PASS actual Swift ZIP writer: opt-in compression, default STORE, empty/random/UTF-8 inputs, bounds, write failure and cancellation state")
    }
}
'''
# Throwing expressions do not belong in assert's nonthrowing autoclosure.
main = main.replace('assert(try Data(contentsOf: root.appendingPathComponent(filename)) == before)', 'let after = try Data(contentsOf: root.appendingPathComponent(filename)); assert(after == before)')
main = main.replace('assert((try failedURL.resourceValues(forKeys: [.fileSizeKey])).fileSize == 0)', 'let failedSize = try failedURL.resourceValues(forKeys: [.fileSizeKey]).fileSize; assert(failedSize == 0)')

with tempfile.TemporaryDirectory(prefix='madeira-diagnostic-zip-') as temporary:
    p = Path(temporary)
    if os.uname().sysname != 'Darwin':
        (p / 'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" export * link "z" }')
    (p / 'Writer.swift').write_text('import Foundation\nimport zlib\nenum LibraryError: Error { case message(String) }\n' + writer + '\nextension SaveZipWriter { func closeOutputForTesting() throws { try handle.close() } }\n')
    (p / 'Check.swift').write_text(main)
    for index, (_, value) in enumerate(entries):
        (p / f'payload-{index}').write_bytes(value)
    subprocess.run([swift, '-swift-version', '5', '-parse-as-library', '-I', str(p), str(p / 'Writer.swift'), str(p / 'Check.swift'), '-o', str(p / 'check')], check=True)
    subprocess.run([str(p / 'check'), str(p)], check=True)
    stats = json.loads((p / 'writer-stats.json').read_text())
    for filename, methods in [('stored.zip', [0] * 4), ('deflated.zip', [8] * 4), ('mixed.zip', [0, 8, 8])]:
        packed = (p / filename).read_bytes()
        with zipfile.ZipFile(io.BytesIO(packed)) as archive:
            assert archive.testzip() is None
            assert archive.namelist() == [name for name, _ in entries[:len(methods)]]
            for info, (name, payload), method in zip(archive.infolist(), entries, methods):
                assert info.compress_type == method
                assert info.file_size == len(payload) and info.CRC == binascii.crc32(payload)
                assert info.flag_bits == 0x800 and info.date_time == (1980, 1, 1, 0, 0, 0)
                assert archive.read(name) == payload
                local = struct.unpack_from('<IHHHHHIIIHH', packed, info.header_offset)
                assert local[0] == 0x04034B50 and local[3] == method
                assert local[6:9] == (info.CRC, info.compress_size, info.file_size)
                body = info.header_offset + 30 + local[9] + local[10]
                raw = packed[body:body + info.compress_size]
                assert (zlib.decompress(raw, -15) if method == 8 else raw) == payload
                if method == 8:
                    assert info.compress_size <= len(payload) + max(1024, len(payload) // 100)
            if filename in stats:
                assert stats[filename]['count'] == len(methods)
                assert stats[filename]['offset'] == archive.start_dir
    assert (p / 'stored.zip').read_bytes() == legacy_stored(entries), 'Default STORE bytes changed'
    with zipfile.ZipFile(p / 'deflated.zip') as archive:
        assert archive.getinfo('logs/render.txt').compress_size < len(text) // 20
        assert archive.getinfo('empty.txt').compress_size == 2
    assert (p / 'deflated.zip').stat().st_size < (p / 'stored.zip').stat().st_size // 3
    for filename in ['bounds-recovered.zip', 'write-recovered.zip']:
        with zipfile.ZipFile(p / filename) as archive:
            assert archive.testzip() is None and archive.read('recovered.txt') == text
            assert archive.getinfo('recovered.txt').compress_type == 8
    with zipfile.ZipFile(p / 'cancelled-recovered.zip') as archive:
        assert archive.testzip() is None and archive.namelist() == ['stored-after-cancel.txt']
        assert archive.read('stored-after-cancel.txt') == text
        assert archive.getinfo('stored-after-cancel.txt').compress_type == 0
    assert (p / 'failed-unpublished.zip').stat().st_size == 0
    corrupt = bytearray((p / 'deflated.zip').read_bytes())
    with zipfile.ZipFile(io.BytesIO(corrupt)) as archive:
        info = archive.getinfo('logs/render.txt')
        header = struct.unpack_from('<IHHHHHIIIHH', corrupt, info.header_offset)
        body = info.header_offset + 30 + header[9] + header[10]
        corrupt[body + info.compress_size // 2] ^= 1
    detected = False
    try:
        with zipfile.ZipFile(io.BytesIO(corrupt)) as archive:
            detected = archive.testzip() is not None
    except (zipfile.BadZipFile, zlib.error):
        detected = True
    assert detected, 'Corrupt DEFLATE payload escaped independent CRC/decompression checks'
    print('PASS Python ZIP interoperability: real method8/raw DEFLATE, correct CRC/sizes, >20x text reduction, exact legacy STORE bytes, empty/random/mixed entries, corruption detection and recovery archives')
