#!/usr/bin/env python3
"""Compile the actual production Swift bridge installer with real CryptoKit.

Unequal-size AMD64 PE fixtures reproduce Foundation URL metadata caching during
atomic DLL upgrades. No Wine, account or installed game is used. The optional
combined test requires authentic official archives; downloads need an explicit
flag. Production Swift, manifest checks and hashes are never rewritten.
"""
from pathlib import Path
import argparse
import hashlib
import urllib.request
import uuid
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
parser.add_argument('--official-archives', type=Path, help='Use genuine pinned Valve archives for combined cache-rebuild/bridge-upgrade sequence')
parser.add_argument('--download-official', action='store_true', help='Explicitly permit downloads of missing exact pinned archives')
args = parser.parse_args()
if os.uname().sysname != 'Darwin' or not shutil.which('swiftc'):
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: macOS Swift/CryptoKit is required')
    print('SKIP production Swift bridge execution: macOS Swift/CryptoKit required')
    raise SystemExit(0)

# Network access is explicit and all files retain the production recipe pins.
packages = [
    ('bins_cef_win32.zip.1c1d9dc1d899e7c8d1cff9cb0fcc11b89e412b98', 130079979,
     'fee14790d59463f31693ef95e10327824f5bdd95baf0aa8fae3b81aea98e794f'),
    ('bins_webhelpers_win32.zip.8a153ec2ee2090c19b25204806ffca2a7ba15bf2', 2735010,
     '1ab3b3834172a644759860f65d853970ba1d8b65f30190aae774395d69136307'),
    ('bins_win32.zip.23e34a6d4b10596a44561a5100dac5585d2517da', 59544006,
     '8b712b2a3412a9066b7725f4e1c5cef9a7ca5b187b6585a5b92d25d09df0ba62'),
]
if args.download_official and args.official_archives is None:
    parser.error('--download-official requires --official-archives')
def file_sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()

if args.official_archives is not None:
    args.official_archives.mkdir(parents=True, exist_ok=True)
    recipe_source = (ROOT / 'app/Madeira/SteamBrowserRuntime.swift').read_text()
    for name, count, digest in packages:
        assert name in recipe_source and digest in recipe_source
        archive = args.official_archives / name
        if not archive.exists():
            assert args.download_official, 'Missing pinned archive; explicit --download-official required'
            temporary = archive.with_name(name + '.part-' + uuid.uuid4().hex)
            url = 'https://client-update.akamai.steamstatic.com/' + name
            request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity'})
            try:
                with urllib.request.urlopen(request, timeout=60) as response, temporary.open('xb') as out:
                    assert response.status == 200 and response.url == url
                    written = 0
                    while chunk := response.read(1024 * 1024):
                        written += len(chunk); assert written <= count
                        out.write(chunk)
                assert temporary.stat().st_size == count
                assert file_sha256(temporary) == digest
                assert not archive.exists()
                temporary.rename(archive)
            finally:
                temporary.unlink(missing_ok=True)
        assert archive.stat().st_size == count
        assert file_sha256(archive) == digest

runtime = (ROOT / 'app/Madeira/SteamRuntime.swift').read_text()
first = runtime.index('enum SteamRuntimeFiles {')
last = runtime.index('\n#if canImport(CryptoKit)', first)
files = 'import Foundation\nimport zlib\n' + runtime[first:last]
update = (ROOT / 'app/Madeira/SteamClientUpdate.swift').read_text().split('#if canImport(SwiftUI)', 1)[0]
main = r'''
import Foundation
import CryptoKit

let fm = FileManager.default
func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
func hashFile(_ file: URL) throws -> String { hash(try Data(contentsOf: file)) }
func fails(_ label: String, _ action: () throws -> Void) {
    do { try action(); fatalError("accepted: " + label) } catch {}
}
func pe(_ count: Int, machine: UInt16 = 0x8664, salt: UInt8 = 1) -> Data {
    precondition(count >= 512)
    var bytes = Data(repeating: salt, count: count)
    func put16(_ at: Int, _ value: UInt16) { bytes[at] = UInt8(value & 255); bytes[at + 1] = UInt8(value >> 8) }
    bytes[0] = 0x4d; bytes[1] = 0x5a
    bytes[0x3c] = 0x80; bytes[0x3d] = 0; bytes[0x3e] = 0; bytes[0x3f] = 0
    bytes[0x80] = 0x50; bytes[0x81] = 0x45; bytes[0x82] = 0; bytes[0x83] = 0
    put16(0x84, machine); put16(0x94, 240); put16(0x98, machine == 0x8664 ? 0x20b : 0x10b)
    return bytes
}
typealias F = SteamNativeBrowserLaunchFiles
typealias B = SteamBrowserRuntimeFiles
let temp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
try fm.createDirectory(at: temp, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: temp) }
let drive = temp.appendingPathComponent("drive_c", isDirectory: true)
let system = drive.appendingPathComponent("windows/system32", isDirectory: true)
let steam = drive.appendingPathComponent("Program Files (x86)/Steam", isDirectory: true)
for root in [system, steam] { try fm.createDirectory(at: root, withIntermediateDirectories: true) }
let privateNames = ["config/loginusers.vdf", "userdata/account/config/localconfig.vdf", "steamapps/appmanifest_730.acf", "steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe", "bin/cef/cef.win64/libcef.dll"]
for name in privateNames {
    let file = steam.appendingPathComponent(name)
    try fm.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data(("protected fixture:" + name).utf8).write(to: file)
}
let unrelated = system.appendingPathComponent("kernel32.dll")
try Data("unrelated-system32".utf8).write(to: unrelated)
let old = pe(51_200, salt: 1), next = pe(57_856, salt: 2), third = pe(60_928, salt: 3)
assert(old.count != next.count && next.count != third.count)
func manifest(_ bytes: Data, hashOverride: String? = nil) -> F.BridgeManifest {
    F.BridgeManifest(format: 1, mode: "native-owner", filename: F.bridgeName, bytes: bytes.count,
        sha256: hashOverride ?? hash(bytes), coreSHA256: B.official.coreSHA256,
        readinessABI: F.ReadinessABI(version: 1, size: 80, sha256: F.abiSHA256))
}
func bundle(_ label: String, _ bytes: Data) throws -> (URL, F.BridgeManifest) {
    let resources = temp.appendingPathComponent("resources-" + label, isDirectory: true)
    let binary = resources.appendingPathComponent("arm64ec-windows", isDirectory: true)
    try fm.createDirectory(at: binary, withIntermediateDirectories: true)
    let dll = binary.appendingPathComponent(F.bridgeName), metadata = binary.appendingPathComponent(F.manifestName)
    try bytes.write(to: dll)
    try JSONEncoder().encode(manifest(bytes)).write(to: metadata)
    return try F.bundle(resources, digest: hashFile)
}
let (oldSource, oldManifest) = try bundle("old", old)
let (nextSource, nextManifest) = try bundle("next", next)
let (thirdSource, thirdManifest) = try bundle("third", third)
let target = system.appendingPathComponent(F.bridgeName)
let stampFile = system.appendingPathComponent(F.stampName)
func stamp() throws -> F.Stamp { try JSONDecoder().decode(F.Stamp.self, from: Data(contentsOf: stampFile)) }
func writeStamp(_ installed: F.Fingerprint?, _ pending: F.Fingerprint?, owner: String = "org.madeira.NativeSteamBrowserBridge/v1") throws {
    try JSONEncoder().encode(F.Stamp(format: 1, owner: owner, filename: F.bridgeName, installed: installed, pending: pending)).write(to: stampFile, options: .atomic)
}
func physicalSize(_ file: URL) throws -> UInt64 {
    let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
    return try handle.seekToEnd()
}
func check(_ bytes: Data, _ expected: F.BridgeManifest) throws {
    assert(try physicalSize(target) == UInt64(bytes.count))
    assert(try Data(contentsOf: target) == bytes)
    let value = try stamp()
    assert(value.installed == expected.fingerprint && value.pending == nil)
    try F.verify(target, fingerprint: expected.fingerprint, digest: hashFile)
}
var reports: [String] = []
func report(_ value: String) { reports.append(value) }
fails("active first installation") { try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { false }) }
assert(!fm.fileExists(atPath: target.path) && !fm.fileExists(atPath: stampFile.path))
try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(old, oldManifest)
let reusedInode = try fm.attributesOfItem(atPath: target.path)[.systemFileNumber] as! NSNumber
try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
let afterReuseInode = try fm.attributesOfItem(atPath: target.path)[.systemFileNumber] as! NSNumber
assert(reusedInode == afterReuseInode)
try check(old, oldManifest)
print("PASS first install and verified reuse: full SHA256, physical size, AMD64 PE and ownership stamp")

// The baseline caches target.resourceValues(fileSizeKey) while recognizing the
// older bridge, then reads that same URL after atomic replacement. Same-size
// fixtures hide the defect. Real upgrade sizes must pass installed readback.
let beforeUpgrade = Set(try fm.contentsOfDirectory(atPath: system.path))
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
let afterUpgrade = Set(try fm.contentsOfDirectory(atPath: system.path))
let preservedOld = afterUpgrade.subtracting(beforeUpgrade).contains { name in
    let root = system.appendingPathComponent(name)
    if (try? Data(contentsOf: root)) == old { return true }
    guard let listing = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else { return false }
    for case let file as URL in listing {
        if file.lastPathComponent == F.bridgeName && (try? Data(contentsOf: file)) == old { return true }
    }
    return false
}
assert(preservedOld)
print("PASS unequal-size owned upgrade 51200->57856: atomic replacement readback sees actual new file, previous image retained")
try F.installBridge(thirdSource, manifest: thirdManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(third, thirdManifest)
try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(old, oldManifest)
print("PASS repeated differing-size upgrades and downgrade without accepting stale file metadata")

// Both legitimate sides of an interrupted pending transaction are recognized.
try writeStamp(oldManifest.fingerprint, nextManifest.fingerprint)
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
try writeStamp(oldManifest.fingerprint, nextManifest.fingerprint)
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
try fm.removeItem(at: target); try writeStamp(nil, nextManifest.fingerprint)
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
print("PASS interrupted pending recovery before/after copy and owned pending first-install with missing target")

// Inject exactly one readback checksum failure through the public digest hook.
// Every other digest is genuine CryptoKit, including rollback ownership checks.
try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true })
let beforeReadbackFailure = try Data(contentsOf: stampFile)
var injectedReadbackFailure = false
fails("failed installed readback restores verified old DLL and stamp") {
    try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: { file in
        let actual = try hashFile(file)
        if !injectedReadbackFailure && file.standardizedFileURL.path == target.standardizedFileURL.path && actual == nextManifest.sha256 {
            injectedReadbackFailure = true
            return String(repeating: "0", count: 64)
        }
        return actual
    }, idle: { true }, report: report)
}
assert(injectedReadbackFailure)
try check(old, oldManifest)
assert(try Data(contentsOf: stampFile) == beforeReadbackFailure)
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
print("PASS failed new-image readback rolls back verified previous DLL/stamp atomically and subsequent retry succeeds")

try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true })
var pendingWasWritten = false
fails("session becomes active after pending stamp but before image copy") {
    try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { !pendingWasWritten }, report: { line in
        report(line)
        if line.contains("phase=bridge-pending-transaction") && line.contains("result=written") { pendingWasWritten = true }
    })
}
assert(pendingWasWritten)
assert(try Data(contentsOf: target) == old)
let interruptedStamp = try stamp()
assert(interruptedStamp.installed == oldManifest.fingerprint && interruptedStamp.pending == nextManifest.fingerprint)
try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
try check(next, nextManifest)
print("PASS active-session transition after pending ownership never writes DLL and genuine pending retry recovers")


let targetBefore = try Data(contentsOf: target), stampBefore = try Data(contentsOf: stampFile)
let wrong = pe(57_856, machine: 0x014c, salt: 4)
let wrongSource = temp.appendingPathComponent("wrong-architecture.dll"); try wrong.write(to: wrongSource)
fails("I386 source with matching full hash") { try F.installBridge(wrongSource, manifest: manifest(wrong), drive: drive, digest: hashFile, idle: { true }) }
fails("source fingerprint mismatch") { try F.installBridge(nextSource, manifest: manifest(next, hashOverride: hash(old)), drive: drive, digest: hashFile, idle: { true }) }
assert(try Data(contentsOf: target) == targetBefore && Data(contentsOf: stampFile) == stampBefore)
try wrong.write(to: target); try writeStamp(manifest(wrong).fingerprint, nil)
fails("owned but wrong-architecture old target") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
assert(try Data(contentsOf: target) == wrong)
try next.write(to: target); try writeStamp(oldManifest.fingerprint, nil)
fails("unknown target despite valid ownership stamp") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
assert(try Data(contentsOf: target) == next)
try writeStamp(nextManifest.fingerprint, nil, owner: "not-Madeira")
fails("foreign stamp") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
try fm.removeItem(at: stampFile)
fails("unowned target") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
assert(try Data(contentsOf: target) == next && !fm.fileExists(atPath: stampFile.path))
try writeStamp(nextManifest.fingerprint, nil)
try fm.removeItem(at: target)
let auth = steam.appendingPathComponent(privateNames[0])
try fm.createSymbolicLink(at: target, withDestinationURL: auth)
fails("linked target") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
try fm.removeItem(at: target); try next.write(to: target)
try fm.removeItem(at: stampFile); try fm.createSymbolicLink(at: stampFile, withDestinationURL: auth)
fails("linked stamp") { try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }) }
try fm.removeItem(at: stampFile); try writeStamp(nextManifest.fingerprint, nil)
print("PASS strict source/old-target architecture, fingerprint, unknown/foreign/unowned and symlink rejection")

// The optional CI integration uses all three genuine archives and the actual
// cache transaction. The offline unit fixture covers canonical path acceptance.
let compat = try F.compatRoot(drive: drive, idle: { true })
let cache: B.Prepared
if CommandLine.arguments.count > 1 {
    let archives = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    let owner = try B.ownerRoot(cacheBase: compat, steamRoot: steam, idle: { true })
    let final = owner.appendingPathComponent(B.official.id, isDirectory: true)
    func freshOfficialStage(_ label: String) throws -> (URL, [B.FileRecord]) {
        let stage = owner.appendingPathComponent(".stage-" + label + "-" + UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: stage, withIntermediateDirectories: false)
        var records: [B.FileRecord] = []
        for package in B.official.packages {
            try B.appendArchive(Data(contentsOf: archives.appendingPathComponent(package.file), options: .mappedIfSafe),
                                package: package, recipe: B.official, stage: stage, records: &records, digest: hash, idle: { true })
        }
        assert(records.count == 79)
        return (stage, records)
    }
    let (firstStage, firstRecords) = try freshOfficialStage("first")
    let prepared = try B.commit(stage: firstStage, destination: final, recipe: B.official, records: firstRecords,
                               digest: hashFile, idle: { true }, recheckCore: {})
    let record = try JSONDecoder().decode(B.Manifest.self, from: Data(contentsOf: final.appendingPathComponent(B.completion)))
    assert(record.files.count == 80)
    try F.installBridge(oldSource, manifest: oldManifest, drive: drive, digest: hashFile, idle: { true })
    let runtime = prepared.browserRoot.appendingPathComponent("debug.log")
    try Data("runtime-output fixture; no credentials".utf8).write(to: runtime)
    var cacheReports: [String] = []
    assert(try B.reuse(final, recipe: B.official, digest: hashFile, idle: { true }, report: { cacheReports.append($0) }) == nil)
    assert(cacheReports.contains { $0.contains("reason=unexpected-file") && $0.contains("relative=" + B.official.prefix + "debug.log") })
    let (recoveryStage, recoveryRecords) = try freshOfficialStage("recovery")
    cache = try B.commit(stage: recoveryStage, destination: final, recipe: B.official, records: recoveryRecords,
                         digest: hashFile, idle: { true }, recheckCore: {})
    assert(try B.reuse(final, recipe: B.official, digest: hashFile, idle: { true }) != nil)
    assert(!fm.fileExists(atPath: cache.browserRoot.appendingPathComponent("debug.log").path))
    // Reproduce the actual device sequence: initial bundle verification succeeded,
    // the genuine cache rebuild succeeded, then an older owned DLL is upgraded.
    try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
    try check(next, nextManifest)
    print("PASS combined pre-Wine sequence: genuine 79-member/80-record cache rebuild after debug.log, unequal-size owned bridge upgrade/readback, canonical helper paths")
} else {
    let browser = compat.appendingPathComponent("SteamBrowserRuntime/" + B.official.id + "/bin/cef/cef.win7", isDirectory: true)
    try fm.createDirectory(at: browser, withIntermediateDirectories: true)
    let helper = browser.appendingPathComponent("steamwebhelper.exe")
    try pe(512, machine: 0x014c).write(to: helper)
    cache = B.Prepared(helper: helper, browserRoot: browser, coreSHA256: B.official.coreSHA256, recipe: B.official.id)
}
for _ in 0..<8 {
    try F.installBridge(nextSource, manifest: nextManifest, drive: drive, digest: hashFile, idle: { true }, report: report)
    try check(next, nextManifest)
    let ready = try F.prepared(cache, bridge: nextManifest.fingerprint, drive: drive)
    assert(ready.cacheDirectory == F.nativeCache && ready.helper == F.nativeCache + "\\steamwebhelper.exe")
}
for phase in ["bridge-source-recheck", "bridge-existing-stamp", "bridge-existing-target", "bridge-pending-transaction", "bridge-copy", "bridge-installed-readback"] {
    assert(reports.contains { $0.contains("phase=" + phase) })
}
for line in reports { assert(!line.contains(temp.path) && !line.contains("\n") && !line.contains("\r") && line.utf8.count < 2048) }
for name in privateNames { assert(try Data(contentsOf: steam.appendingPathComponent(name)) == Data(("protected fixture:" + name).utf8)) }
assert(try Data(contentsOf: unrelated) == Data("unrelated-system32".utf8))
print("PASS repeated bridge reuse/canonical cache-path acceptance and bounded diagnostics; Steam auth, CS2, original CEF and unrelated prefix files unchanged")
'''
# Foundation operations genuinely throw; force only test assertions' expressions.
main = main.replace('assert(try ', 'assert(try! ')
with tempfile.TemporaryDirectory(prefix='madeira-browser-bridge-') as directory:
    p = Path(directory)
    (p / 'Files.swift').write_text(files)
    (p / 'Update.swift').write_text(update)
    (p / 'Browser.swift').write_text((ROOT / 'app/Madeira/SteamBrowserRuntime.swift').read_text())
    (p / 'Native.swift').write_text((ROOT / 'app/Madeira/SteamNativeBrowserLaunch.swift').read_text())
    (p / 'main.swift').write_text(main)
    subprocess.run(['swiftc', '-swift-version', '5', str(p / 'Files.swift'), str(p / 'Update.swift'), str(p / 'Browser.swift'), str(p / 'Native.swift'), str(p / 'main.swift'), '-o', str(p / 'check')], check=True)
    subprocess.run([str(p / 'check')] + ([str(args.official_archives.resolve())] if args.official_archives else []), check=True, timeout=180)
