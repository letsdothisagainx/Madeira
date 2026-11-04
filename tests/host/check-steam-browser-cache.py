#!/usr/bin/env python3
"""Exercise the production Swift browser-cache functions; no Steam download or Wine run.

Without a Swift toolchain, fixture/source checks run and execution is explicitly
reported SKIP. CI should pass --require-swift so that absence fails the job.
Digest injection uses Python SHA-256 values for a closed set of test fixtures;
it does not replace production CryptoKit or claim to test its implementation.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
parser.add_argument('--app-activated', action='store_true', help='verify exact applied sources in an isolated candidate build checkout')
args = parser.parse_args()
runtime = (ROOT / 'app/Madeira/SteamRuntime.swift').read_text()
cache = (ROOT / 'app/Madeira/SteamBrowserRuntime.swift').read_text()
assert 'limits: ZIPLimits = .standard' in runtime
assert 'archive: 64 * 1024 * 1024, member: 64 * 1024 * 1024' in runtime
assert 'total: 256 * 1024 * 1024, records: 256, strict: false' in runtime
assert 'member: 256 * 1024 * 1024, total: 768 * 1024 * 1024, records: 256, strict: true' in runtime
assert cache.index('digest(archive) == package.sha256') < cache.index('limits: .trustedOfficialI386Browser')
assert 'URLSessionDataDelegate' in cache and 'data.count <= package.bytes - received' in cache
assert 'URLSession.download(' not in cache and 'session.data(from:' not in cache
assert 'completionHandler(nil)' in cache
assert 'response.expectedContentLength == Int64(package.bytes)' in cache
assert 'SteamOwnedLibrary.shared.wineSessionActive' in cache
assert 'moveItem(at: stage, to: final)' in cache
commit_start = cache.index('static func commit(stage:')
commit_source = cache[commit_start:cache.index('\n#if canImport(CryptoKit)', commit_start)]
assert commit_source.index('try validate(stage,') < commit_source.index('moveItem(at: stage, to: final)')
contract = (ROOT / 'build/htmlipc/runtime/cache-contract.txt').read_bytes()
assert len(contract) == 363
assert hashlib.sha256(contract).hexdigest() == 'fff4a23d727dd4f33ec070d29cb0012d7a22bf7f6f4e84e2cffc6709224e1781'
assert hashlib.sha256(contract).hexdigest() in cache
for line in contract.decode().splitlines(keepends=True):
    assert json.dumps(line) in cache
assert 'let generated: Bool' in cache
assert cache.index('try validateTree(stage, recipe: recipe, records: records, extraFiles: [], digest: digest)') < cache.index('try recipe.marker.bytes.write(')
assert cache.index('try recipe.marker.bytes.write(') < cache.index('try encoder.encode(value).write(')

def pe(kind):
    image = bytearray(512)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3c, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', image, 0x84, kind)
    struct.pack_into('<H', image, 0x94, 240)
    struct.pack_into('<H', image, 0x98, 0x10b if kind == 0x14c else 0x20b)
    return bytes(image)

prefix = 'bin/cef/cef.win7/'
payloads = {prefix + name: pe(0x14c) + name.encode() for name in ['steamwebhelper.exe', 'libcef.dll', 'chrome_elf.dll']}
payloads[prefix + 'resources.pak'] = b'official fixture resources'

def archive(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return out.getvalue()

good = archive(payloads.items())
traversal = archive([('../outside', b'bad')])
collision = archive([('name', b'a'), ('NAME', b'b')])
symlink = zipfile.ZipInfo('link'); symlink.create_system = 3; symlink.external_attr = (0o120777 << 16)
linked = archive([(symlink, b'../outside')])
crc_bad = bytearray(good)
first_body = 30 + struct.unpack_from('<H', good, 26)[0] + struct.unpack_from('<H', good, 28)[0]
crc_bad[first_body + 100] ^= 1
local_bad = bytearray(good); local_bad[30] ^= 1
local_crc_bad = bytearray(good); local_crc_bad[14] ^= 1
amd64_payloads = dict(payloads); amd64_payloads[prefix + 'steamwebhelper.exe'] = pe(0x8664)
wrong_arch = archive(amd64_payloads.items())

class Unseekable(io.BytesIO):
    def seekable(self): return False
    def seek(self, *args): raise OSError('unseekable fixture')

stream = Unseekable()
with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as z:
    z.writestr('descriptor.txt', b'descriptor body')
descriptor = stream.getvalue()
assert struct.unpack_from('<H', descriptor, 6)[0] & 8
descriptor_bad = bytearray(descriptor)
descriptor_bad[descriptor.index(b'PK\x07\x08') + 4] ^= 1
fixtures = {'good.zip': good, 'traversal.zip': traversal, 'collision.zip': collision, 'symlink.zip': linked,
            'crc.zip': bytes(crc_bad), 'local.zip': bytes(local_bad), 'local-crc.zip': bytes(local_crc_bad),
            'amd64.zip': wrong_arch, 'descriptor.zip': descriptor, 'descriptor-bad.zip': bytes(descriptor_bad),
            'core.dll': b'current real-core fixture'}
fixtures.update({f'payload-{i}': value for i, value in enumerate(payloads.values())})
fixtures['amd64.exe'] = pe(0x8664)
fixtures['cache-marker'] = b'MadeiraHtmlIPC-TEST-FIXTURE-NOT-PRODUCTION\n'
fixtures['marker-tampered'] = b'X' + fixtures['cache-marker'][1:]
fixtures['official-marker'] = contract
fixtures['spoof-marker.zip'] = archive([(prefix + '.madeira-cache-verified-v1', fixtures['cache-marker']), *payloads.items()])
fixtures['spoof-marker-case.zip'] = archive([(prefix + '.MADEIRA-CACHE-VERIFIED-V1', fixtures['cache-marker']), *payloads.items()])
fixtures['sdl-i386.dll'] = pe(0x14c) + b'exact-selected-SDL3-fixture'
fixtures['sdl-amd64.dll'] = pe(0x8664) + b'wrong-architecture-SDL3-fixture'
sdl_ignored = [('steamclient64.dll', pe(0x8664) + b'ignored-core-dll'),
               ('steam.exe', pe(0x8664) + b'ignored-client-launcher'),
               ('config/loginusers.vdf', b'ignored-auth-like-fixture-must-not-install'),
               ('userdata/account/localconfig.vdf', b'ignored-userdata-fixture-must-not-install')]
# SDL is first: malformed ignored entries later in the archive must still stop
# selection without writing the already decoded selected member or its record.
fixtures['sdl-core.zip'] = archive([('SDL3.dll', fixtures['sdl-i386.dll']), *sdl_ignored])
fixtures['sdl-core-amd64.zip'] = archive([('SDL3.dll', fixtures['sdl-amd64.dll']), *sdl_ignored])
fixtures['sdl-core-missing.zip'] = archive(sdl_ignored)
fixtures['sdl-core-case.zip'] = archive([('sdl3.dll', fixtures['sdl-i386.dll']), *sdl_ignored])
sdl_crc = bytearray(fixtures['sdl-core.zip'])
ignored_header = zipfile.ZipFile(io.BytesIO(sdl_crc)).getinfo('steamclient64.dll').header_offset
ignored_body = ignored_header + 30 + struct.unpack_from('<H', sdl_crc, ignored_header + 26)[0] + struct.unpack_from('<H', sdl_crc, ignored_header + 28)[0]
sdl_crc[ignored_body + 100] ^= 1
fixtures['sdl-core-ignored-crc.zip'] = bytes(sdl_crc)
sdl_local = bytearray(fixtures['sdl-core.zip']); sdl_local[ignored_header + 30] ^= 1
fixtures['sdl-core-ignored-local.zip'] = bytes(sdl_local)
fixtures['sdl-core-ignored-traversal.zip'] = archive([('SDL3.dll', fixtures['sdl-i386.dll']), ('../outside', b'ignored traversal')])
sdl_link = zipfile.ZipInfo('ignored-link'); sdl_link.create_system = 3; sdl_link.external_attr = (0o120777 << 16)
fixtures['sdl-core-ignored-symlink.zip'] = archive([('SDL3.dll', fixtures['sdl-i386.dll']), (sdl_link, b'../outside')])
fixtures['sdl-core-ignored-collision.zip'] = archive([('SDL3.dll', fixtures['sdl-i386.dll']), ('ignored.txt', b'a'), ('IGNORED.TXT', b'b')])
fixtures['sdl-cache-marker'] = b'MadeiraHtmlIPC-TEST-FIXTURE-4KEY-NOT-PRODUCTION\n' + b''.join(
    name.encode() + b' 014c ' + hashlib.sha256(value).hexdigest().encode() + b'\n'
    for name, value in [(name.removeprefix(prefix), value) for name, value in payloads.items() if name.endswith(('.exe', '.dll'))]
    + [('SDL3.dll', fixtures['sdl-i386.dll'])])
fixtures['dia-amd64.dll'] = pe(0x8664) + b'official mixed-architecture diagnostic fixture'
fixtures['dia-i386.dll'] = pe(0x14c) + b'incorrect diagnostic architecture'
fixtures['dia-mutated.dll'] = fixtures['dia-amd64.dll'] + b'tampered'
fixtures['mixed.zip'] = archive([*payloads.items(), (prefix + 'msdia140.dll', fixtures['dia-amd64.dll'])])
fixtures['mixed-i386.zip'] = archive([*payloads.items(), (prefix + 'msdia140.dll', fixtures['dia-i386.dll'])])
fixtures['mixed-mutated.zip'] = archive([*payloads.items(), (prefix + 'msdia140.dll', fixtures['dia-mutated.dll'])])
fixtures['mixed-case.zip'] = archive([*payloads.items(), (prefix + 'MSDIA140.dll', fixtures['dia-amd64.dll'])])
fixtures['mixed-other.zip'] = archive([*payloads.items(), (prefix + 'other.dll', fixtures['dia-amd64.dll'])])
digests = {value: hashlib.sha256(value).hexdigest() for value in fixtures.values()}
assert zipfile.ZipFile(io.BytesIO(good)).testzip() is None
assert zipfile.ZipFile(io.BytesIO(fixtures['sdl-core.zip'])).testzip() is None
assert zipfile.ZipFile(io.BytesIO(fixtures['sdl-core-ignored-crc.zip'])).testzip() == 'steamclient64.dll'
assert len(payloads) == 4 and len(set(n.lower() for n in payloads)) == 4
print('PASS production source and ZIP fixtures: preserved app defaults, pin-before-expanded-parser, bounded transfer, malicious fixture construction')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
    print('SKIP Swift execution: no toolchain; real parser/cache transaction harness is ready for CI --require-swift')
    raise SystemExit(0)

main = r'''
import Foundation
let fm = FileManager.default
let fixtures = URL(fileURLWithPath: CommandLine.arguments[1])
func fixture(_ name: String) throws -> Data { try Data(contentsOf: fixtures.appendingPathComponent(name)) }
let hashes: [String: String] = HASHES
func digest(_ bytes: Data) -> String { hashes[bytes.base64EncodedString()] ?? "unknown-mutation" }
func digestFile(_ file: URL) throws -> String { digest(try Data(contentsOf: file)) }
func checkpoint(_ label: String) {
    FileHandle.standardError.write(Data(("[browser-cache-test] " + label + "\n").utf8))
}
func checked<T>(_ label: String, _ body: () throws -> T) throws -> T {
    checkpoint("begin " + label)
    do { let value = try body(); checkpoint("pass " + label); return value }
    catch { checkpoint("FAIL " + label + " error=" + String(describing: error)); throw error }
}
func fails(_ label: String, _ block: () throws -> Void) {
    do { try block(); fatalError("accepted: " + label) } catch {}
}
func predicate(_ reason: SteamBrowserRuntimeFiles.Reason, name: String, _ block: () throws -> Void) {
    do { try block(); fatalError("accepted predicate: " + reason.rawValue) }
    catch let issue as SteamBrowserRuntimeFiles.ValidationIssue {
        assert(issue.reason == reason && issue.name == name)
    } catch { fatalError("wrong failure type for " + reason.rawValue) }
}
let temp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
try fm.createDirectory(at: temp, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: temp) }
let base = temp.appendingPathComponent("ApplicationSupport"), steam = temp.appendingPathComponent("Steam")
try fm.createDirectory(at: base, withIntermediateDirectories: true)
try fm.createDirectory(at: steam, withIntermediateDirectories: true)
let privateNames = ["config/loginusers.vdf", "userdata/account/config/localconfig.vdf", "steamapps/appmanifest_730.acf", "steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe", "bin/cef/cef.win64/libcef.dll"]
for name in privateNames {
    let url = steam.appendingPathComponent(name)
    try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data(name.utf8).write(to: url)
}
let core = steam.appendingPathComponent("bin/chromehtml.dll")
try fixture("core.dll").write(to: core)
typealias F = SteamBrowserRuntimeFiles
assert(F.official.expectedFiles == 79 && F.officialMarker.bytes.count == 363)
assert(F.officialMarker.sha256 == digest(F.officialMarker.bytes))
let package = F.Package(file: "fixture.zip", bytes: try fixture("good.zip").count, sha256: digest(try fixture("good.zip")))
let names = ["steamwebhelper.exe", "libcef.dll", "chrome_elf.dll"]
let keys = try names.enumerated().map { F.Key(name: $0.element, sha256: digest(try fixture("payload-\($0.offset)"))) }
let generated = F.GeneratedFile(name: ".madeira-cache-verified-v1", bytes: try fixture("cache-marker"), sha256: digest(try fixture("cache-marker")))
let recipe = F.Recipe(id: "fixture-v1", coreSHA256: digest(try fixture("core.dll")), prefix: "bin/cef/cef.win7/", expectedFiles: 4, packages: [package], keys: keys, marker: generated)
for spoof in ["spoof-marker.zip", "spoof-marker-case.zip"] {
    let bytes = try fixture(spoof)
    let spoofPackage = F.Package(file: spoof, bytes: bytes.count, sha256: digest(bytes))
    let spoofRecipe = F.Recipe(id: recipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix, expectedFiles: 4, packages: [spoofPackage], keys: recipe.keys, marker: generated)
    var spoofRecords: [F.FileRecord] = []
    fails("archive cannot supply generated marker") { try F.appendArchive(bytes, package: spoofPackage, recipe: spoofRecipe, stage: base, records: &spoofRecords, digest: digest, idle: { true }) }
    assert(spoofRecords.isEmpty)
}
try checked("current-core") { try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile) }
fails("core outside Steam") { try F.core(core, steamRoot: base, recipe: recipe, digest: digestFile) }
fails("active owner acquisition") { _ = try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { false }) }
let alien = base.appendingPathComponent("SteamBrowserRuntime")
try fm.createDirectory(at: alien, withIntermediateDirectories: false)
try Data("keep".utf8).write(to: alien.appendingPathComponent("existing"))
fails("unowned existing cache") { _ = try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { true }) }
assert(try! Data(contentsOf: alien.appendingPathComponent("existing")) == Data("keep".utf8))
try fm.removeItem(at: alien)
let owner = try checked("fresh-owner-root") { try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { true }) }
assert(try! F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { true }) == owner)
let interrupted = owner.appendingPathComponent(".stage-interrupted")
try fm.createDirectory(at: interrupted, withIntermediateDirectories: false)
try Data("keep".utf8).write(to: interrupted.appendingPathComponent("partial"))
func newStage(_ suffix: String) throws -> URL {
    let stage = owner.appendingPathComponent(".stage-" + suffix)
    try fm.createDirectory(at: stage, withIntermediateDirectories: false)
    return stage
}
let stage = try newStage("complete")
var records: [F.FileRecord] = []
fails("active extraction") { try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { false }) }
assert(records.isEmpty && (try! fm.contentsOfDirectory(atPath: stage.path)).isEmpty)
fails("unverified archive") { try F.appendArchive(try fixture("crc.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { true }) }
assert(records.isEmpty)
try checked("verified-archive-extraction") {
    try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { true })
}
assert(records.count == 4)
assert(!fm.fileExists(atPath: stage.appendingPathComponent(recipe.prefix + generated.name).path))
let falseOfficialRecipe = F.Recipe(id: recipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix, expectedFiles: 4, packages: [package], keys: recipe.keys, marker: F.officialMarker)
fails("fixture recipe cannot emit real production contract") { _ = try F.commit(stage: stage, destination: owner.appendingPathComponent(recipe.id), recipe: falseOfficialRecipe, records: records, digest: digestFile, idle: { true }, recheckCore: {}) }
assert(!fm.fileExists(atPath: stage.appendingPathComponent(recipe.prefix + generated.name).path))
fails("duplicate archive members") { try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { true }) }
fails("wrong final ownership") { _ = try F.commit(stage: stage, destination: base.appendingPathComponent(recipe.id), recipe: recipe, records: records, digest: digestFile, idle: { true }, recheckCore: {}) }
let final = owner.appendingPathComponent(recipe.id)
fails("active atomic completion") { _ = try F.commit(stage: stage, destination: final, recipe: recipe, records: records, digest: digestFile, idle: { false }, recheckCore: {}) }
try checked("official-record-metadata") { try F.checkOfficialRecords(recipe: recipe, records: records) }
checkpoint("stage directory-hint=" + String(stage.hasDirectoryPath) + " path-final-slash=" + String(stage.path.hasSuffix("/")))
for item in records.prefix(8) {
    let file = stage.appendingPathComponent(item.name)
    let sizeOK = (try file.resourceValues(forKeys: [.fileSizeKey])).fileSize == item.bytes
    let hashOK = try digestFile(file) == item.sha256
    let machine = F.executable(item.name) ? F.machine(try Data(contentsOf: file)) : nil
    checkpoint("fixture-record " + item.name + " size=" + String(sizeOK) + " hash=" + String(hashOK) + " machine=" + String(describing: machine))
}
let hintedStage = URL(fileURLWithPath: stage.path, isDirectory: true)
for hinted in [false, true] {
    let bin = URL(fileURLWithPath: stage.appendingPathComponent("bin").path, isDirectory: hinted)
    assert(try! F.relativePath(bin, under: stage, directory: true) == "bin")
    assert(try! F.relativePath(bin, under: hintedStage, directory: true) == "bin")
}
// The OS /var alias and its /private/var canonical path name the same cache.
// A sibling symlink models that Foundation enumerator spelling without making
// a symlink part of the component tree accepted by plain()/validateTree().
let systemAlias = temp.appendingPathComponent("system-container-alias", isDirectory: true)
try fm.createSymbolicLink(at: systemAlias, withDestinationURL: base)
let aliasedStage = systemAlias.appendingPathComponent("SteamBrowserRuntime/" + stage.lastPathComponent, isDirectory: true)
assert(try! F.relativePath(aliasedStage.appendingPathComponent("bin", isDirectory: true), under: stage, directory: true) == "bin")
assert(try! F.relativePath(stage.appendingPathComponent(recipe.prefix + "resources.pak"), under: aliasedStage, directory: false) == recipe.prefix + "resources.pak")
fails("directory relative path outside cache") { _ = try F.relativePath(base, under: stage, directory: true) }
fails("directory relative path root itself") { _ = try F.relativePath(stage, under: stage, directory: true) }
if let listing = fm.enumerator(at: stage, includingPropertiesForKeys: [.isDirectoryKey], options: []) {
    var logged = 0
    for case let entry as URL in listing {
        guard logged < 16 else { break }; logged += 1
        let kind = (try entry.resourceValues(forKeys: [.isDirectoryKey])).isDirectory == true ? "directory" : "file"
        let relative = String(entry.path.dropFirst(stage.path.count + 1))
        checkpoint("fixture-tree " + kind + " relative=" + String(reflecting: relative))
    }
}
try checked("exact-official-stage-tree") { try F.validateTree(stage, recipe: recipe, records: records, extraFiles: [], digest: digestFile) }
_ = try checked("prospective-completion-manifest") { try F.manifest(recipe: recipe, records: records + [F.generatedRecord(recipe: recipe)]) }
var commitIdleChecks = 0, commitCoreChecks = 0
let prepared = try checked("complete-cache-transaction") {
    try F.commit(stage: stage, destination: final, recipe: recipe, records: records, digest: digestFile, idle: {
        commitIdleChecks += 1; checkpoint("commit idle-check " + String(commitIdleChecks)); return true
    }) {
        commitCoreChecks += 1; checkpoint("commit core-check " + String(commitCoreChecks))
        try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile)
    }
}
assert(prepared.helper.lastPathComponent == "steamwebhelper.exe")
assert(!fm.fileExists(atPath: stage.path))
_ = try checked("reuse-completed-cache") { try F.validate(final, recipe: recipe, digest: digestFile) }
let verifiedMarker = final.appendingPathComponent(recipe.prefix + generated.name)
assert(try! Data(contentsOf: verifiedMarker) == fixture("cache-marker"))
let initialManifestBytes = try Data(contentsOf: final.appendingPathComponent(F.completion))
let initialManifest = try JSONDecoder().decode(F.Manifest.self, from: initialManifestBytes)
assert(initialManifest.files.count == 5 && initialManifest.files.filter(\.generated).count == 1)
assert(initialManifest.files.filter { !$0.generated }.count == 4)
try fm.removeItem(at: verifiedMarker)
fails("missing generated marker") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try fixture("marker-tampered").write(to: verifiedMarker)
fails("same-length generated marker corruption") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
let alteredMarkerRecords = initialManifest.files.map {
    $0.generated ? F.FileRecord(name: $0.name, bytes: $0.bytes, sha256: digest(try! fixture("marker-tampered")), generated: true) : $0
}
let alteredManifest = F.Manifest(format: 1, recipe: recipe.id, coreSHA256: recipe.coreSHA256, packages: recipe.packages, files: alteredMarkerRecords)
try JSONEncoder().encode(alteredManifest).write(to: final.appendingPathComponent(F.completion))
fails("edited manifest cannot bless marker tampering") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try initialManifestBytes.write(to: final.appendingPathComponent(F.completion))
try generated.bytes.write(to: verifiedMarker)
fails("second generated record") { _ = try F.manifest(recipe: recipe, records: initialManifest.files + [F.generatedRecord(recipe: recipe)]) }
assert(try! Data(contentsOf: interrupted.appendingPathComponent("partial")) == Data("keep".utf8))
let resource = final.appendingPathComponent(recipe.prefix + "resources.pak")
let originalResource = try Data(contentsOf: resource)
try fm.removeItem(at: resource)
fails("marker cannot bless partial official tree") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try originalResource.write(to: resource)
try Data(repeating: 0, count: originalResource.count).write(to: resource)
fails("cache member hash changed") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try originalResource.write(to: resource)
let extra = final.appendingPathComponent("unexpected")
try Data().write(to: extra)
fails("unexpected file") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try fm.removeItem(at: extra)
try fm.removeItem(at: resource); try fm.createSymbolicLink(at: resource, withDestinationURL: core)
fails("linked member") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try fm.removeItem(at: resource); try originalResource.write(to: resource)
let completion = final.appendingPathComponent(F.completion), completed = try Data(contentsOf: completion)
try fm.removeItem(at: completion)
fails("incomplete cache cannot be reused") { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
try completed.write(to: completion)

// Exercise the actual reuse and commit methods, including verified recovery.
// No malformed cache is adopted, cleaned in place, or allowed to overwrite the
// old cache before the replacement has passed all production predicates.
func treeSnapshot(_ root: URL) throws -> [String: Data] {
    var result: [String: Data] = [:]
    guard let listing = fm.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else {
        fatalError("snapshot enumeration failed")
    }
    for case let file as URL in listing {
        let values = try file.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        assert(values.isSymbolicLink != true)
        if values.isDirectory != true {
            result[try F.relativePath(file, under: root, directory: false)] = try Data(contentsOf: file)
        }
    }
    return result
}
func retainedEntries() throws -> Set<String> {
    Set(try fm.contentsOfDirectory(atPath: owner.path).filter { $0.hasPrefix(".retained-") })
}
func freshRecoveryStage(_ label: String) throws -> (URL, [F.FileRecord]) {
    let stage = try newStage("repair-" + label + "-" + UUID().uuidString)
    var records: [F.FileRecord] = []
    try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage,
                        records: &records, digest: digest, idle: { true })
    return (stage, records)
}
func recovery(_ label: String, reason: F.Reason, name: String, _ mutate: () throws -> Void) throws {
    try mutate()
    let old = try treeSnapshot(final), retainedBefore = try retainedEntries()
    predicate(reason, name: name) { _ = try F.validate(final, recipe: recipe, digest: digestFile) }
    var reports: [String] = []
    let cached = try F.reuse(final, recipe: recipe, digest: digestFile, idle: { true }, report: { reports.append($0) })
    assert(cached == nil && !reports.isEmpty)
    assert(reports.count == 1 && reports[0].contains("phase=reuse") && reports[0].contains("reason=" + reason.rawValue))
    assert(reports[0].contains("recipe=" + recipe.id) && reports[0].contains("records-expected=5"))
    assert(reports[0].contains("relative=" + name))
    assert(try! treeSnapshot(final) == old && retainedEntries() == retainedBefore)
    for report in reports {
        assert(!report.contains(temp.path) && !report.contains(steam.path))
        assert(!report.contains("\n") && !report.contains("\r"))
    }
    let (replacement, replacementRecords) = try freshRecoveryStage(label)
    _ = try F.commit(stage: replacement, destination: final, recipe: recipe, records: replacementRecords,
                     digest: digestFile, idle: { true }, recheckCore: {
        try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile)
    })
    let retainedAfter = try retainedEntries(), added = retainedAfter.subtracting(retainedBefore)
    assert(added.count == 1)
    assert(try! treeSnapshot(owner.appendingPathComponent(added.first!)) == old)
    assert(!fm.fileExists(atPath: replacement.path))
    reports.removeAll()
    assert(try! F.reuse(final, recipe: recipe, digest: digestFile, idle: { true }, report: { reports.append($0) }) != nil)
    _ = try F.validate(final, recipe: recipe, digest: digestFile)
    assert(reports.isEmpty)
    for name in privateNames { assert(try! Data(contentsOf: steam.appendingPathComponent(name)) == Data(name.utf8)) }
    checkpoint("recovered-and-reused " + label)
}
try recovery("runtime-extra-file", reason: .unexpectedFile, name: recipe.prefix + "debug.log") {
    try Data("real runtime output fixture".utf8).write(to: final.appendingPathComponent(recipe.prefix + "debug.log"))
}
try recovery("runtime-extra-directory", reason: .unexpectedDirectory, name: recipe.prefix + "Crashpad") {
    try fm.createDirectory(at: final.appendingPathComponent(recipe.prefix + "Crashpad", isDirectory: true), withIntermediateDirectories: false)
}
try recovery("modified-browser-dll", reason: .fileHash, name: recipe.prefix + "chrome_elf.dll") {
    let target = final.appendingPathComponent(recipe.prefix + "chrome_elf.dll")
    var bytes = try Data(contentsOf: target); bytes[bytes.count - 1] ^= 1
    try bytes.write(to: target)
}
try recovery("wrong-browser-architecture", reason: .architecture, name: recipe.prefix + "steamwebhelper.exe") {
    let target = final.appendingPathComponent(recipe.prefix + "steamwebhelper.exe")
    var bytes = try Data(contentsOf: target)
    bytes[0x84] = 0x64; bytes[0x85] = 0x86; bytes[0x98] = 0x0b; bytes[0x99] = 0x02
    try bytes.write(to: target)
}
try recovery("missing-official-member", reason: .missingFile, name: recipe.prefix + "resources.pak") { try fm.removeItem(at: resource) }
try recovery("missing-generated-marker", reason: .missingFile, name: recipe.prefix + generated.name) { try fm.removeItem(at: verifiedMarker) }
try recovery("changed-generated-marker", reason: .fileHash, name: recipe.prefix + generated.name) { try fixture("marker-tampered").write(to: verifiedMarker) }
try recovery("corrupt-completion-json", reason: .completionMalformed, name: F.completion) { try Data("{not valid JSON".utf8).write(to: completion) }
try recovery("missing-completion-after-interruption", reason: .missingFile, name: F.completion) { try fm.removeItem(at: completion) }
// A JSON object of the correct shape still cannot change package or recipe pins.
try recovery("changed-completion-recipe", reason: .completionMismatch, name: F.completion) {
    let original = try JSONDecoder().decode(F.Manifest.self, from: Data(contentsOf: completion))
    let changed = F.Manifest(format: original.format, recipe: "foreign-recipe", coreSHA256: original.coreSHA256,
                             packages: original.packages, files: original.files)
    try JSONEncoder().encode(changed).write(to: completion)
}
for untrustedName in ["../outside", "config/password-token.txt", String(repeating: "a", count: 80)] {
    let report = F.ValidationIssue(.unexpectedFile, untrustedName).diagnostic(phase: "reuse", recipe: recipe)
    assert(!report.contains(untrustedName) && !report.contains("\n") && report.utf8.count < 1024)
}
try Data("retained invalid cache".utf8).write(to: resource)
let beforeFailedRepair = try treeSnapshot(final), retainedBeforeFailedRepair = try retainedEntries()
fails("active cache recovery") {
    _ = try F.reuse(final, recipe: recipe, digest: digestFile, idle: { false }, report: { _ in })
}
let (rollbackStage, rollbackRecords) = try freshRecoveryStage("owner-became-active-before-publish")
var retainedForRollback = false
fails("failed publication restores old cache name and content") {
    _ = try F.commit(stage: rollbackStage, destination: final, recipe: recipe, records: rollbackRecords,
                     digest: digestFile, idle: { !retainedForRollback }, report: {
        if $0.contains("phase=retain") { retainedForRollback = true }
    }, recheckCore: {})
}
assert(retainedForRollback)
assert(try! treeSnapshot(final) == beforeFailedRepair && retainedEntries() == retainedBeforeFailedRepair)
let (invalidReplacement, invalidReplacementRecords) = try freshRecoveryStage("must-not-retire-before-verification")
try fm.removeItem(at: invalidReplacement.appendingPathComponent(recipe.prefix + "resources.pak"))
fails("invalid replacement never retires existing cache") {
    _ = try F.commit(stage: invalidReplacement, destination: final, recipe: recipe, records: invalidReplacementRecords,
                     digest: digestFile, idle: { true }, recheckCore: {})
}
assert(try! treeSnapshot(final) == beforeFailedRepair && retainedEntries() == retainedBeforeFailedRepair)
try originalResource.write(to: resource)
_ = try F.validate(final, recipe: recipe, digest: digestFile)
let linkedRuntime = final.appendingPathComponent(recipe.prefix + "unowned-linked-output")
try fm.createSymbolicLink(at: linkedRuntime, withDestinationURL: core)
let retainedBeforeLinked = try retainedEntries()
fails("linked cache remains ownership failure rather than auto-recovery") {
    _ = try F.reuse(final, recipe: recipe, digest: digestFile, idle: { true }, report: { _ in })
}
assert(fm.fileExists(atPath: linkedRuntime.path) && (try! retainedEntries()) == retainedBeforeLinked)
try fm.removeItem(at: linkedRuntime)
_ = try F.validate(final, recipe: recipe, digest: digestFile)
assert(try! Data(contentsOf: interrupted.appendingPathComponent("partial")) == Data("keep".utf8))
print("PASS production cache recovery/reuse: runtime extras, altered DLL, missing member/marker, malformed/changed/missing completion; old tree retained byte-for-byte only after verified replacement, failed/active/linked recovery refused and Steam/CS2/auth fixtures unchanged")
var incomplete = records; incomplete.removeLast()
fails("incomplete manifest") { _ = try F.manifest(recipe: recipe, records: incomplete) }
let partialStage = try newStage("partial-tree")
var partialRecords: [F.FileRecord] = []
try checked("partial-stage-extraction") {
    try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: partialStage, records: &partialRecords, digest: digest, idle: { true })
}
try fm.removeItem(at: partialStage.appendingPathComponent(recipe.prefix + "resources.pak"))
fails("no generated marker for partial stage") { _ = try F.commit(stage: partialStage, destination: owner.appendingPathComponent(recipe.id), recipe: recipe, records: partialRecords, digest: digestFile, idle: { true }, recheckCore: {}) }
assert(!fm.fileExists(atPath: partialStage.appendingPathComponent(recipe.prefix + generated.name).path))
let interruptedMarkerStage = try newStage("interrupted-after-marker")
try fm.createDirectory(at: interruptedMarkerStage.appendingPathComponent(recipe.prefix), withIntermediateDirectories: true)
try generated.bytes.write(to: interruptedMarkerStage.appendingPathComponent(recipe.prefix + generated.name))
fails("marker without completion is never a ready cache") { _ = try F.validate(interruptedMarkerStage, recipe: recipe, digest: digestFile) }
assert(fm.fileExists(atPath: interruptedMarkerStage.appendingPathComponent(recipe.prefix + generated.name).path))
let wrongStage = try newStage("wrong-architecture")
let wrongBytes = try fixture("amd64.zip")
let wrongPackage = F.Package(file: "amd64.zip", bytes: wrongBytes.count, sha256: digest(wrongBytes))
let wrongRecipe = F.Recipe(id: recipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix, expectedFiles: 4, packages: [wrongPackage], keys: recipe.keys, marker: generated)
var wrongRecords: [F.FileRecord] = []
fails("AMD64 in i386 browser tree") { try F.appendArchive(wrongBytes, package: wrongPackage, recipe: wrongRecipe, stage: wrongStage, records: &wrongRecords, digest: digest, idle: { true }) }
let amd64 = try fixture("amd64.exe")
assert(F.machine(amd64) == 0x8664)
for n in 0..<392 { assert(F.machine(Data(amd64.prefix(n))) == nil) }
for name in ["traversal.zip", "collision.zip", "symlink.zip", "crc.zip", "local.zip", "local-crc.zip", "descriptor-bad.zip"] {
    fails(name) { try SteamRuntimeFiles.unpack(try fixture(name), limits: .trustedOfficialI386Browser) { _, _ in } }
}
var descriptorCount = 0
try checked("valid-data-descriptor") {
    try SteamRuntimeFiles.unpack(try fixture("descriptor.zip"), limits: .trustedOfficialI386Browser) { _, _ in descriptorCount += 1 }
}
assert(descriptorCount == 1)
// The default behavior stays unchanged; the stricter local-CRC check belongs
// to the authenticated-browser budget only.
try checked("unchanged-default-local-crc-behavior") { try SteamRuntimeFiles.unpack(try fixture("local-crc.zip")) { _, _ in } }
// A second fixture recipe adds one exact root DLL from a verified core ZIP.
// Its marker is explicitly a TEST contract with four local fixture key hashes.
// The completed earlier recipe is retained byte-for-byte throughout v2 staging.
let priorCompletion = try Data(contentsOf: final.appendingPathComponent(F.completion))
let priorFiles = try initialManifest.files.map { ($0.name, try Data(contentsOf: final.appendingPathComponent($0.name))) }
let sdlImage = try fixture("sdl-i386.dll")
let sdlKey = F.Key(name: "SDL3.dll", sha256: digest(sdlImage), bytes: sdlImage.count)
let sdlMarker = F.GeneratedFile(name: generated.name, bytes: try fixture("sdl-cache-marker"), sha256: digest(try fixture("sdl-cache-marker")))
let sdlArchive = try fixture("sdl-core.zip")
let sdlPackage = F.Package(file: "sdl-core.zip", bytes: sdlArchive.count, sha256: digest(sdlArchive), singleMember: "SDL3.dll")
let sdlRecipe = F.Recipe(id: "fixture-v2-with-sdl", coreSHA256: recipe.coreSHA256, prefix: recipe.prefix,
    expectedFiles: 5, packages: [package, sdlPackage], keys: keys + [sdlKey], marker: sdlMarker)
let sdlStage = try newStage("sdl-complete")
var sdlRecords: [F.FileRecord] = []
try checked("sdl-base-cef-extraction") {
    try F.appendArchive(try fixture("good.zip"), package: package, recipe: sdlRecipe, stage: sdlStage,
                        records: &sdlRecords, digest: digest, idle: { true })
}
assert(sdlRecords.count == 4)
assert(!fm.fileExists(atPath: sdlStage.appendingPathComponent(recipe.prefix + "SDL3.dll").path))
try checked("sdl-exact-member-extraction") {
    try F.appendArchive(sdlArchive, package: sdlPackage, recipe: sdlRecipe, stage: sdlStage,
                        records: &sdlRecords, digest: digest, idle: { true })
}
assert(sdlRecords.count == 5 && sdlRecords.filter { $0.name == recipe.prefix + "SDL3.dll" }.count == 1)
assert(try! Data(contentsOf: sdlStage.appendingPathComponent(recipe.prefix + "SDL3.dll")) == sdlImage)
assert(!fm.fileExists(atPath: sdlStage.appendingPathComponent("SDL3.dll").path))
assert(!fm.fileExists(atPath: sdlStage.appendingPathComponent(recipe.prefix + sdlMarker.name).path))
for ignored in ["steamclient64.dll", "steam.exe", "config/loginusers.vdf", "userdata/account/localconfig.vdf"] {
    assert(!fm.fileExists(atPath: sdlStage.appendingPathComponent(ignored).path))
    assert(!fm.fileExists(atPath: sdlStage.appendingPathComponent(recipe.prefix + ignored).path))
}
let sdlFinal = owner.appendingPathComponent(sdlRecipe.id)
_ = try checked("sdl-completed-cache") {
    try F.commit(stage: sdlStage, destination: sdlFinal, recipe: sdlRecipe, records: sdlRecords,
                 digest: digestFile, idle: { true }) {
        try F.core(core, steamRoot: steam, recipe: sdlRecipe, digest: digestFile)
    }
}
_ = try checked("sdl-completed-cache-reuse") { try F.validate(sdlFinal, recipe: sdlRecipe, digest: digestFile) }
let sdlManifest = try JSONDecoder().decode(F.Manifest.self, from: Data(contentsOf: sdlFinal.appendingPathComponent(F.completion)))
assert(sdlManifest.files.count == 6 && sdlManifest.files.filter(\.generated).count == 1)
assert(sdlManifest.files.filter { !$0.generated }.count == 5)
assert(sdlManifest.files.contains { $0.name == recipe.prefix + "SDL3.dll" && !$0.generated && $0.sha256 == sdlKey.sha256 && $0.bytes == sdlImage.count })
assert(try! Data(contentsOf: sdlFinal.appendingPathComponent(recipe.prefix + sdlMarker.name)) == sdlMarker.bytes)
for archiveName in ["sdl-core-amd64.zip", "sdl-core-missing.zip", "sdl-core-case.zip", "sdl-core-ignored-crc.zip",
                    "sdl-core-ignored-local.zip", "sdl-core-ignored-traversal.zip", "sdl-core-ignored-symlink.zip", "sdl-core-ignored-collision.zip"] {
    let candidate = try fixture(archiveName)
    let selectedPackage = F.Package(file: archiveName, bytes: candidate.count, sha256: digest(candidate), singleMember: "SDL3.dll")
    let selectedRecipe = F.Recipe(id: sdlRecipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix,
        expectedFiles: 5, packages: [package, selectedPackage], keys: keys + [sdlKey], marker: sdlMarker)
    let selectedStage = try newStage(archiveName)
    var selectedRecords: [F.FileRecord] = []
    try F.appendArchive(try fixture("good.zip"), package: package, recipe: selectedRecipe, stage: selectedStage,
                        records: &selectedRecords, digest: digest, idle: { true })
    let before = selectedRecords
    fails("exact SDL selection refuses " + archiveName) {
        try F.appendArchive(candidate, package: selectedPackage, recipe: selectedRecipe, stage: selectedStage,
                            records: &selectedRecords, digest: digest, idle: { true })
    }
    // Invalid ignored entries occur after valid SDL in the fixture. Neither
    // selected bytes nor a record may commit until the whole ZIP is validated.
    assert(selectedRecords == before)
    assert(!fm.fileExists(atPath: selectedStage.appendingPathComponent(recipe.prefix + "SDL3.dll").path))
    assert(!fm.fileExists(atPath: selectedStage.appendingPathComponent(recipe.prefix + sdlMarker.name).path))
    try F.validateTree(selectedStage, recipe: selectedRecipe, records: before, extraFiles: [], digest: digestFile)
}
let sdlWrongHashStage = try newStage("sdl-wrong-key-hash")
let sdlWrongHashRecipe = F.Recipe(id: sdlRecipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix,
    expectedFiles: 5, packages: [package, sdlPackage], keys: keys + [F.Key(name: "SDL3.dll", sha256: digest(try fixture("sdl-amd64.dll")))], marker: sdlMarker)
var sdlWrongHashRecords: [F.FileRecord] = []
try F.appendArchive(try fixture("good.zip"), package: package, recipe: sdlWrongHashRecipe, stage: sdlWrongHashStage,
                    records: &sdlWrongHashRecords, digest: digest, idle: { true })
let beforeWrongHash = sdlWrongHashRecords
fails("selected SDL exact full SHA is required") {
    try F.appendArchive(sdlArchive, package: sdlPackage, recipe: sdlWrongHashRecipe, stage: sdlWrongHashStage,
                        records: &sdlWrongHashRecords, digest: digest, idle: { true })
}
assert(sdlWrongHashRecords == beforeWrongHash)
assert(!fm.fileExists(atPath: sdlWrongHashStage.appendingPathComponent(recipe.prefix + "SDL3.dll").path))
assert(!fm.fileExists(atPath: sdlWrongHashStage.appendingPathComponent(recipe.prefix + sdlMarker.name).path))
assert(try! Data(contentsOf: final.appendingPathComponent(F.completion)) == priorCompletion)
for (name, bytes) in priorFiles { assert(try! Data(contentsOf: final.appendingPathComponent(name)) == bytes) }
print("PASS exact SDL selection: one I386/key-pinned member from core ZIP, ignored core/auth-like members validated but never installed; missing/case/wrong-architecture/hash and ignored CRC/header/traversal/symlink/collision failures leave selected records/files untouched; six-entry fixture completion retains prior cache")
for name in privateNames { assert(try! Data(contentsOf: steam.appendingPathComponent(name)) == Data(name.utf8)) }
assert(try! Data(contentsOf: core) == fixture("core.dll"))
print("PASS real candidate Swift functions: generated-marker absence/tamper/edited-manifest/partial-tree/interruption refusal, manifest/full-tree validation, idle rechecks, ownership, archive pins, traversal/case/symlink/CRC/local-header/descriptor rejection, i386 PE requirement; Steam authentication, CS2 and official cef.win64 fixtures unchanged")

let diaKey = F.Key(name: "msdia140.dll", sha256: digest(try fixture("dia-amd64.dll")),
                   bytes: try fixture("dia-amd64.dll").count, machine: 0x8664)
assert(F.expectedMachine(F.official.prefix + "msdia140.dll", recipe: F.official) == 0x8664)
for name in ["MSDIA140.dll", "other.dll", "steamwebhelper.exe", "libcef.dll", "chrome_elf.dll", "SDL3.dll"] {
    assert(F.expectedMachine(F.official.prefix + name, recipe: F.official) == 0x014c)
}
func mixedRecipe(_ archive: String, keys: [F.Key]) throws -> F.Recipe {
    let bytes = try fixture(archive)
    return F.Recipe(id: "fixture-mixed-v1", coreSHA256: recipe.coreSHA256, prefix: recipe.prefix,
        expectedFiles: 5, packages: [F.Package(file: archive, bytes: bytes.count, sha256: digest(bytes))],
        keys: keys, marker: generated)
}
let mixed = try mixedRecipe("mixed.zip", keys: recipe.keys + [diaKey])
let mixedStage = try newStage("mixed")
var mixedRecords: [F.FileRecord] = []
try F.appendArchive(try fixture("mixed.zip"), package: mixed.packages[0], recipe: mixed,
                    stage: mixedStage, records: &mixedRecords, digest: digest, idle: { true })
let mixedFinal = owner.appendingPathComponent(mixed.id)
_ = try F.commit(stage: mixedStage, destination: mixedFinal, recipe: mixed, records: mixedRecords,
                 digest: digestFile, idle: { true }, recheckCore: { try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile) })
_ = try F.validate(mixedFinal, recipe: mixed, digest: digestFile)
let diaTarget = mixedFinal.appendingPathComponent(recipe.prefix + diaKey.name)
try fixture("dia-mutated.dll").write(to: diaTarget)
fails("mixed architecture cache cannot reuse tampered diagnostic DLL") { _ = try F.validate(mixedFinal, recipe: mixed, digest: digestFile) }
try fixture("dia-amd64.dll").write(to: diaTarget)
_ = try F.validate(mixedFinal, recipe: mixed, digest: digestFile)
for archive in ["mixed.zip", "mixed-i386.zip", "mixed-mutated.zip", "mixed-case.zip", "mixed-other.zip"] {
    let wantedKeys = archive == "mixed.zip" ? recipe.keys : recipe.keys + [diaKey]
    let rejected = try mixedRecipe(archive, keys: wantedKeys)
    let rejectedStage = try newStage(archive)
    var rejectedRecords: [F.FileRecord] = []
    fails("only exact hash/size/architecture/name-pinned AMD64 diagnostic member may be installed: " + archive) {
        try F.appendArchive(try fixture(archive), package: rejected.packages[0], recipe: rejected,
                            stage: rejectedStage, records: &rejectedRecords, digest: digest, idle: { true })
    }
    assert(rejectedRecords.count <= 4)
    assert(!fm.fileExists(atPath: rejectedStage.appendingPathComponent(recipe.prefix + "msdia140.dll").path))
    assert(!fm.fileExists(atPath: rejectedStage.appendingPathComponent(recipe.prefix + "MSDIA140.dll").path))
    assert(!fm.fileExists(atPath: rejectedStage.appendingPathComponent(recipe.prefix + "other.dll").path))
}
for name in privateNames { assert(try! Data(contentsOf: steam.appendingPathComponent(name)) == Data(name.utf8)) }
print("PASS exact mixed-architecture official-cache regression: pinned AMD64 diagnostic member installed, committed and reused; wrong architecture/hash/name, unpinned AMD64 and edited cache refused; browser keys remain I386 and Steam data unchanged")

'''
main = main.replace('HASHES', '[' + ',\n'.join(json.dumps(__import__('base64').b64encode(data).decode()) + ': ' + json.dumps(value) for data, value in digests.items()) + ']')
start = runtime.index('enum SteamRuntimeFiles {')
end = runtime.index('\n#if canImport(CryptoKit)', start)
with tempfile.TemporaryDirectory(prefix='madeira-browser-cache-') as temporary:
    p = Path(temporary)
    for name, value in fixtures.items():
        (p / name).write_bytes(value)
    if os.uname().sysname != 'Darwin':
        (p / 'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" export * link "z" }')
    (p / 'Files.swift').write_text('import Foundation\nimport zlib\n' + runtime[start:end])
    # macOS compiles the full candidate including CryptoKit/downloader; Linux
    # compiles its pure production cache/parser transaction functions.
    (p / 'Browser.swift').write_text(cache)
    (p / 'main.swift').write_text(main)
    subprocess.run([swift, '-I', str(p), str(p / 'Files.swift'), str(p / 'Browser.swift'), str(p / 'main.swift'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test'), str(p)], check=True)
