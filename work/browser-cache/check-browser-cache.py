#!/usr/bin/env python3
"""Exercise candidate production Swift functions; no Steam download or Wine run.

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
args = parser.parse_args()
runtime = (HERE / 'SteamRuntime.swift.candidate').read_text()
cache = (HERE / 'SteamBrowserRuntime.swift').read_text()
production_runtime = (ROOT / 'app/Madeira/SteamRuntime.swift').read_text()
assert 'limits: ZIPLimits = .standard' in runtime
assert 'archive: 64 * 1024 * 1024, member: 64 * 1024 * 1024' in runtime
assert 'total: 256 * 1024 * 1024, records: 256, strict: false' in runtime
assert 'member: 256 * 1024 * 1024, total: 768 * 1024 * 1024, records: 256, strict: true' in runtime
assert 'limits: ZIPLimits' not in production_runtime, 'Candidate unexpectedly activated in app'
assert cache.index('digest(archive) == package.sha256') < cache.index('limits: .trustedOfficialI386Browser')
assert 'URLSessionDataDelegate' in cache and 'data.count <= package.bytes - received' in cache
assert 'URLSession.download(' not in cache and 'session.data(from:' not in cache
assert 'completionHandler(nil)' in cache
assert 'response.expectedContentLength == Int64(package.bytes)' in cache
assert 'SteamOwnedLibrary.shared.wineSessionActive' in cache
assert 'try fm.moveItem(at: stage, to: final)' not in cache  # commit uses its own checked transaction
assert 'moveItem(at: stage, to: final)' in cache
contract = (ROOT / 'work/htmlipc-dispatch/runtime-shim/cache-contract.txt').read_bytes()
assert len(contract) == 284
assert hashlib.sha256(contract).hexdigest() == '86d1ca3b9e48ef3ee3cc099cfb25ddf18cb2e09754e66a5c3c8a830e007425b8'
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
digests = {value: hashlib.sha256(value).hexdigest() for value in fixtures.values()}
assert zipfile.ZipFile(io.BytesIO(good)).testzip() is None
assert len(payloads) == 4 and len(set(n.lower() for n in payloads)) == 4
print('PASS candidate source and ZIP fixtures: preserved app defaults, pin-before-expanded-parser, bounded transfer, malicious fixture construction')

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
func fails(_ label: String, _ block: () throws -> Void) {
    do { try block(); fatalError("accepted: " + label) } catch {}
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
assert(F.official.expectedFiles == 78 && F.officialMarker.bytes.count == 284)
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
try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile)
fails("core outside Steam") { try F.core(core, steamRoot: base, recipe: recipe, digest: digestFile) }
fails("active owner acquisition") { _ = try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { false }) }
let alien = base.appendingPathComponent("SteamBrowserRuntime")
try fm.createDirectory(at: alien, withIntermediateDirectories: false)
try Data("keep".utf8).write(to: alien.appendingPathComponent("existing"))
fails("unowned existing cache") { _ = try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { true }) }
assert(try! Data(contentsOf: alien.appendingPathComponent("existing")) == Data("keep".utf8))
try fm.removeItem(at: alien)
let owner = try F.ownerRoot(cacheBase: base, steamRoot: steam, idle: { true })
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
try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { true })
assert(records.count == 4)
assert(!fm.fileExists(atPath: stage.appendingPathComponent(recipe.prefix + generated.name).path))
let falseOfficialRecipe = F.Recipe(id: recipe.id, coreSHA256: recipe.coreSHA256, prefix: recipe.prefix, expectedFiles: 4, packages: [package], keys: recipe.keys, marker: F.officialMarker)
fails("fixture recipe cannot emit real production contract") { _ = try F.commit(stage: stage, destination: owner.appendingPathComponent(recipe.id), recipe: falseOfficialRecipe, records: records, digest: digestFile, idle: { true }, recheckCore: {}) }
assert(!fm.fileExists(atPath: stage.appendingPathComponent(recipe.prefix + generated.name).path))
fails("duplicate archive members") { try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: stage, records: &records, digest: digest, idle: { true }) }
fails("wrong final ownership") { _ = try F.commit(stage: stage, destination: base.appendingPathComponent(recipe.id), recipe: recipe, records: records, digest: digestFile, idle: { true }, recheckCore: {}) }
let final = owner.appendingPathComponent(recipe.id)
fails("active atomic completion") { _ = try F.commit(stage: stage, destination: final, recipe: recipe, records: records, digest: digestFile, idle: { false }, recheckCore: {}) }
let prepared = try F.commit(stage: stage, destination: final, recipe: recipe, records: records, digest: digestFile, idle: { true }) {
    try F.core(core, steamRoot: steam, recipe: recipe, digest: digestFile)
}
assert(prepared.helper.lastPathComponent == "steamwebhelper.exe")
assert(!fm.fileExists(atPath: stage.path))
_ = try F.validate(final, recipe: recipe, digest: digestFile)
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
var incomplete = records; incomplete.removeLast()
fails("incomplete manifest") { _ = try F.manifest(recipe: recipe, records: incomplete) }
let partialStage = try newStage("partial-tree")
var partialRecords: [F.FileRecord] = []
try F.appendArchive(try fixture("good.zip"), package: package, recipe: recipe, stage: partialStage, records: &partialRecords, digest: digest, idle: { true })
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
try SteamRuntimeFiles.unpack(try fixture("descriptor.zip"), limits: .trustedOfficialI386Browser) { _, _ in descriptorCount += 1 }
assert(descriptorCount == 1)
// The default behavior stays unchanged; the stricter local-CRC check belongs
// to the authenticated-browser budget only.
try SteamRuntimeFiles.unpack(try fixture("local-crc.zip")) { _, _ in }
for name in privateNames { assert(try! Data(contentsOf: steam.appendingPathComponent(name)) == Data(name.utf8)) }
assert(try! Data(contentsOf: core) == fixture("core.dll"))
print("PASS real candidate Swift functions: generated-marker absence/tamper/edited-manifest/partial-tree/interruption refusal, manifest/full-tree validation, idle rechecks, ownership, archive pins, traversal/case/symlink/CRC/local-header/descriptor rejection, i386 PE requirement; Steam authentication, CS2 and official cef.win64 fixtures unchanged")
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
