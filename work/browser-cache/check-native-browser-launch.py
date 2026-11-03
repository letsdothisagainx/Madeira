#!/usr/bin/env python3
"""Run candidate bridge-install/environment Swift helpers without Wine/downloads.

Python computes SHA-256 for a closed set of small synthetic PE fixtures. Injecting
that map exercises production transaction decisions, not CryptoKit itself. macOS
also compiles the complete candidate including its async launch coordinator.
Use --require-swift in CI; a missing compiler is otherwise reported honestly.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
native = (HERE / 'SteamNativeBrowserLaunch.swift').read_text()
cache = (HERE / 'SteamBrowserRuntime.swift').read_text()
runtime = (HERE / 'SteamRuntime.swift.candidate').read_text()
update = (ROOT / 'app/Madeira/SteamClientUpdate.swift').read_text().split('#if canImport(SwiftUI)', 1)[0]
bridge_source = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()
start = bridge_source.index('static int madeira_env_is_locked(')
end = bridge_source.index('\nstatic int madeira_cfg_off_word(', start)
locked_function = bridge_source[start:end]
assert 'manifest.mode == "native-owner"' in native
assert 'manifest.coreSHA256 == Files.official.coreSHA256' in native
assert 'ReadinessABI(version: 1, size: 80, sha256: abiSHA256)' in native
assert 'SteamBrowserRuntimeFiles.machine(header) == 0x8664' in native
assert 'else if hasTarget { throw Failure.ownership }' in native
assert native.index('try encoded.write(to: stamp') < native.index('try image.write(to: target')
assert '"MADEIRA_NATIVE_STEAM_LAUNCH", "MADEIRA_ENV_LOCKED"' in native
assert 'for name in lockedNames.prefix(3) { unset(name) }' in native
assert native.index('guard native else { return }') < native.index('guard let selected = prepared')
assert 'SteamNativeBrowserLaunch' not in (ROOT / 'app/Madeira/ContentView.swift').read_text(), 'candidate unexpectedly activated'


def pe(kind, label):
    image = bytearray(512)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3c, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', image, 0x84, kind)
    struct.pack_into('<H', image, 0x94, 240)
    struct.pack_into('<H', image, 0x98, 0x10b if kind == 0x14c else 0x20b)
    return bytes(image) + label


fixtures = {
    'bridge-v1.dll': pe(0x8664, b'bridge-fixture-v1'),
    'bridge-v2.dll': pe(0x8664, b'bridge-fixture-v2'),
    'bridge-i386.dll': pe(0x14c, b'i386-not-bridge'),
    'bridge-corrupt.dll': pe(0x8664, b'changed-unowned!!'),
}
digests = {value: hashlib.sha256(value).hexdigest() for value in fixtures.values()}
assert len(digests) == len(fixtures)
print('PASS native launch candidate source/fixture checks: manifest mode/core/ABI, AMD64 PE gate, pending ownership before copy, absent-value environment locks')

# Compile the actual C lock predicate used by BOTH global and game cfg loops.
# The Swift test runs this executable with the environment its real export()
# produced; its own lock name is attacked first to test locklist replacement.
c_code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
LOCK_FUNCTION
static void cfg(const char *name,const char *value) {
    if(!madeira_env_is_locked(name)) assert(setenv(name,value,1)==0);
}
int main(void) {
    const char *keys[]={"MADEIRA_HTMLIPC_HELPER","MADEIRA_HTMLIPC_CACHE_DIR","MADEIRA_NATIVE_STEAM_LAUNCH","MADEIRA_ENV_LOCKED"};
    char *before[4];
    for(unsigned i=0;i<4;i++){const char *p=getenv(keys[i]);before[i]=p?strdup(p):NULL;}
    assert(before[3]);
    cfg("MADEIRA_ENV_LOCKED","");
    for(unsigned i=0;i<3;i++)cfg(keys[i],"cfg-attempted-override");
    for(unsigned i=0;i<4;i++) {
        const char *after=getenv(keys[i]);
        assert(before[i] ? after&&!strcmp(before[i],after) : !after);
        free(before[i]);
    }
    cfg("MADEIRA_HTMLIPC_HELPER_EXTRA","ordinary-setting");
    assert(!strcmp(getenv("MADEIRA_HTMLIPC_HELPER_EXTRA"),"ordinary-setting"));
    puts("PASS actual Wine bridge cfg-lock predicate: native values and unrelated absence survive cfg overrides including locklist replacement");
}
'''.replace('LOCK_FUNCTION', locked_function)

main = r'''
import Foundation
let fm = FileManager.default
let fixtures = URL(fileURLWithPath: CommandLine.arguments[1])
let locksExecutable = URL(fileURLWithPath: CommandLine.arguments[2])
let hashes: [String: String] = HASHES
func fixture(_ name: String) throws -> Data { try Data(contentsOf: fixtures.appendingPathComponent(name)) }
func digest(_ bytes: Data) -> String { hashes[bytes.base64EncodedString()] ?? "unknown-mutation" }
func digestFile(_ file: URL) throws -> String { digest(try Data(contentsOf: file)) }
func fails(_ label: String, _ action: () throws -> Void) {
    do { try action(); fatalError("accepted: " + label) } catch {}
}
typealias F = SteamNativeBrowserLaunchFiles
typealias B = SteamBrowserRuntimeFiles
let temp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
try fm.createDirectory(at: temp, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: temp) }
let drive = temp.appendingPathComponent("drive_c")
let system = drive.appendingPathComponent("windows/system32")
let steam = drive.appendingPathComponent("Program Files (x86)/Steam")
let resources = temp.appendingPathComponent("BundleResources")
let binaryFolder = resources.appendingPathComponent("arm64ec-windows")
for folder in [system, steam, binaryFolder] { try fm.createDirectory(at: folder, withIntermediateDirectories: true) }
let privateNames = ["config/loginusers.vdf", "userdata/account/config/localconfig.vdf", "steamapps/appmanifest_730.acf", "steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe", "bin/chromehtml.dll", "bin/cef/cef.win64/libcef.dll"]
for name in privateNames {
    let file = steam.appendingPathComponent(name)
    try fm.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data(("keep-private:" + name).utf8).write(to: file)
}
let originalSystem = system.appendingPathComponent("kernel32.dll")
try Data("unrelated-system32-kept".utf8).write(to: originalSystem)
let dll = binaryFolder.appendingPathComponent(F.bridgeName)
let metadata = binaryFolder.appendingPathComponent(F.manifestName)
let first = try fixture("bridge-v1.dll"), second = try fixture("bridge-v2.dll")
func manifest(_ image: Data, mode: String = "native-owner", core: String = B.official.coreSHA256,
              abi: F.ReadinessABI = F.ReadinessABI(version: 1, size: 80, sha256: F.abiSHA256),
              hash: String? = nil, filename: String = F.bridgeName) -> F.BridgeManifest {
    F.BridgeManifest(format: 1, mode: mode, filename: filename, bytes: image.count,
        sha256: hash ?? digest(image), coreSHA256: core, readinessABI: abi)
}
func saveManifest(_ value: F.BridgeManifest) throws { try JSONEncoder().encode(value).write(to: metadata) }
try first.write(to: dll)
let valid = manifest(first)
try saveManifest(valid)
let loaded = try F.bundle(resources, digest: digestFile)
assert(loaded.0 == dll && loaded.1 == valid)
for value in [manifest(first, mode: "test-proxy"), manifest(first, core: String(repeating: "0", count: 64)),
              manifest(first, abi: F.ReadinessABI(version: 2, size: 80, sha256: F.abiSHA256)),
              manifest(first, abi: F.ReadinessABI(version: 1, size: 79, sha256: F.abiSHA256)),
              manifest(first, abi: F.ReadinessABI(version: 1, size: 80, sha256: String(repeating: "1", count: 64))),
              manifest(first, hash: digest(second)), manifest(first, filename: "different.dll")] {
    try saveManifest(value)
    fails("invalid bundle manifest") { _ = try F.bundle(resources, digest: digestFile) }
}
let i386 = try fixture("bridge-i386.dll")
try i386.write(to: dll); try saveManifest(manifest(i386))
fails("i386 bundle image despite matching full hash") { _ = try F.bundle(resources, digest: digestFile) }
try first.write(to: dll); try saveManifest(valid)
try Data(repeating: 0x20, count: 65 * 1024).write(to: metadata)
fails("oversized bundle manifest") { _ = try F.bundle(resources, digest: digestFile) }
try saveManifest(valid)

let target = system.appendingPathComponent(F.bridgeName)
let stamp = system.appendingPathComponent(F.stampName)
func currentStamp() throws -> F.Stamp { try JSONDecoder().decode(F.Stamp.self, from: Data(contentsOf: stamp)) }
func writeStamp(installed: F.Fingerprint?, pending: F.Fingerprint?, owner: String = "org.madeira.NativeSteamBrowserBridge/v1") throws {
    try JSONEncoder().encode(F.Stamp(format: 1, owner: owner, filename: F.bridgeName, installed: installed, pending: pending)).write(to: stamp)
}
fails("active fresh installation") { try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { false }) }
assert(!fm.fileExists(atPath: target.path) && !fm.fileExists(atPath: stamp.path))
try first.write(to: target)
fails("matching but unowned existing target") { try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { true }) }
assert(try! Data(contentsOf: target) == first)
assert(!fm.fileExists(atPath: stamp.path))
try fm.removeItem(at: target)
try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { true })
assert(try! Data(contentsOf: target) == first)
assert(try! currentStamp().installed == valid.fingerprint && currentStamp().pending == nil)
try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { true })

let sourceSecond = fixtures.appendingPathComponent("bridge-v2.dll"), next = manifest(second)
try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true })
assert(try! Data(contentsOf: target) == second)
assert(try! currentStamp().installed == next.fingerprint && currentStamp().pending == nil)
// Resume when copy committed but final stamp did not, and when the old image
// remains after the pending stamp committed but before replacement.
try writeStamp(installed: valid.fingerprint, pending: next.fingerprint)
try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true })
assert(try! currentStamp().installed == next.fingerprint && currentStamp().pending == nil)
try first.write(to: target); try writeStamp(installed: valid.fingerprint, pending: next.fingerprint)
try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true })
assert(try! Data(contentsOf: target) == second)
try fm.removeItem(at: target); try writeStamp(installed: nil, pending: next.fingerprint)
try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true })
assert(try! Data(contentsOf: target) == second)
var idleChecks = 0
fails("session begins after pending stamp") {
    try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { idleChecks += 1; return idleChecks == 1 })
}
assert(try! Data(contentsOf: target) == second)
assert(try! currentStamp().installed == next.fingerprint && currentStamp().pending == valid.fingerprint)
try F.installBridge(dll, manifest: valid, drive: drive, digest: digestFile, idle: { true })
assert(try! Data(contentsOf: target) == first)
let changed = try fixture("bridge-corrupt.dll")
idleChecks = 0
fails("target changes between pending ownership and replacement") {
    try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: {
        idleChecks += 1
        if idleChecks == 2 { try! changed.write(to: target) }
        return true
    })
}
assert(try! Data(contentsOf: target) == changed)
fails("changed target cannot be blessed by owned stamp") { try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true }) }
assert(try! Data(contentsOf: target) == changed)
try second.write(to: target); try writeStamp(installed: next.fingerprint, pending: nil, owner: "unowned")
fails("foreign ownership stamp") { try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true }) }
assert(try! Data(contentsOf: target) == second)
try writeStamp(installed: next.fingerprint, pending: nil)
try fm.removeItem(at: target)
let auth = steam.appendingPathComponent(privateNames[0])
try fm.createSymbolicLink(at: target, withDestinationURL: auth)
fails("linked target") { try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true }) }
assert(try! Data(contentsOf: auth) == Data(("keep-private:" + privateNames[0]).utf8))
try fm.removeItem(at: target); try second.write(to: target)
try fm.removeItem(at: stamp); try fm.createSymbolicLink(at: stamp, withDestinationURL: auth)
fails("linked ownership stamp") { try F.installBridge(sourceSecond, manifest: next, drive: drive, digest: digestFile, idle: { true }) }
try fm.removeItem(at: stamp); try writeStamp(installed: next.fingerprint, pending: nil)

let compat = try F.compatRoot(drive: drive, idle: { true })
assert(compat == drive.appendingPathComponent("windows/madeira-compat"))
let browser = compat.appendingPathComponent("SteamBrowserRuntime/" + B.official.id + "/bin/cef/cef.win7")
try fm.createDirectory(at: browser, withIntermediateDirectories: true)
let helper = browser.appendingPathComponent("steamwebhelper.exe")
try i386.write(to: helper)
let cache = B.Prepared(helper: helper, browserRoot: browser, coreSHA256: B.official.coreSHA256, recipe: B.official.id)
let selected = try F.prepared(cache, bridge: next.fingerprint, drive: drive)
let expectedDirectory = "C:\\windows\\madeira-compat\\SteamBrowserRuntime\\" + B.official.id + "\\bin\\cef\\cef.win7"
assert(selected.cacheDirectory == expectedDirectory)
assert(selected.helper == expectedDirectory + "\\steamwebhelper.exe")
assert(try! F.windowsPath(target, drive: drive) == "C:\\windows\\system32\\" + F.bridgeName)
fails("drive itself is not a file path") { _ = try F.windowsPath(drive, drive: drive) }
fails("outside drive path") { _ = try F.windowsPath(temp.appendingPathComponent("outside"), drive: drive) }
fails("drive prefix alias") { _ = try F.windowsPath(temp.appendingPathComponent("drive_c_extra/file"), drive: drive) }
fails("non-ASCII Windows path") { _ = try F.windowsPath(drive.appendingPathComponent("caf\u{00e9}/file"), drive: drive) }
fails("invalid Windows path colon") { _ = try F.windowsPath(drive.appendingPathComponent("wrong:name/file"), drive: drive) }
let linked = drive.appendingPathComponent("linked")
try fm.createSymbolicLink(at: linked, withDestinationURL: browser)
fails("linked Windows path") { _ = try F.windowsPath(linked.appendingPathComponent("steamwebhelper.exe"), drive: drive) }
fails("unapproved cache recipe") {
    _ = try F.prepared(B.Prepared(helper: helper, browserRoot: browser, coreSHA256: B.official.coreSHA256, recipe: "other"), bridge: next.fingerprint, drive: drive)
}
fails("unapproved cache core") {
    _ = try F.prepared(B.Prepared(helper: helper, browserRoot: browser, coreSHA256: "other", recipe: B.official.id), bridge: next.fingerprint, drive: drive)
}

func checkCfg(_ environment: [String: String]) throws {
    let process = Process(); process.executableURL = locksExecutable; process.environment = environment
    try process.run(); process.waitUntilExit(); assert(process.terminationStatus == 0)
}
var environment = ["MADEIRA_ENV_LOCKED": "OTHER,MADEIRA_EXE, OTHER", "OTHER": "kept", "MADEIRA_HTMLIPC_HELPER": "stale"]
func export(_ native: Bool, _ prepared: F.Prepared?, failingSet: String? = nil) throws {
    try F.export(native: native, prepared: prepared, get: { environment[$0] }, set: { name, value in
        if name == failingSet { return false }; environment[name] = value; return true
    }, unset: { environment.removeValue(forKey: $0) })
}
try export(true, selected)
assert(environment["MADEIRA_HTMLIPC_HELPER"] == selected.helper)
assert(environment["MADEIRA_HTMLIPC_CACHE_DIR"] == selected.cacheDirectory)
assert(environment["MADEIRA_NATIVE_STEAM_LAUNCH"] == "1" && environment["OTHER"] == "kept")
let locks = environment["MADEIRA_ENV_LOCKED"]!.split(separator: ",").map(String.init)
assert(Set(locks).count == locks.count && locks.contains("OTHER") && locks.contains("MADEIRA_EXE"))
assert(F.lockedNames.allSatisfy { locks.contains($0) })
try checkCfg(environment)
try export(false, nil)
for name in F.lockedNames.prefix(3) { assert(environment[name] == nil) }
assert(environment["OTHER"] == "kept")
try checkCfg(environment)
fails("native launch requires verified token") { try export(true, nil) }
for name in F.lockedNames.prefix(3) { assert(environment[name] == nil) }
fails("mismatched native helper") { try export(true, F.Prepared(helper: selected.helper + ".bad", cacheDirectory: selected.cacheDirectory, bridge: next.fingerprint)) }
fails("unapproved native prefix") { try export(true, F.Prepared(helper: "C:\\Other\\steamwebhelper.exe", cacheDirectory: "C:\\Other", bridge: next.fingerprint)) }
let escaped = F.nativePrefix + "..\\escape"
fails("cache prefix cannot bless traversal") { try export(true, F.Prepared(helper: escaped + "\\steamwebhelper.exe", cacheDirectory: escaped, bridge: next.fingerprint)) }
fails("native export requires valid bridge fingerprint") { try export(true, F.Prepared(helper: selected.helper, cacheDirectory: selected.cacheDirectory, bridge: F.Fingerprint(bytes: 1, sha256: "invalid"))) }
fails("oversized lock list") { _ = try F.mergedLocks(String(repeating: "x", count: 16 * 1024 + 1)) }
fails("failed environment export is fail-closed") { try export(true, selected, failingSet: "MADEIRA_HTMLIPC_CACHE_DIR") }
for name in F.lockedNames.prefix(3) { assert(environment[name] == nil) }
for name in privateNames { assert(try! Data(contentsOf: steam.appendingPathComponent(name)) == Data(("keep-private:" + name).utf8)) }
assert(try! Data(contentsOf: originalSystem) == Data("unrelated-system32-kept".utf8))
print("PASS real native-launch Swift helpers: bundle mode/ABI/core/PE/hash pins; fresh/owned/pending install transactions; unknown/changed/linked/active targets refused; exact C paths; native and unrelated locked environments; Steam authentication, CS2, official CEF and unrelated system32 fixtures unchanged")
'''
main = main.replace('HASHES', '[' + ',\n'.join(json.dumps(base64.b64encode(data).decode()) + ': ' + json.dumps(value) for data, value in digests.items()) + ']')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
with tempfile.TemporaryDirectory(prefix='madeira-native-browser-') as temporary:
    p = Path(temporary)
    for name, value in fixtures.items():
        (p / name).write_bytes(value)
    (p / 'locks.c').write_text(c_code)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(p / 'locks.c'), '-o', str(p / 'locks')], check=True)
    subprocess.run([str(p / 'locks')], env={'MADEIRA_ENV_LOCKED': ','.join(['OTHER', 'MADEIRA_HTMLIPC_HELPER', 'MADEIRA_HTMLIPC_CACHE_DIR', 'MADEIRA_NATIVE_STEAM_LAUNCH', 'MADEIRA_ENV_LOCKED'])}, check=True)
    if not swift:
        if args.require_swift:
            raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
        print('SKIP Swift execution: no toolchain; native bridge-install/export harness is ready for CI --require-swift')
        raise SystemExit(0)
    if os.uname().sysname != 'Darwin':
        (p / 'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" export * link "z" }')
    first = runtime.index('enum SteamRuntimeFiles {')
    last = runtime.index('\n#if canImport(CryptoKit)', first)
    (p / 'Files.swift').write_text('import Foundation\nimport zlib\n' + runtime[first:last])
    (p / 'Browser.swift').write_text(cache)
    (p / 'Native.swift').write_text(native)
    (p / 'Update.swift').write_text(update)
    (p / 'main.swift').write_text(main)
    subprocess.run([swift, '-swift-version', '5', '-I', str(p), str(p / 'Files.swift'), str(p / 'Browser.swift'), str(p / 'Native.swift'), str(p / 'Update.swift'), str(p / 'main.swift'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test'), str(p), str(p / 'locks')], check=True)
