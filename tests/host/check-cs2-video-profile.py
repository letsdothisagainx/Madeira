#!/usr/bin/env python3
"""Run the actual bounded CS2 user-video profile parser and file transaction.

The complete production helper is extracted without a replacement algorithm.
Fixtures cover unique/ambiguous accounts, byte preservation, owned restoration,
interrupted transactions, malformed/oversized configs and unsafe filesystem
objects. This is host filesystem execution, not CS2 or iPhone validation.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
library = (ROOT / 'app/Madeira/Library.swift').read_text()
content = (ROOT / 'app/Madeira/ContentView.swift').read_text()
helper = library.split('// BEGIN CS2 TEXTURE MEMORY PROFILE\n', 1)[1].split('// END CS2 TEXTURE MEMORY PROFILE', 1)[0]
assert 'let updated = options + ["d3d11.mipClampAuto=0"]' in helper
assert 'Balanced uses CS2’s own Low texture detail' in helper
assert 'setting.videocfg_texture_detail' in helper
assert 'videoLimit = 1024 * 1024' in helper
assert 'maximum + 1' in helper and 'read(upToCount:' in helper
assert 'if nativeSteamClient && textureMemory.applicable && !standaloneProbe {' in content
assert 'CS2TextureMemoryProfile.configureVideo(textureMemory' in content
assert content.index('CS2TextureMemoryProfile.configureVideo(') < content.index('setenv("DXMT_CONFIG"')
assert 'applicationSupportDirectory' in content
assert 'options: .atomic' in helper
assert 'options: .withoutOverwriting' in helper
for forbidden in ['r_texture_stream', 'videocfg_texture_detail=', 'write(to: file, options: [])', 'removeItem(at: file)', 'setenv(', 'resetSettings']:
    assert forbidden not in helper
print('PASS genuine CS2 scalar selection, Auto=0, bounded launch-time native-Steam-only wiring and app-private atomic receipt source checks')
swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('Swift compiler required for actual CS2 video profile execution')
    print('SKIP Swift execution: macOS CI must run --require-swift; no game/iPhone success claim')
    raise SystemExit(0)

harness = r'''
let fm = FileManager.default
var checked = 0
func check(_ value: @autoclosure () throws -> Bool, _ message: String) {
    checked += 1
    do { let result = try value(); precondition(result, message) }
    catch { preconditionFailure(message + ": unexpected fixture I/O error") }
}
let original = Data(("\u{feff}// user video settings\r\n\"video.cfg\"\r\n{\r\n" +
    "\t\"Version\"\t\"16\"\r\n\t\"AutoConfig\" \"1\"\r\n" +
    "\t\"setting.videocfg_texture_detail\"  \"2\" // High\r\n" +
    "\t\"setting.defaultres\" \"800\"\r\n\t\"setting.defaultresheight\" \"450\"\r\n" +
    "\t\"unknown\" \"preserved 中 😀 \\\"quote\\\"\"\r\n}\r\n").utf8)
let initialScalar = try CS2TextureMemoryProfile.videoScalar(original)
check(initialScalar.value == 2 && initialScalar.raw == Data("\"2\"".utf8), "actual scalar")
let expected = CS2TextureMemoryProfile.replacingVideoScalar(original, scalar: initialScalar, with: Data("\"0\"".utf8))
check(expected == Data(String(decoding: original, as: UTF8.self).replacingOccurrences(of: "\"2\" // High", with: "\"0\" // High").utf8), "only token changed")
let unquoted = Data("video.cfg { Version 16 /*keep*/ setting.videocfg_texture_detail 1 other { x y } }".utf8)
check(try CS2TextureMemoryProfile.videoScalar(unquoted).raw == Data("1".utf8), "unquoted scalar")
let malformed: [Data] = [Data(), Data([0xff]), Data([0]), Data("{}".utf8),
    Data("video.cfg { Version 16 }".utf8),
    Data("video.cfg { setting.videocfg_texture_detail 2 }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 3 }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 2 setting.videocfg_texture_detail 1 }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 2 OTHER { setting.videocfg_texture_detail 1 } }".utf8),
    Data("video.cfg { Version 16 Version 17 setting.videocfg_texture_detail 2 }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail {} }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 2".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 2 } extra".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail \"2 }".utf8),
    Data("video.cfg { Version 16 setting.videocfg_texture_detail 2 /* never closes".utf8),
    Data(repeating: 32, count: CS2TextureMemoryProfile.videoLimit + 1)]
for data in malformed {
    do { _ = try CS2TextureMemoryProfile.videoScalar(data); preconditionFailure("accepted malformed/ambiguous config") }
    catch { checked += 1 }
}

func profile(_ mode: String = "balanced", options: [String] = [], app: Int? = 730) -> CS2TextureMemoryProfile.Decision {
    CS2TextureMemoryProfile.apply(options: options, appID: app, saved: mode,
        budget: 6 << 30, environmentAuto: nil)
}
struct Fixture {
    let root: URL, documents: URL, steam: URL, storage: URL, config: URL
    func run(_ decision: CS2TextureMemoryProfile.Decision = profile()) -> String {
        CS2TextureMemoryProfile.configureVideo(decision, documents: documents, steamRoot: steam, storage: storage)
    }
    func bytes() throws -> Data { try Data(contentsOf: config) }
    func receipt() -> URL { storage.appendingPathComponent("123456.json") }
    func backup() -> URL { storage.appendingPathComponent("123456.original") }
}
func fixture(_ bytes: Data = original) throws -> Fixture {
    let root = fm.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("madeira-cs2-video-" + UUID().uuidString)
    let documents = root.appendingPathComponent("Documents", isDirectory: true)
    let steam = documents.appendingPathComponent("wine/drive_c/Program Files (x86)/Steam", isDirectory: true)
    let config = steam.appendingPathComponent("userdata/123456/730/local/cfg/cs2_video.txt")
    let support = root.appendingPathComponent("Application Support", isDirectory: true)
    try fm.createDirectory(at: config.deletingLastPathComponent(), withIntermediateDirectories: true)
    try fm.createDirectory(at: support, withIntermediateDirectories: true)
    try bytes.write(to: config)
    return Fixture(root: root, documents: documents, steam: steam,
        storage: support.appendingPathComponent("Madeira-CS2-Video-Profile-v1", isDirectory: true), config: config)
}
func isolated(_ body: (Fixture) throws -> Void, bytes: Data = original) throws {
    let f = try fixture(bytes); defer { try? fm.removeItem(at: f.root) }; try body(f)
}
try isolated { f in
    check(f.run() == "applied-game-low", "balanced uses game Low")
    check(try f.bytes() == expected, "only game scalar changed")
    check(try Data(contentsOf: f.backup()) == original, "private original backup")
    check(f.run() == "already-low", "repeat balanced is idempotent")
    let changed = Data(String(decoding: expected, as: UTF8.self).replacingOccurrences(of: "\"16\"", with: "\"17\"").utf8)
    try changed.write(to: f.config, options: .atomic)
    check(f.run(profile("full")) == "restored-owned-detail", "full restores owned scalar")
    let restored = Data(String(decoding: original, as: UTF8.self).replacingOccurrences(of: "\"16\"", with: "\"17\"").utf8)
    check(try f.bytes() == restored, "Version and every unrelated updated byte preserved")
    check(!fm.fileExists(atPath: f.receipt().path) && !fm.fileExists(atPath: f.backup().path), "owned receipt retired")
}
try isolated { f in
    check(f.run(profile("full")) == "full-no-owned-change", "Full never raises unowned settings")
    check(try f.bytes() == original, "Full preserves user setting")
    check(f.run(profile(options: ["d3d11.mipClampBC=2"])) == "custom-override-preserved", "explicit custom mip setting unchanged")
    check(f.run(profile(app: 570)) == "unrelated-launch", "other game untouched")
    check(try f.bytes() == original, "custom/unrelated preserve full file")
}
try isolated({ f in
    check(f.run() == "already-low", "already-Low has no owned mutation")
    check(f.run(profile("full")) == "full-no-owned-change", "Full keeps preexisting Low")
    check(try f.bytes() == expected, "no fabricated restore")
}, bytes: expected)
try isolated { f in
    check(f.run() == "applied-game-low", "start managed")
    let external = CS2TextureMemoryProfile.replacingVideoScalar(expected,
        scalar: try CS2TextureMemoryProfile.videoScalar(expected), with: Data("\"1\"".utf8))
    try external.write(to: f.config, options: .atomic)
    check(f.run(profile("full")) == "full-external-change-preserved", "respect independently changed scalar")
    check(try f.bytes() == external && !fm.fileExists(atPath: f.receipt().path), "old ownership retired without resetting settings")
}
try isolated { f in
    check(f.run() == "applied-game-low", "establish owned storage")
    check(f.run(profile("full")) == "restored-owned-detail", "restore after first launch")
    try original.write(to: f.backup(), options: .atomic) // interrupted after backup, before receipt
    check(f.run() == "applied-game-low", "recover backup-before-receipt interruption")
    try original.write(to: f.config, options: .atomic) // interruption after receipt, before target
    check(f.run() == "applied-game-low", "recover receipt-before-target interruption")
    check(try f.run(profile("full")) == "restored-owned-detail" && f.bytes() == original, "recovery retains original setting")
}
try isolated { f in
    let other = f.steam.appendingPathComponent("userdata/987654/730/local/cfg", isDirectory: true)
    try fm.createDirectory(at: other, withIntermediateDirectories: true)
    check(f.run() == "skipped-ambiguous-accounts", "never guess active account")
    check(try f.bytes() == original && !fm.fileExists(atPath: other.appendingPathComponent("cs2_video.txt").path), "no multiaccount writes or new config")
}
try isolated { f in
    for account in ["0", "00123", "4294967296", "anonymous"] {
        let cfg = f.steam.appendingPathComponent("userdata/" + account + "/730/local/cfg", isDirectory: true)
        try fm.createDirectory(at: cfg, withIntermediateDirectories: true)
        try original.write(to: cfg.appendingPathComponent("cs2_video.txt"))
    }
    check(f.run() == "applied-game-low", "only canonical positive AccountID32 directories are candidates")
}
try isolated { f in
    try fm.removeItem(at: f.config)
    check(f.run() == "skipped-missing-video-config" && !fm.fileExists(atPath: f.config.path), "never create missing game config")
}
try isolated({ f in
    check(f.run().hasPrefix("skipped-"), "malformed config skipped")
    check(try f.bytes() == malformed[6], "malformed data unchanged")
}, bytes: malformed[6])
try isolated({ f in
    check(f.run() == "skipped-oversized-file", "bounded read rejects oversized config")
    check(try f.bytes().count == CS2TextureMemoryProfile.videoLimit + 1, "oversized config unchanged")
}, bytes: Data(repeating: 32, count: CS2TextureMemoryProfile.videoLimit + 1))
try isolated { f in
    let outside = f.root.appendingPathComponent("outside.txt")
    try original.write(to: outside)
    try fm.removeItem(at: f.config)
    try fm.createSymbolicLink(at: f.config, withDestinationURL: outside)
    check(f.run() == "skipped-unsafe-path", "reject config symlink")
    check(try Data(contentsOf: outside) == original, "no outside write")
}
try isolated { f in
    let userdata = f.steam.appendingPathComponent("userdata")
    let outside = f.root.appendingPathComponent("outside-userdata", isDirectory: true)
    try fm.moveItem(at: userdata, to: outside)
    try fm.createSymbolicLink(at: userdata, withDestinationURL: outside)
    check(f.run() == "skipped-unsafe-path", "reject parent symlink")
}
try isolated { f in
    try fm.linkItem(at: f.config, to: f.root.appendingPathComponent("linked.txt"))
    check(f.run() == "skipped-unsafe-file-links", "reject shared hardlink config")
    check(try f.bytes() == original, "hardlink unchanged")
}
try isolated { f in
    check(f.run() == "applied-game-low", "establish storage for corruption case")
    try Data("not-json".utf8).write(to: f.receipt(), options: .atomic)
    check(f.run(profile("full")) == "skipped-invalid-receipt", "fail closed on corrupt receipt")
    check(try f.bytes() == expected, "invalid receipt cannot overwrite game data")
}
try isolated { f in
    check(f.run() == "applied-game-low", "establish storage for orphan case")
    check(f.run(profile("full")) == "restored-owned-detail", "return original")
    try Data("unrelated".utf8).write(to: f.backup(), options: .atomic)
    check(f.run() == "skipped-orphan-backup-conflict", "preserve conflicting orphan backup")
    check(try f.bytes() == original, "orphan conflict leaves game config untouched")
}
try isolated { f in
    check(f.run() == "applied-game-low", "establish storage for dangling symlink case")
    check(f.run(profile("full")) == "restored-owned-detail", "restore before link fixture")
    try fm.createSymbolicLink(at: f.backup(), withDestinationURL: f.root.appendingPathComponent("missing"))
    check(f.run() == "skipped-unsafe-path", "reject dangling backup symlink")
    check(try f.bytes() == original, "dangling link leaves config unchanged")
}
try isolated({ f in
    check(f.run() == "applied-game-low", "accept bounded maximum-size valid config")
    check(try f.bytes().count == CS2TextureMemoryProfile.videoLimit, "bounded replacement preserves size")
}, bytes: original + Data(repeating: 32, count: CS2TextureMemoryProfile.videoLimit-original.count))
print("PASS \(checked) production Swift KV/file assertions: only selected scalar changed, app-owned backup/restore/recovery, bounded reads, custom precedence and unsafe/ambiguous paths fail safely")
print("No CS2 startup, visual correction, memory or FPS success claim; iPhone validation remains necessary.")
'''
with tempfile.TemporaryDirectory(prefix='madeira-cs2-video-profile-') as temporary:
    source = Path(temporary) / 'video.swift'
    binary = Path(temporary) / 'video'
    source.write_text('import Foundation\n' + helper + harness)
    subprocess.run([swift, '-swift-version', '5', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
