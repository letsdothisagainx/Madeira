#!/usr/bin/env python3
"""Exercise owned probe staging, never substitute this for GPU readback."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--require-swift', action='store_true')
args = p.parse_args()
swift = shutil.which('swift')
if not swift:
    if args.require_swift:
        raise SystemExit('Swift is required for the production graphics staging regression')
    print('SKIP graphics staging execution: Swift unavailable')
    raise SystemExit(0)
fixture = r'''
let fm = FileManager.default
let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try fm.createDirectory(at: root, withIntermediateDirectories: false)
defer { try? fm.removeItem(at: root) }
let drive = root.appendingPathComponent("drive_c")
try fm.createDirectory(at: drive, withIntermediateDirectories: false)
let canary = drive.appendingPathComponent("existing-game.dll")
try Data("untouched existing game".utf8).write(to: canary)
var image = Data(repeating: 0, count: 256)
func word(_ offset: Int, _ value: Int) { image[offset] = UInt8(value & 255); image[offset+1] = UInt8(value >> 8) }
image[0] = 0x4d; image[1] = 0x5a; image[60] = 0x80
image[128] = 0x50; image[129] = 0x45
word(132,0x8664); word(152,0x20b); word(220,3)
image.append(Data("[d3d11-pixels] DXMT device identity".utf8))
let source = root.appendingPathComponent("bundled.exe")
try image.write(to: source)
let first = try GraphicsPixelProbe.stage(executable: source, drive: drive)
let target = drive.appendingPathComponent(first)
assert(first.hasPrefix("madeira-graphics-probe-"))
assert(first.hasSuffix("/pixel-readback-x64.exe"))
assert(try! Data(contentsOf: target) == image)
let lock = NSLock()
var paths = Set([first]), errors = 0
DispatchQueue.concurrentPerform(iterations: 24) { _ in
    do {
        let name = try GraphicsPixelProbe.stage(executable: source, drive: drive)
        let copied = try Data(contentsOf: drive.appendingPathComponent(name))
        lock.lock(); defer { lock.unlock() }
        if !paths.insert(name).inserted || copied != image { errors += 1 }
    } catch { lock.lock(); errors += 1; lock.unlock() }
}
assert(errors == 0 && paths.count == 25)
let sourceLink = root.appendingPathComponent("source-link.exe")
try fm.createSymbolicLink(at: sourceLink, withDestinationURL: source)
let driveLink = root.appendingPathComponent("drive-link")
try fm.createSymbolicLink(at: driveLink, withDestinationURL: drive)
func refuse(_ file: URL, _ parent: URL) {
    let before = try! fm.contentsOfDirectory(atPath: drive.path)
    do { _ = try GraphicsPixelProbe.stage(executable: file, drive: parent); assertionFailure("invalid staging accepted") }
    catch { }
    assert(try! fm.contentsOfDirectory(atPath: drive.path).count == before.count)
}
refuse(sourceLink, drive); refuse(source, driveLink)
refuse(source, root.appendingPathComponent("absent-drive"))
for kind in 0..<7 {
    var bad = image
    switch kind {
    case 0: bad[0] = 0
    case 1: bad[132] = 0x4c; bad[133] = 1
    case 2: bad[152] = 0x0b; bad[153] = 1
    case 3: bad[220] = 2
    case 4: bad[63] = 0xff
    case 5: bad = Data(repeating: 0, count: 20)
    default: bad = Data(repeating: 0, count: 4 * 1024 * 1024 + 1)
    }
    let file = root.appendingPathComponent("bad-\(kind).exe")
    try bad.write(to: file); refuse(file, drive)
}
assert(try! Data(contentsOf: canary) == Data("untouched existing game".utf8))
assert(try! Data(contentsOf: source) == image)
print("PASS production graphics staging: 25 distinct concurrent owned copies; exact bytes; symlink, absent-drive, wrong architecture/format/bounds rejection; existing prefix and bundled files unchanged; GPU not executed")
'''
with tempfile.TemporaryDirectory(prefix='madeira-graphics-stage-') as folder:
    work = Path(folder)
    source = work / 'main.swift'
    source.write_text((ROOT / 'app/Madeira/GraphicsPixelProbe.swift').read_text() + '\n' + fixture)
    if sys.platform == 'darwin':
        binary = work / 'probe-stage'
        subprocess.run([shutil.which('swiftc'), '-swift-version', '5', '-sanitize=address', str(source), '-o', str(binary)], check=True)
        command = [str(binary)]
    else:
        command = [swift, str(source)]
    subprocess.run(command, check=True, timeout=60)
content = (ROOT / 'app/Madeira/ContentView.swift').read_text()
start = content.index('    private func runGraphicsPixelProbe()')
end = content.index('    private func verifySteamFiles(', start)
entry = content[start:end]
assert 'mkdir(directory.path, mode_t(0o700)) == 0' in (ROOT / 'app/Madeira/GraphicsPixelProbe.swift').read_text()
assert entry.index('nativeSteamPreparationIdle()') < entry.index('GraphicsPixelProbe.stage(')
assert entry.index('jitReadyForLaunch(') < entry.index('GraphicsPixelProbe.stage(')
assert 'startLibraryEntry(entry, remember: false)' in entry
assert 'LibraryModel.sessionsThisRun' in entry and 'MADEIRA_ONE_SESSION_PER_RUN' in entry
assert 'WINEDLLOVERRIDES' not in entry and 'library.save' not in entry
ui = (ROOT / 'app/Madeira/Library.swift').read_text()
assert 'Button("Run D3D11 pixel test"' in ui
assert 'runGraphicsPixelProbe: runGraphicsPixelProbe' in content
assert (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text().count('GraphicsPixelProbe.swift in Sources') == 2
print('PASS normal Settings → Diagnostics launch uses real Library/JIT session, idle/restart guards, transient profile and genuine backend identity check')
