#!/usr/bin/env python3
"""Compile the production app clock and its native-epoch handoff on Apple CI."""
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
source = (ROOT / 'app/Madeira/SteamNativeBrowserLaunch.swift').read_text()
start = source.index('final class SteamStartupClock:')
clock = source[start:source.index('\nenum SteamNativeBrowserLaunchFiles', start)]
view = (ROOT / 'app/Madeira/ContentView.swift').read_text()
for marker in ('.requested)', '.launcherReady)', '.jitGate)', '.jitReady)',
               '.wineserverStart)', '.wineStart)'):
    assert 'SteamStartupClock.shared.mark(' + marker in view
for marker in ('.browserBegin)', '.browserCacheBegin)', '.browserCacheReady)',
               '.browserBridgeReady)', '.browserReady)'):
    assert 'SteamStartupClock.shared.mark(' + marker in source
assert 'MADEIRA_STARTUP_T0_NS' in (ROOT / 'build/ntdll-unix/steam_startup_timeline.h').read_text()
if not shutil.which('swiftc'):
    assert not args.require_swift, 'Apple Swift compiler is required'
    print('PASS app/native clock integration; actual Swift execution requires Apple CI')
    raise SystemExit(0)

code = '''import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
''' + clock + r'''
@main struct Check {
    static func main() {
        let line = SteamStartupClock.line(.wineStart, epoch: 1_000_000_000,
            previous: 392_800_000_000, previousPhase: "wineserver-start", now: 398_400_000_000)!
        assert(line.contains("t-ms=397400") && line.contains("interval-ms=5600"))
        assert(line.contains("accounting=observed-boundaries-not-cpu"))
        assert(SteamStartupClock.line(.failed, epoch: 2, previous: 2, previousPhase: "none", now: 1) == nil)
        assert(SteamStartupClock.line(.failed, epoch: 1, previous: 3, previousPhase: "none", now: 2) == nil)
        assert(SteamStartupClock.line(.failed, epoch: 1, previous: 1, previousPhase: "/private/token", now: 2) == nil)
        let timer = SteamStartupClock()
        timer.reset()
        var records: [String] = []
        let begin = SteamStartupClock.nowNS()
        timer.mark(.requested) { records.append($0) }
        let exported = getenv("MADEIRA_STARTUP_T0_NS").flatMap { UInt64(String(cString: $0)) }!
        assert(exported >= begin && exported <= SteamStartupClock.nowNS())
        timer.mark(.jitGate) { records.append($0) }
        timer.mark(.jitReady) { records.append($0) }
        assert(records.count == 3 && records[1].contains("previous=requested"))
        assert(UInt64(String(cString: getenv("MADEIRA_STARTUP_T0_NS"))) == exported)
        final class Output: @unchecked Sendable {
            let lock = NSLock()
            var records: [String] = []
            func append(_ line: String) { lock.lock(); records.append(line); lock.unlock() }
        }
        let output = Output()
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in
            timer.mark(.browserReady) { output.append($0) }
        }
        assert(output.records.count <= 61)
        assert(output.records.allSatisfy { !$0.contains("/private/") && !$0.contains("token=") })
        timer.reset()
        assert(getenv("MADEIRA_STARTUP_T0_NS") == nil)
        timer.mark(.requested) { assert($0.contains("previous=none") && $0.contains("t-ms=0")) }
        timer.reset()
        print("PASS production app monotonic timeline: real native epoch, exact397400ms fixture, no clock underflow, bounded concurrent output, retry reset, fixed phases and no private clock/path export")
    }
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-startup-clock-') as directory:
    path = Path(directory)
    program = path / 'clock.swift'
    program.write_text(code)
    executable = path / 'clock'
    subprocess.run(['swiftc', '-parse-as-library', '-swift-version', '5', str(program),
                    '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
