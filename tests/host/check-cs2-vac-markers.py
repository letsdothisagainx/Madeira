#!/usr/bin/env python3
"""Execute the production bounded user/input marker core without game hooks."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--require-swift', action='store_true')
args = p.parse_args()
source = ROOT / 'app/Madeira/CS2VACMarkers.swift'
core = source.read_text()
library = (ROOT / 'app/Madeira/Library.swift').read_text()
store = (ROOT / 'app/Madeira/LogStore.swift').read_text()
view = (ROOT / 'app/Madeira/ContentView.swift').read_text()
hardware = (ROOT / 'app/Madeira/HardwareInput.swift').read_text()
pad = (ROOT / 'app/Madeira/GamepadInput.swift').read_text()
padkbm = (ROOT / 'app/Madeira/PadKeyboardMouse.swift').read_text()
project = (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert 'CS2VACMarkers.swift in Sources' in project
assert 'CS2VACMarkers.shared.begin(appID: entry.steamAppID ?? dock?.id)' in library
assert 'CS2VACMarkers.shared.finish()' in library
assert 'CS2VACDiagnosticActions()' in library and 'SteamGameDiagnosticsExportButton()' in library
assert 'Begin VAC Test' in core and 'Mark VAC Error' in core
assert 'raw.contains("[cs2-launch-flags-v1] ")' in store
assert 'SteamGameDiagnostics.decode(raw)' in store and 'observeProcess(pid: pid)' in store
assert store.index('observeProcess(pid: pid)') < store.index('if suppressed { return }')
assert 'writer.async { fputs(line + "\\n", stderr) }' in core
assert 'guard lock.try() else { return }' in core
assert not any(x in core for x in ('URLSession', 'FileManager', 'winios_', 'task_for_pid', 'VirtualProtect'))
# Observations follow existing dispatches; no call receives coordinates, key
# values, text, controller packets, button identity or a device/account name.
assert view.index('winios_pointer(event.x, event.y, event.flags, event.data)') < view.index('CS2VACMarkers.shared.noteInput(.touch)')
for code in (view, hardware, pad, padkbm):
    calls = re.findall(r'CS2VACMarkers\.shared\.noteInput\(([^\n]+)\)', code)
    assert calls and all(x in ('.touch', '.pointer', '.keyboard', '.controller') for x in calls)
assert 'if !edges.down.isEmpty { CS2VACMarkers.shared.noteInput(.pointer) }' in hardware
assert 'if !edges.down.isEmpty { CS2VACMarkers.shared.noteInput(.keyboard) }' in hardware
assert 'let markerDown = markerPressed && !vacMarkerPressed[i]' in pad
assert 'winios_gamepad_set_state(Int32(i), &state)\n            if markerDown' in pad

swift = shutil.which('swiftc')
if not swift:
    assert not args.require_swift, 'Swift compiler required for production marker tests'
    print('PASS marker/UI/input wiring; production dual-clock/rate/concurrency core requires Swift CI')
    raise SystemExit(0)

code = r'''
import Foundation

final class Time: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 1000
    private var offset = -300
    func set(_ value: UInt64, offset: Int = -300) { lock.lock(); self.value = value; self.offset = offset; lock.unlock() }
    func now() -> CS2VACMarkers.Stamp {
        lock.lock(); defer { lock.unlock() }
        return .init(wall: Date(timeIntervalSince1970: 1_794_208_200.125), monotonicMS: value, offsetMinutes: offset)
    }
}
func fields(_ line: String) -> [String: String] {
    assert(line.hasPrefix("[cs2-user-marker-v1] "))
    return Dictionary(uniqueKeysWithValues: line.split(separator: " ").dropFirst().map {
        let pair = $0.split(separator: "=", omittingEmptySubsequences: false)
        assert(pair.count == 2); return (String(pair[0]), String(pair[1]))
    })
}
func rows(_ markers: CS2VACMarkers, _ kind: String) -> [[String: String]] {
    markers.lines().map(fields).filter { $0["kind"] == kind }
}
let time = Time(), recorder = CS2VACMarkers(clock: { time.now() })
for _ in 0..<100 { recorder.noteInput(.keyboard) }
assert(recorder.lines().isEmpty && !recorder.isCS2Context)
recorder.begin(appID: 42); recorder.noteInput(.pointer)
assert(recorder.lines().isEmpty)
assert(recorder.markError())
assert(rows(recorder, "error-reported").last!["app"] == "unmeasured")
assert(rows(recorder, "error-reported").last!["pid"] == "unmeasured")
recorder.begin(appID: 730)
let start = rows(recorder, "session-begin").last!
assert(start["context"] == "cs2-requested" && start["pid"] == "unmeasured" && start["session"] == "1")
let iso = ISO8601DateFormatter(); iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
assert(abs(iso.date(from: start["utc"]!)!.timeIntervalSince1970 - 1_794_208_200.125) < 0.002)
assert(start["utc-offset-min"] == "-300" && start["monotonic-ms"] == "1000")
let count = recorder.lines().count
for bad in ["../secret", "OPAQUE_TICKET_6a9c", "76561198000000000", "0000", "0x033c", ""] { recorder.observeProcess(pid: bad) }
assert(recorder.lines().count == count)
recorder.observeProcess(pid: "033C")
assert(rows(recorder, "process-observed").last!["pid"] == "033c")
assert(rows(recorder, "process-observed").last!["session"] == "1")
let firstProcess = recorder.lines().count
recorder.observeProcess(pid: "033c"); assert(recorder.lines().count == firstProcess)
recorder.noteInput(.touch); assert(rows(recorder, "input").isEmpty)
assert(recorder.beginTest())
DispatchQueue.concurrentPerform(iterations: 64) { _ in recorder.noteInput(.touch) }
assert(rows(recorder, "input").count == 1)
for i in 2...121 { time.set(UInt64(i) * 1000); recorder.noteInput(.controller) }
assert(rows(recorder, "input").count <= 128)
let beforeExpiry = rows(recorder, "input").count
time.set(121_001); recorder.noteInput(.keyboard)
assert(rows(recorder, "input").count == beforeExpiry)
time.set(200_000)
assert(recorder.beginTest()); recorder.noteInput(.pointer)
assert(rows(recorder, "input").last!["input"] == "pointer")
assert(recorder.markError())
let lastError = rows(recorder, "error-reported").last!
assert(lastError["utc-offset-min"] == "-300" && lastError["monotonic-ms"] == "200000")
assert(lastError["evidence"] == "user-report" && lastError["context"] == "cs2-observed")
assert(!recorder.markError())
time.set(201_001); recorder.noteInput(.touch)
assert(rows(recorder, "input").last!["monotonic-ms"] == "200000", "error must disarm input collection")
recorder.finish(); assert(!recorder.isCS2Context)
assert(rows(recorder, "session-end").last!["pid"] == "033c")
time.set(300_000); assert(recorder.beginTest())
let unknownInput = rows(recorder, "input").count
recorder.noteInput(.keyboard); assert(rows(recorder, "input").count == unknownInput)

let boundedTime = Time(), bounded = CS2VACMarkers(clock: { boundedTime.now() })
for i in 0..<4200 { boundedTime.set(UInt64(i) * 1001); _ = bounded.markError() }
assert(bounded.lines().count == 256)
let numbers = bounded.lines().map { UInt64(fields($0)["sequence"]!)! }
assert(numbers.last == 4096 && zip(numbers, numbers.dropFirst()).allSatisfy { $0.0 < $0.1 })
assert(!bounded.markError())
assert(!bounded.lines().joined().contains("OPAQUE_TICKET"))

// Regressions for bad wall/offset clocks: never fabricate a timestamp.
let invalid = CS2VACMarkers(clock: { .init(wall: Date(timeIntervalSince1970: .nan), monotonicMS: 1, offsetMinutes: 0) })
assert(!invalid.markError() && invalid.lines().isEmpty)
let invalidOffset = CS2VACMarkers(clock: { .init(wall: Date(), monotonicMS: 1, offsetMinutes: 1000) })
assert(!invalidOffset.beginTest())

// Actual trylock path: a metadata producer holding the diagnostic lock must
// not delay an input caller; no UI, file writer or game process is required.
let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
let blocker = CS2VACMarkers(clock: {
    entered.signal(); release.wait()
    return .init(wall: Date(), monotonicMS: 1, offsetMinutes: 0)
})
let lifetime = DispatchGroup(); lifetime.enter()
DispatchQueue.global().async { blocker.begin(appID: 730); lifetime.leave() }
assert(entered.wait(timeout: .now() + 3) == .success)
DispatchQueue.global().async { blocker.noteInput(.touch); done.signal() }
assert(done.wait(timeout: .now() + 1) == .success, "input waited on diagnostic producer")
release.signal(); assert(lifetime.wait(timeout: .now() + 3) == .success)
print("PASS production VAC markers: dual UTC/local/monotonic clocks, explicit user reports, typed input, opt-in120s/rate limit,256-row/4096-event bounds,64-way contention, nonblocking input and unknown/liveness provenance")
'''
with tempfile.TemporaryDirectory(prefix='madeira-cs2-vac-markers-') as folder:
    temporary = Path(folder)
    main = temporary / 'main.swift'; main.write_text(code)
    binary = temporary / 'test'
    subprocess.run([swift, '-swift-version', '5', '-sanitize=address', str(source), str(main), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
