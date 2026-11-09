// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Madeira contributors
// Madeira Converter Exception: see LICENSE-EXCEPTION.md
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// User/host observations only. No game/security callback is invoked. Input
/// timing is opt-in, coarse, bounded and recorded after normal dispatch.
final class CS2VACMarkers: @unchecked Sendable {
    enum Input: String { case touch, pointer, keyboard, controller }
    struct Stamp {
        var wall: Date
        var monotonicMS: UInt64
        var offsetMinutes: Int
    }
    typealias Clock = () -> Stamp
    typealias Emit = (String) -> Void
    private static let writer = DispatchQueue(label: "madeira.cs2-vac-marker-log", qos: .utility)
    static let shared = CS2VACMarkers(emit: { line in
        // Logging must never wait for a file/pipe on the game's input path.
        writer.async { fputs(line + "\n", stderr) }
    })
    static func snapshotLines() -> [String] { shared.lines() }

    private enum Context: String { case unmeasured, requested = "cs2-requested", observed = "cs2-observed" }
    private enum Kind: String { case begin = "session-begin", end = "session-end", process = "process-observed", test = "test-begin", error = "error-reported", input }
    private let lock = NSLock()
    private let clock: Clock
    private let emit: Emit
    private let formatter: DateFormatter
    private var context = Context.unmeasured
    private var pid: String?
    private var session: UInt64 = 0
    private var sequence: UInt64 = 0
    private var rows: [String] = []
    private var lastInput: UInt64?
    private var inputCount = 0
    private var armedUntil: UInt64?
    private var lastUser: [Kind: UInt64] = [:]

    init(clock: @escaping Clock = {
        let now = Date()
        return Stamp(wall: now, monotonicMS: DispatchTime.now().uptimeNanoseconds / 1_000_000,
                     offsetMinutes: TimeZone.current.secondsFromGMT(for: now) / 60)
    }, emit: @escaping Emit = { _ in }) {
        self.clock = clock; self.emit = emit
        formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    }

    var isCS2Context: Bool {
        lock.lock(); defer { lock.unlock() }
        return context != .unmeasured
    }
    func lines() -> [String] { lock.lock(); defer { lock.unlock() }; return rows }

    func begin(appID: Int?) {
        lock.lock()
        context = appID == 730 ? .requested : .unmeasured; pid = nil
        armedUntil = nil; lastInput = nil; inputCount = 0
        if context != .unmeasured && session < 4096 { session += 1 }
        let line = context == .unmeasured ? nil : make(.begin, source: "library", evidence: "library-lifecycle")
        lock.unlock()
        if let line { emit(line) }
    }
    func finish() {
        lock.lock()
        let line = context == .unmeasured ? nil : make(.end, source: "library", evidence: "library-lifecycle")
        context = .unmeasured; pid = nil; armedUntil = nil
        lock.unlock()
        if let line { emit(line) }
    }
    /// Only called after the existing decoder accepts a native CS2 launch
    /// record. PID is the last observation, never proof of current liveness.
    func observeProcess(pid value: String) {
        guard (4...8).contains(value.utf8.count), value.utf8.allSatisfy({
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }), let number = UInt32(value, radix: 16), number != 0 else { return }
        let value = value.lowercased()
        lock.lock()
        guard context != .observed || pid != value else { lock.unlock(); return }
        if context != .requested && session < 4096 { session += 1 }
        context = .observed; pid = value
        armedUntil = nil; lastInput = nil; inputCount = 0
        let line = make(.process, source: "runtime", evidence: "accepted-process-observation")
        lock.unlock()
        if let line { emit(line) }
    }
    @discardableResult func beginTest() -> Bool { user(.test) }
    @discardableResult func markError() -> Bool { user(.error) }

    private func user(_ kind: Kind) -> Bool {
        lock.lock()
        let stamp = clock()
        if let last = lastUser[kind], stamp.monotonicMS < last || stamp.monotonicMS - last < 1000 {
            lock.unlock(); return false
        }
        let line = make(kind, source: "user", evidence: "user-report", stamp: stamp)
        if line != nil {
            lastUser[kind] = stamp.monotonicMS
            if kind == .test {
                armedUntil = stamp.monotonicMS <= UInt64.max - 120_000 ? stamp.monotonicMS + 120_000 : nil
                lastInput = nil; inputCount = 0
            } else { armedUntil = nil }
        }
        lock.unlock()
        if let line { emit(line); return true }
        return false
    }
    func noteInput(_ input: Input) {
        // Never wait on a diagnostic lock before the next input event.
        guard lock.try() else { return }
        guard context != .unmeasured, let until = armedUntil, inputCount < 128 else { lock.unlock(); return }
        let stamp = clock(), now = stamp.monotonicMS
        guard now <= until else { armedUntil = nil; lock.unlock(); return }
        if let last = lastInput, now < last || now - last < 1000 { lock.unlock(); return }
        let line = make(.input, source: "input-layer", input: input.rawValue, evidence: "input-dispatch", stamp: stamp)
        if line != nil { lastInput = now; inputCount += 1 }
        lock.unlock()
        if let line { emit(line) }
    }

    /// All arguments are finite closed enums/literals, never text, coordinates,
    /// device names or values from a keyboard/controller packet.
    private func make(_ kind: Kind, source: String, input: String = "none", evidence: String, stamp: Stamp? = nil) -> String? {
        guard sequence < 4096 else { return nil }
        let stamp = stamp ?? clock(), seconds = stamp.wall.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0, seconds < 7_258_118_400,
              (-840...840).contains(stamp.offsetMinutes) else { return nil }
        sequence += 1
        let line = "[cs2-user-marker-v1] kind=\(kind.rawValue) source=\(source) input=\(input) app=\(context == .unmeasured ? "unmeasured" : "730") context=\(context.rawValue) pid=\(pid ?? "unmeasured") session=\(session) sequence=\(sequence) utc=\(formatter.string(from: stamp.wall)) utc-offset-min=\(stamp.offsetMinutes) monotonic-ms=\(stamp.monotonicMS) evidence=\(evidence)"
        rows.append(line)
        if rows.count > 256 { rows.removeFirst(rows.count - 256) }
        return line
    }
}

#if canImport(SwiftUI) && canImport(UIKit)
import SwiftUI
import UIKit

struct CS2VACDiagnosticActions: View {
    @State private var feedback: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button("Begin VAC Test", systemImage: "clock.badge.checkmark") {
                feedback = CS2VACMarkers.shared.beginTest()
                    ? "Test timestamp recorded. Return to CS2 and press Play. Coarse input timing is captured for two minutes."
                    : "A timestamp could not be recorded. Wait a moment and try again."
            }
            Button("Mark VAC Error", systemImage: "flag") {
                feedback = CS2VACMarkers.shared.markError()
                    ? "VAC dialog reported now. Export CS2 VAC Diagnostics to share this timestamp."
                    : "A timestamp could not be recorded. Wait a moment and try again."
            }
            Text("Marks when you report the dialog, not when the game detected it. No keys, text or pointer coordinates are recorded.")
                .font(.caption).foregroundStyle(.secondary)
            if let feedback { Text(feedback).font(.caption).foregroundStyle(.secondary) }
        }
    }
}
#endif
