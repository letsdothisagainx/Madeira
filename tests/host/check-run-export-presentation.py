#!/usr/bin/env python3
"""Exercise the real export operation and verify the production UIKit wiring.

UIKit presentation itself is tested separately on an iOS simulator. This test
does not equate a completed ZIP helper with a displayed share interface.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
args = argparse.ArgumentParser()
args.add_argument('--require-swift', action='store_true')
options = args.parse_args()
source = (ROOT / 'app/Madeira/RunExportPresentation.swift').read_text()
wiring = (ROOT / 'app/Madeira/SteamGameDiagnostics.swift').read_text()
controls = (ROOT / 'app/Madeira/ContentView.swift').read_text()
project = (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert 'RunExportButton(export: {' in wiring and 'try await LogStore.shared.exportRunDiagnostics()' in wiring
assert 'catch RunDiagnostics.Failure.stage(_, let code)' in wiring
assert 'url = try await LogStore.shared.exportSteamGameDiagnostics()' in wiring
assert '.sheet(item: $export) { ActivitySheet(items: [$0.url]) }' in wiring
assert 'Label("Export Run", systemImage:' in source
assert 'static let shared = RunExportCoordinator()' in source
assert 'host.windowLevel = .alert + 1' in source
assert 'source?.window?.windowScene' in source and 'activeScenes.count == 1' in source
assert 'activity.viewIfLoaded?.window != nil' in source
completion = source[source.index('activity.completionWithItemsHandler = '):source.index('if let popover = ', source.index('activity.completionWithItemsHandler = '))]
assert completion.index('guard self.operation.acceptsCompletion(request: identity)') < completion.index('self.closePresentation()')
assert 'popover.sourceView = root.view' in source
assert 'previousKeyWindow.makeKey()' in source
assert 'UIApplication.shared.beginBackgroundTask(withName: "Madeira run export")' in source
assert 'UIApplication.shared.endBackgroundTask(identifier)' in source
assert 'defer { archiveLease.finish(request: identity) }' in source
assert 'self?.operation.expireArchive(request: identity)' in source
assert 'try Task.checkCancellation()' in source
producer = (ROOT / 'app/Madeira/LogStore.swift').read_text()
producer = producer[producer.index('    func exportRunDiagnostics()'):producer.index('    /// Keeps this session', producer.index('    func exportRunDiagnostics()'))]
assert 'DispatchQueue.global(qos: .utility).async' in producer
assert 'withTaskCancellationHandler' in producer and 'onCancel: { cancellation.cancel() }' in producer
assert 'RunExportPresentation.swift in Sources' in project
modal = controls.index('if let modal = rootViewController?.presentedViewController')
assert modal < controls.index('if library.enabled && library.current == nil { return nil }', modal)
assert 'modal.viewIfLoaded?.window === self' in controls[modal:modal + 250]
print('PASS actual Export Run action uses stable coordinator/native scene presentation; existing VAC action and ordinary game hit testing retained')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if options.require_swift:
        raise SystemExit('Swift compiler required for production export operation test')
    print('SKIP actual Swift operation execution: no compiler; UIKit simulator coverage remains separate')
    raise SystemExit(0)

main = r'''
import Foundation
@MainActor final class ButtonLifetime {
    let tap: () -> Void
    init(_ tap: @escaping () -> Void) { self.tap = tap }
}
final class CancellationObserved: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func cancel() { lock.lock(); value = true; lock.unlock() }
    var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return value }
}
@main struct Check {
    @MainActor static func wait(_ condition: () -> Bool) async {
        for _ in 0..<100_000 { if condition() { return }; await Task.yield() }
        preconditionFailure("export operation did not reach the expected state")
    }
    @MainActor static func main() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("madeira-export-presentation-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let zip = folder.appendingPathComponent("run.zip")
        // A genuine empty ZIP's end-of-central-directory record, not an app log.
        try Data([0x50,0x4b,0x05,0x06] + Array(repeating: UInt8(0), count: 18)).write(to: zip)
        let operation = RunExportOperation()
        var events = [String](), exportCalls = 0, presentations = [URL]()
        var pending: CheckedContinuation<URL, Error>?
        var error: RunExportOperation.Failure?
        operation.onFailure = { error = $0 }
        let exporter: () async throws -> URL = {
            exportCalls += 1
            return try await withCheckedThrowingContinuation { pending = $0 }
        }
        let presenter: (URL) async throws -> Void = {
            precondition(operation.phase == .presenting && operation.acceptsCompletion(request: operation.request))
            presentations.append($0)
        }
        var button: ButtonLifetime? = ButtonLifetime {
            precondition(operation.start(export: exporter, present: presenter, record: { events.append($0) }))
        }
        weak var oldButton = button
        button!.tap()
        precondition(operation.phase == .creating && events.count == 1 && events[0].contains("event=requested"))
        precondition(!operation.acceptsCompletion(request: operation.request))
        precondition(!operation.start(export: { preconditionFailure("duplicate export") }, present: presenter, record: { _ in }))
        button = nil
        precondition(oldButton == nil, "request must not retain a transient view")
        await wait { pending != nil }
        pending!.resume(returning: zip); pending = nil
        await wait { operation.phase == .sharing }
        precondition(operation.acceptsCompletion(request: operation.request))
        precondition(exportCalls == 1 && presentations == [zip] && operation.archive == zip)
        precondition(events.count == 3 && events[1].contains("event=archive-created") && events[2].contains("event=share-presented"))
        let oldRequest = operation.request
        operation.didPresent(request: oldRequest)
        precondition(events.count == 3, "native completion may not duplicate presentation events")
        operation.finish(request: oldRequest, completed: false, error: nil)
        precondition(operation.phase == .idle && operation.archive == nil && FileManager.default.fileExists(atPath: zip.path))
        precondition(!operation.acceptsCompletion(request: oldRequest))
        precondition(operation.start(export: { zip }, present: presenter, record: { events.append($0) }))
        await wait { operation.phase == .sharing }
        precondition(!operation.acceptsCompletion(request: oldRequest))
        operation.finish(request: oldRequest, completed: true, error: nil)
        precondition(operation.phase == .sharing, "a late callback must not close a new request")
        operation.finish(request: operation.request, completed: true, error: nil)
        precondition(operation.phase == .idle)
        precondition(operation.start(export: { throw NSError(domain: NSPOSIXErrorDomain, code: 28, userInfo: [NSFilePathErrorKey: "/private/token-do-not-export"]) }, present: presenter, record: { events.append($0) }))
        await wait { error != nil }
        precondition(error!.stage == .archive && error!.code == 28 && error!.message.contains("storage"))
        precondition(!events.joined().contains("token-do-not-export") && !error!.message.contains("private"))
        precondition(RunExportOperation.Failure(stage: .archive, domain: "archive", code: 640).message.contains("storage"))
        error = nil
        precondition(operation.start(export: { zip }, present: { _ in throw NSError(domain: "private.secret-token", code: 77, userInfo: [NSLocalizedDescriptionKey: "credential-do-not-export"]) }, record: { events.append($0) }))
        await wait { error != nil }
        precondition(error!.stage == .presentation && error!.domain == "export" && error!.code == 77)
        precondition(operation.archive == zip && !events.joined().contains("secret-token") && !events.joined().contains("credential"))
        let failedPhase = operation.phase
        precondition(!operation.acceptsCompletion(request: operation.request), "same-request callback after timeout/failure may not close a newer error alert")
        operation.finish(request: operation.request, completed: true, error: nil)
        precondition(operation.phase == failedPhase && operation.archive == zip)
        error = nil
        precondition(operation.start(export: { folder }, present: presenter, record: { events.append($0) }))
        await wait { error != nil }
        precondition(error!.stage == .archive && presentations.count == 2)
        error = nil
        precondition(operation.start(export: { zip }, present: { _ in
            precondition(operation.phase == .presenting && operation.acceptsCompletion(request: operation.request))
            operation.finish(request: operation.request, completed: false, error: nil)
        }, record: { events.append($0) }))
        await wait { operation.phase == .idle }
        precondition(operation.start(export: { zip }, present: { _ in
            operation.didPresent(request: operation.request)
            operation.finish(request: operation.request, completed: true, error: nil)
        }, record: { events.append($0) }))
        await wait { operation.phase == .idle }
        precondition(events.last!.contains("event=share-finished"), "presentation completion must not resurrect a closed sheet")
        // The same production lease used by UIKit must release exactly once,
        // including a provider expiring before acquisition returns its token.
        let lease = RunExportArchiveLease()
        var expiration: (() -> Void)?, releases = 0, expirations = 0
        lease.begin(request: 1, acquire: { expiration = $0; return { releases += 1 } }, expired: { expirations += 1 })
        lease.finish(request: 1); lease.finish(request: 1); expiration?()
        precondition(releases == 1 && expirations == 0)
        lease.begin(request: 2, acquire: { expiration = $0; return { releases += 1 } }, expired: { expirations += 1 })
        let oldExpiration = expiration
        expiration?(); expiration?(); lease.finish(request: 2)
        precondition(releases == 2 && expirations == 1)
        lease.begin(request: 3, acquire: { expiration = $0; return { releases += 1 } }, expired: { expirations += 1 })
        oldExpiration?(); lease.finish(request: 2)
        precondition(releases == 2 && expirations == 1, "stale expiration must not release the current lease")
        lease.finish(request: 3)
        lease.begin(request: 4, acquire: { expire in expire(); return { releases += 1 } }, expired: { expirations += 1 })
        lease.finish(request: 4)
        precondition(releases == 4 && expirations == 2)
        lease.begin(request: 5, acquire: { _ in nil }, expired: { preconditionFailure("no native lease expired") })
        lease.finish(request: 5)
        var expiryOrder = [String]()
        lease.begin(request: 6, acquire: { expiration = $0; return { expiryOrder.append("end") } },
                    expired: { expiryOrder.append("cancel") })
        expiration?(); lease.finish(request: 6)
        precondition(expiryOrder == ["cancel", "end"], "cancel the producer before iOS can suspend the released task")

        let expiring = RunExportOperation(), cancellation = CancellationObserved()
        var delayed: CheckedContinuation<URL, Error>?, expiryFailure: RunExportOperation.Failure?
        var expiryEvents = [String](), expiryPresentations = 0
        expiring.onFailure = { expiryFailure = $0 }
        precondition(expiring.start(export: {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { delayed = $0 }
            } onCancel: { cancellation.cancel() }
        }, present: { _ in expiryPresentations += 1 }, record: { expiryEvents.append($0) }))
        await wait { delayed != nil }
        let expiredRequest = expiring.request
        expiring.expireArchive(request: expiredRequest - 1)
        precondition(!cancellation.cancelled)
        expiring.expireArchive(request: expiredRequest)
        expiring.expireArchive(request: expiredRequest)
        precondition(cancellation.cancelled && expiring.phase == .creating)
        precondition(!expiring.start(export: { zip }, present: { _ in }, record: { _ in }),
                     "expired work must acknowledge cancellation before another worker starts")
        // A producer can finish despite cancellation. Its late valid file must
        // never open a sheet, and the existing file must not be destroyed.
        delayed!.resume(returning: zip); delayed = nil
        await wait { expiryFailure != nil }
        precondition(expiryFailure!.domain == "background" && expiryFailure!.stage == .archive)
        precondition(expiryFailure!.message.contains("iOS") && expiryPresentations == 0)
        precondition(FileManager.default.fileExists(atPath: zip.path))
        precondition(expiryEvents.filter { $0.contains("event=background-time-expired") }.count == 1)
        expiryFailure = nil
        precondition(expiring.start(export: { zip }, present: { _ in expiryPresentations += 1 }, record: { expiryEvents.append($0) }))
        expiring.expireArchive(request: expiredRequest)
        await wait { expiring.phase == .sharing }
        precondition(expiryFailure == nil && expiryPresentations == 1)
        expiring.expireArchive(request: expiring.request)
        precondition(expiring.phase == .sharing, "archive expiry does not cancel an active share extension")
        expiring.finish(completed: true, error: nil)
        print("PASS production archive background lifecycle: normal/error/expiration release exactly once, synchronous acquisition expiry, missing lease, stale callbacks, real Task cancellation propagation, late archive refusal and safe retry")
        print("PASS production export operation: actual action, transient button destruction, duplicate taps, delayed archive, ordered real presentation event, completion during presenting/sharing, retry, failed/idle/stale callback rejection and sanitized useful errors")
    }
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-run-export-ui-') as tmp:
    folder = Path(tmp)
    (folder / 'Check.swift').write_text(main)
    subprocess.run([swift, '-swift-version', '5', '-parse-as-library', str(ROOT / 'app/Madeira/RunExportPresentation.swift'),
                    str(folder / 'Check.swift'), '-o', str(folder / 'check')], check=True)
    subprocess.run([str(folder / 'check')], check=True)
    # This regression must reject a producer which finishes after cancellation
    # instead of treating a valid ZIP URL as authorization to open a late sheet.
    changed = source.replace('                try Task.checkCancellation()',
                             '                // Negative control: cancellation check removed', 1)
    assert changed != source
    (folder / 'NoCancellation.swift').write_text(changed)
    subprocess.run([swift, '-swift-version', '5', '-parse-as-library', str(folder / 'NoCancellation.swift'),
                    str(folder / 'Check.swift'), '-o', str(folder / 'no-cancellation')], check=True)
    rejected = subprocess.run([str(folder / 'no-cancellation')], capture_output=True, text=True, timeout=30)
    assert rejected.returncode != 0 and 'export operation did not reach the expected state' in rejected.stderr, rejected
    print('PASS negative control: removing the production post-export cancellation check reproduces the unsafe late-presentation regression')
