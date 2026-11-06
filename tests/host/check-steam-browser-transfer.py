#!/usr/bin/env python3
"""Exercise production Swift transfer limits/delegate without network access.

The executable test requires macOS Swift/CryptoKit; --require-swift makes its
absence fail CI. Private access is supplied only by a same-file extension in a
temporary source copy. Production response/body validation is never replaced.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--require-swift", action="store_true")
args = parser.parse_args()
source = (root / "app/Madeira/SteamBrowserRuntime.swift").read_text()
delegate = source[source.index("private final class SteamBrowserDownload:"):]
progress = source[source.index("struct DownloadProgress:"):source.index("struct FileRecord:")]
assert "updates < 64" in progress and "15_000" in progress and "1_000" in progress
assert "heartbeat.schedule(deadline: .now() + 15, repeating: 15)" in delegate
assert "queue.maxConcurrentOperationCount = 1" in delegate
assert "queue.addOperation { [weak self] in self?.reportProgress() }" in delegate
assert "guard !finished else { return }" in delegate
assert "self.continuation = next; self.session = session; self.task = task" in delegate
assert "http.statusCode == 200" in delegate and "http.url == url" in delegate
assert "response.expectedContentLength == Int64(package.bytes)" in delegate
assert '== "identity"' in delegate and "data.count <= package.bytes - received" in delegate
assert "try handle.write(contentsOf: data)" in delegate
assert "try? FileManager.default.removeItem(at: temporary)" in delegate
assert "report(event(.response" in delegate and "report(event(.completed))" in delegate
assert "report(event(wasCancelled ? .cancelled : .failed" in delegate
diagnostic = source[source.index("func diagnostic(package:"):source.index("// Rate limiting is independent")]
assert all(term not in diagnostic for term in ("url", "header", "description", "package.file", "error"))
assert "AsyncStream<Files.DownloadEvent>.makeStream()" in source
assert "events.continuation.finish(); await observer.value" in source
assert "throw error" in source and "if let download" in source
assert "guard try hash(temporary) == package.sha256" in source
assert "try Files.appendArchive(archive, package: package" in source
assert source.index("guard try hash(temporary) == package.sha256") < source.index("try Files.appendArchive(archive, package: package")
print("PASS production transfer source: serialized heartbeat/events, strict response/body limits and unchanged post-transport verification")

swift = os.environ.get("SWIFTC") or shutil.which("swiftc")
if os.uname().sysname != "Darwin" or not swift:
    if args.require_swift:
        raise SystemExit("FAIL --require-swift: macOS Swift/CryptoKit execution required")
    print("SKIP executable Swift transfer tests: macOS Swift/CryptoKit required")
    raise SystemExit(0)

extension = r'''

// TEST COPY ONLY. The real delegate still creates/writes/closes/removes its
// own file and runs all original URL/status/length/encoding/body checks.
private final class TransferSpy: @unchecked Sendable {
    private let lock = NSLock()
    private var saved: [SteamBrowserRuntimeFiles.DownloadEvent] = []
    private var decision: URLSession.ResponseDisposition?
    private var rejectedRedirect = false
    func record(_ event: SteamBrowserRuntimeFiles.DownloadEvent) {
        lock.lock(); saved.append(event); lock.unlock()
    }
    var events: [SteamBrowserRuntimeFiles.DownloadEvent] {
        lock.lock(); defer { lock.unlock() }; return saved
    }
    func disposition(_ value: URLSession.ResponseDisposition) {
        lock.lock(); decision = value; lock.unlock()
    }
    var allowed: Bool {
        lock.lock(); defer { lock.unlock() }; return decision == .allow
    }
    func redirect(_ request: URLRequest?) {
        lock.lock(); rejectedRedirect = request == nil; lock.unlock()
    }
    var redirectWasRejected: Bool {
        lock.lock(); defer { lock.unlock() }; return rejectedRedirect
    }
}

extension SteamBrowserDownload {
    static func runTransferTests() throws {
        typealias Files = SteamBrowserRuntimeFiles
        let fm = FileManager.default
        let package = Files.Package(file: "madeira-transfer-test-fixture.zip", bytes: 8,
                                    sha256: String(repeating: "0", count: 64))
        var cases = 0
        func fixture(_ body: (SteamBrowserDownload, URLSession, URLSessionDataTask, TransferSpy) throws -> Void) throws {
            let spy = TransferSpy()
            let transfer = try SteamBrowserDownload(package, report: { spy.record($0) })
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil; configuration.urlCredentialStorage = nil
            configuration.urlCache = nil
            let session = URLSession(configuration: configuration)
            let task = session.dataTask(with: transfer.url)
            // The actual URLSession task is deliberately NEVER resumed.
            assert(task.state == .suspended)
            defer {
                task.cancel(); session.invalidateAndCancel()
                try? transfer.handle.close(); try? fm.removeItem(at: transfer.temporary)
            }
            try body(transfer, session, task, spy)
            cases += 1
        }
        func response(_ transfer: SteamBrowserDownload, status: Int = 200,
                      path: String? = nil, length: String? = "8", encoding: String? = "identity") -> HTTPURLResponse {
            var headers: [String: String] = [:]
            if let length { headers["Content-Length"] = length }
            if let encoding { headers["Content-Encoding"] = encoding }
            let url = path.map { URL(string: Files.origin + $0)! } ?? transfer.url
            return HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        }
        func accept(_ transfer: SteamBrowserDownload, _ session: URLSession,
                    _ task: URLSessionDataTask, _ spy: TransferSpy) {
            transfer.urlSession(session, dataTask: task, didReceive: response(transfer), completionHandler: { spy.disposition($0) })
            assert(spy.allowed && transfer.accepted)
            assert(spy.events.last?.phase == .response && spy.events.last?.code == 200)
        }
        func finished(_ transfer: SteamBrowserDownload, _ spy: TransferSpy, phase: Files.DownloadEvent.Phase) {
            assert(transfer.finished && spy.events.last?.phase == phase)
            let count = spy.events.count
            transfer.reportProgress() // A timer operation already queued at completion is harmless.
            assert(spy.events.count == count)
        }
        // Actual response/chunk/completion flow with a real FileHandle.
        try fixture { transfer, session, task, spy in
            transfer.report(transfer.event(.waiting))
            accept(transfer, session, task, spy)
            transfer.urlSession(session, dataTask: task, didReceive: Data([0,1,2]))
            transfer.urlSession(session, dataTask: task, didReceive: Data([3,4,5,6,7]))
            assert(transfer.received == 8)
            assert(try! Data(contentsOf: transfer.temporary) == Data([0,1,2,3,4,5,6,7]))
            transfer.urlSession(session, task: task, didCompleteWithError: nil)
            finished(transfer, spy, phase: .completed)
            assert(fm.fileExists(atPath: transfer.temporary.path))
            assert(spy.events.filter { $0.phase != .receiving }.map(\.phase) == [.waiting,.response,.completed])
            assert(spy.events.last?.received == 8 && spy.events.last?.expected == 8)
        }
        // Every response rejection uses the real original validator.
        let invalid: [(Files.Reason, Int, String?, String?, String?)] = [
            (.responseStatus, 503, nil, "8", "identity"),
            (.responseURL, 200, "different-test-fixture.zip", "8", "identity"),
            (.responseLength, 200, nil, "7", "identity"),
            (.responseLength, 200, nil, nil, "identity"),
            (.responseEncoding, 200, nil, "8", "gzip")
        ]
        for (reason,status,path,length,encoding) in invalid {
            try fixture { transfer, session, task, spy in
                transfer.urlSession(session, dataTask: task,
                    didReceive: response(transfer, status: status, path: path, length: length, encoding: encoding),
                    completionHandler: { spy.disposition($0) })
                assert(!spy.allowed && !transfer.accepted && transfer.received == 0)
                assert((transfer.failure as? Files.ValidationIssue)?.reason == reason)
                assert(try! Data(contentsOf: transfer.temporary).isEmpty)
                transfer.urlSession(session, task: task, didCompleteWithError: URLError(.cancelled))
                finished(transfer, spy, phase: .failed)
                assert(!fm.fileExists(atPath: transfer.temporary.path))
            }
        }
        try fixture { transfer, session, task, spy in
            let plain = URLResponse(url: transfer.url, mimeType: nil, expectedContentLength: 8, textEncodingName: nil)
            transfer.urlSession(session, dataTask: task, didReceive: plain, completionHandler: { spy.disposition($0) })
            assert(!spy.allowed && (transfer.failure as? Files.ValidationIssue)?.reason == .responseStatus)
            transfer.urlSession(session, task: task, didCompleteWithError: nil)
            finished(transfer, spy, phase: .failed)
            assert(!fm.fileExists(atPath: transfer.temporary.path))
        }
        try fixture { transfer, session, task, spy in
            transfer.urlSession(session, dataTask: task, didReceive: Data([1]))
            assert(!transfer.accepted && transfer.received == 0)
            assert((transfer.failure as? Files.ValidationIssue)?.reason == .bodyLength)
            assert(try! Data(contentsOf: transfer.temporary).isEmpty)
            transfer.urlSession(session, task: task, didCompleteWithError: nil)
            finished(transfer, spy, phase: .failed)
            assert(!fm.fileExists(atPath: transfer.temporary.path))
        }
        // An oversized chunk is not written, including after a valid prefix.
        try fixture { transfer, session, task, spy in
            accept(transfer, session, task, spy)
            transfer.urlSession(session, dataTask: task, didReceive: Data([1,2,3]))
            transfer.urlSession(session, dataTask: task, didReceive: Data(repeating: 9, count: 6))
            assert(transfer.received == 3 && (transfer.failure as? Files.ValidationIssue)?.reason == .bodyLength)
            assert(try! Data(contentsOf: transfer.temporary) == Data([1,2,3]))
            transfer.urlSession(session, task: task, didCompleteWithError: URLError(.cancelled))
            finished(transfer, spy, phase: .failed)
            assert(!fm.fileExists(atPath: transfer.temporary.path))
        }
        try fixture { transfer, session, task, spy in
            accept(transfer, session, task, spy)
            transfer.urlSession(session, dataTask: task, didReceive: Data([1,2,3]))
            transfer.urlSession(session, task: task, didCompleteWithError: nil)
            finished(transfer, spy, phase: .failed)
            assert(spy.events.last?.received == 3 && !fm.fileExists(atPath: transfer.temporary.path))
        }
        try fixture { transfer, session, task, spy in
            transfer.task = task
            transfer.cancel()
            transfer.urlSession(session, task: task, didCompleteWithError: URLError(.cancelled))
            finished(transfer, spy, phase: .cancelled)
            assert(!fm.fileExists(atPath: transfer.temporary.path))
        }
        // Arbitrary NSError metadata is never copied into transfer events.
        for code in [NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost,
                     NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost, NSURLErrorServerCertificateUntrusted] {
            try fixture { transfer, session, task, spy in
                let error = NSError(domain: NSURLErrorDomain, code: code, userInfo: [
                    NSLocalizedDescriptionKey: "password=DO-NOT-PRINT token=SECRET-TEST",
                    NSURLErrorFailingURLErrorKey: URL(string: "https://private-user:private-password@example.invalid/?credential=SECRET-TEST")!])
                transfer.urlSession(session, task: task, didCompleteWithError: error)
                finished(transfer, spy, phase: .failed)
                assert(spy.events.last?.code == code)
                assert(spy.events.last?.retryable == (code != NSURLErrorServerCertificateUntrusted))
                let text = spy.events.map { $0.diagnostic(package: 1, count: 3) }.joined()
                for privateValue in ["SECRET-TEST", "private-user", "private-password", "credential", "https://", transfer.temporary.path] {
                    assert(!text.contains(privateValue))
                }
                assert(!fm.fileExists(atPath: transfer.temporary.path))
            }
        }
        try fixture { transfer, session, task, spy in
            transfer.urlSession(session, task: task, willPerformHTTPRedirection: response(transfer, status: 302),
                newRequest: URLRequest(url: transfer.url), completionHandler: { spy.redirect($0) })
            assert(spy.redirectWasRejected)
            transfer.cancel()
            transfer.urlSession(session, task: task, didCompleteWithError: URLError(.cancelled))
            assert(!fm.fileExists(atPath: transfer.temporary.path))
        }
        print("PASS real production Swift download delegate: \(cases) closed fixtures, response/body validation, real file bytes, cancellation/error cleanup, terminal heartbeat guard and private NSError redaction; no task resumed")
    }
}

enum SteamBrowserTransferTest {
    static func run() throws {
        typealias Files = SteamBrowserRuntimeFiles
        var waiting = Files.DownloadProgress(), at: [Int] = []
        for ms in stride(from: 0, through: 40_000, by: 1_000) {
            if waiting.shouldReport(received: 0, expected: 130_079_979, elapsedMS: ms) { at.append(ms) }
        }
        assert(at == [15_000,30_000]) // The old downloader emitted neither heartbeat.
        var threshold = Files.DownloadProgress()
        assert(!threshold.shouldReport(received: 5, expected: 100, elapsedMS: 999))
        assert(threshold.shouldReport(received: 5, expected: 100, elapsedMS: 1_000))
        assert(!threshold.shouldReport(received: 10, expected: 100, elapsedMS: 1_999))
        assert(threshold.shouldReport(received: 10, expected: 100, elapsedMS: 2_000))
        assert(!threshold.shouldReport(received: 20, expected: 100, elapsedMS: 1_999))
        assert(!threshold.shouldReport(received: 10, expected: 100, elapsedMS: 3_000))
        assert(threshold.shouldReport(received: 10, expected: 100, elapsedMS: 17_000))
        var bounded = Files.DownloadProgress()
        for n in 1...64 { assert(bounded.shouldReport(received: 0, expected: 8, elapsedMS: n * 15_000)) }
        assert(bounded.updates == 64)
        for n in 65...128 { assert(!bounded.shouldReport(received: 8, expected: 8, elapsedMS: n * 15_000)) }
        var invalid = Files.DownloadProgress()
        assert(!invalid.shouldReport(received: -1, expected: 8, elapsedMS: 15_000))
        assert(!invalid.shouldReport(received: 9, expected: 8, elapsedMS: 15_000))
        assert(!invalid.shouldReport(received: 0, expected: 0, elapsedMS: 15_000))
        assert(!invalid.shouldReport(received: 0, expected: 8, elapsedMS: -1))
        // Extreme caller inputs must fail closed rather than overflow bucket math.
        assert(!invalid.shouldReport(received: Int.max, expected: Int.max, elapsedMS: 15_000))
        assert(invalid.updates == 0)
        let diagnostic = Files.DownloadEvent(.failed, received: 3, expected: 8, elapsedMS: 15,
            code: NSURLErrorTimedOut, retryable: true).diagnostic(package: 2, count: 3)
        assert(diagnostic == "[steam-browser-transfer-v1] package=2/3 phase=failed received=3 expected=8 elapsed-ms=15 code=-1001 retryable=1")
        try SteamBrowserDownload.runTransferTests()
        print("PASS production Swift progress limiter: forty-second waiting regression, 5%-per-second threshold, monotonic time, 64-update cap and numeric-only diagnostics")
    }
}
'''

with tempfile.TemporaryDirectory(prefix="madeira-browser-transfer-") as folder:
    directory = Path(folder)
    runtime = (root / "app/Madeira/SteamRuntime.swift").read_text()
    begin = runtime.index("enum SteamRuntimeFiles {")
    end = runtime.index("\n#if canImport(CryptoKit)", begin)
    (directory / "Files.swift").write_text("import Foundation\nimport zlib\n" + runtime[begin:end])
    (directory / "Browser.swift").write_text(source + extension)
    (directory / "main.swift").write_text("import Foundation\nimport CryptoKit\ntry SteamBrowserTransferTest.run()\n")
    binary = directory / "transfer"
    subprocess.run([swift, "-swift-version", "5", "-strict-concurrency=complete", "-warnings-as-errors",
                    str(directory / "Files.swift"), str(directory / "Browser.swift"),
                    str(directory / "main.swift"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
