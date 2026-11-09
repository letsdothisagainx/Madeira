// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Observations never decide whether Steam, an installer or VAC is ready.
/// The job is asynchronous, runs once while idle, and may stop when Wine starts.
final class SteamIntegrityDiagnostics: @unchecked Sendable {
    typealias Idle = @Sendable () -> Bool
    typealias Work = @Sendable (Idle) -> [String]
    typealias Log = @Sendable (String) -> Void
    static let shared = SteamIntegrityDiagnostics()

    private let lock = NSLock()
    private var scheduled = false
    private var downloadActive = false

    /// Mirrors the actual download task lifetime, including cancellation waits.
    func setDownloadActive(_ active: Bool) {
        lock.lock(); downloadActive = active; lock.unlock()
    }

    /// This is a diagnostic switch, never a Steam identity or secure-mode flag.
    static func configureEnvironment(nativeSteam: Bool, appID: Int?,
                                     get: (String) -> String?, set: (String, String) -> Void,
                                     unset: (String) -> Void) {
        let name = "MADEIRA_TRUST_DIAGNOSTICS"
        guard nativeSteam, appID == 730 else { unset(name); return }
        set(name, get(name) == "0" ? "0" : "1")
    }

    @discardableResult
    func schedule(appID: Int, idle: @escaping Idle, work: @escaping Work,
                  log: @escaping Log, queue: DispatchQueue = .global(qos: .utility)) -> Bool {
        let canRun: Idle = {
            self.lock.lock(); let downloading = self.downloadActive; self.lock.unlock()
            return !downloading && idle()
        }
        guard appID == 730, canRun() else { return false }
        lock.lock()
        guard !scheduled else { lock.unlock(); return false }
        scheduled = true
        lock.unlock()
        queue.async {
            guard canRun() else {
                self.lock.lock(); self.scheduled = false; self.lock.unlock()
                log("[steam-content-audit-v1] app=730 phase=summary state=stopped-unmeasured reason=runtime-or-download-active trust=unmeasured")
                return
            }
            // The production audit checks idle again between bounded reads.
            // A partial or missing reference is an observation, never a gate.
            for line in work(canRun).prefix(32) { log(line) }
        }
        return true
    }
}
