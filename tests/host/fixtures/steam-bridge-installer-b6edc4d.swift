    static func installBridge(_ source: URL, manifest: BridgeManifest, drive: URL,
                              digest: DigestFile, idle: () -> Bool, report: (String) -> Void = { _ in }) throws {
        typealias Files = SteamBrowserRuntimeFiles
        let fm = FileManager.default
        try verify(source, fingerprint: manifest.fingerprint, digest: digest, report: report)
        let system = try Files.destination("windows/system32", under: drive)
        try Files.plain(system, directory: true)
        let target = try Files.destination("windows/system32/" + bridgeName, under: drive)
        let stamp = try Files.destination("windows/system32/" + stampName, under: drive)
        let hasTarget = fm.fileExists(atPath: target.path), hasStamp = fm.fileExists(atPath: stamp.path)
        var previous: Fingerprint?, previousStamp: Data?, state = "missing"
        if hasStamp {
            let (value, bytes) = try checkedStamp(stamp, report: report)
            previousStamp = bytes
            state = stampState(value)
            if hasTarget {
                trace(.existing, result: "begin", state: state, report: report)
                let count = try freshLength(target)
                guard count <= 32 * 1024 * 1024 else {
                    trace(.existing, result: "failed", reason: "size", observed: count, state: state, report: report)
                    throw Failure.ownership
                }
                let actualHash = try digest(target)
                guard let match = [value.installed, value.pending].compactMap({ $0 })
                    .first(where: { $0.bytes == count && actualHash == $0.sha256 }) else {
                    trace(.existing, result: "failed", reason: "ownership-fingerprint", observed: count, hash: "mismatch", state: state, report: report)
                    throw Failure.ownership
                }
                try verify(target, fingerprint: match, digest: digest, phase: .existing, state: state, report: report)
                previous = match
            } else {
                trace(.existing, result: "absent", reason: "pending-recovery", state: state, report: report)
            }
        } else if hasTarget {
            trace(.stamp, result: "absent", reason: "unowned-target", state: state, report: report)
            throw Failure.ownership
        } else {
            trace(.stamp, result: "absent", state: state, report: report)
            trace(.existing, result: "absent", state: state, report: report)
        }
        if previous == manifest.fingerprint, hasStamp {
            // Recover a completed copy whose final stamp write was interrupted.
            guard idle() else { throw Failure.active }
        } else {
            guard idle() else { throw Failure.active }
            trace(.pending, result: "begin", state: state, report: report)
            var backup: URL?
            if let previous {
                // Retain only a version proved by the existing ownership stamp.
                // This invocation creates the directory; no old/ambient backup
                // is adopted or overwritten. It remains available for diagnosis.
                let directory = system.appendingPathComponent(".madeira-bridge-previous-" + UUID().uuidString, isDirectory: true)
                try fm.createDirectory(at: directory, withIntermediateDirectories: false)
                let saved = directory.appendingPathComponent(bridgeName)
                try bounded(target, maximum: 32 * 1024 * 1024).write(to: saved, options: .withoutOverwriting)
                guard let previousStamp else { throw Failure.ownership }
                try previousStamp.write(to: directory.appendingPathComponent(stampName), options: .withoutOverwriting)
                try verify(saved, fingerprint: previous, digest: digest, phase: .pending, state: "previous-retained", report: report)
                backup = saved
            }
            let pending = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                                installed: previous, pending: manifest.fingerprint)
            let encoded = try JSONEncoder().encode(pending)
            try encoded.write(to: stamp, options: hasStamp ? .atomic : .withoutOverwriting)
            state = stampState(pending)
            trace(.pending, result: "written", observed: encoded.count, state: state, report: report)
            do {
                guard idle() else { throw Failure.active }
                if let previous { try verify(target, fingerprint: previous, digest: digest, phase: .existing, state: state, report: report) }
                else if fm.fileExists(atPath: target.path) { throw Failure.ownership }
                // Atomic write retains the established publication behavior.
                // Readback opens the NEW inode instead of reusing URL metadata.
                trace(.copy, result: "begin", expected: manifest.bytes, state: state, report: report)
                let image = try bounded(source, maximum: 32 * 1024 * 1024)
                try image.write(to: target, options: .atomic)
                trace(.copy, result: "written", expected: manifest.bytes, observed: image.count, state: state, report: report)
                try verify(target, fingerprint: manifest.fingerprint, digest: digest, phase: .readback, state: state, report: report)
                guard idle() else { throw Failure.active }
            } catch {
                // Restore only a still-owned published version. An unexpected
                // third-party/corrupted file is never overwritten on failure.
                if let backup, let previous, let previousStamp, idle(),
                   (try? verify(target, fingerprint: manifest.fingerprint, digest: digest)) != nil,
                   (try? verify(backup, fingerprint: previous, digest: digest)) != nil {
                    do {
                        try bounded(backup, maximum: 32 * 1024 * 1024).write(to: target, options: .atomic)
                        try verify(target, fingerprint: previous, digest: digest, phase: .readback, state: "rollback", report: report)
                        try previousStamp.write(to: stamp, options: .atomic)
                    } catch {
                        trace(.readback, result: "failed", reason: "rollback", state: state, report: report)
                    }
                }
                throw error
            }
        }
        guard idle() else { throw Failure.active }
        // Reuse/pending recovery also emits the mandatory installed readback.
        try verify(target, fingerprint: manifest.fingerprint, digest: digest, phase: .readback, state: state, report: report)
        let complete = Stamp(format: 1, owner: "org.madeira.NativeSteamBrowserBridge/v1", filename: bridgeName,
                             installed: manifest.fingerprint, pending: nil)
        try JSONEncoder().encode(complete).write(to: stamp, options: .atomic)
        trace(.pending, result: "completed", observed: manifest.bytes, hash: "match", machine: 0x8664, state: "installed", report: report)
    }
