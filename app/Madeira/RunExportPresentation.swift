import Foundation

/// Owns an export independently of the button/menu which requested it. UIKit
/// presentation is an explicit asynchronous boundary, not a button-local sheet.
@MainActor
final class RunExportOperation {
    enum Stage: String { case archive, presentation, activity }
    struct Failure: Error, Equatable {
        let stage: Stage
        let domain: String
        let code: Int
        var message: String {
            if domain == NSPOSIXErrorDomain && code == 28 || domain == NSCocoaErrorDomain && code == 640 ||
               domain == "archive" && (code == 28 || code == 640) {
                return "There is not enough free storage to export this run. Free some storage and try again."
            }
            switch stage {
            case .archive: return "Madeira could not create the run archive (\(domain), code \(code)). Your existing logs are unchanged. Try again with Madeira open."
            case .presentation: return "The run archive is ready, but its share interface could not open (code \(code)). Return to Madeira and tap Export Run again."
            case .activity: return "The sharing application reported an error (\(domain), code \(code)). The run archive remains available; try exporting again."
            }
        }
        static func capture(_ error: Error, at stage: Stage) -> Failure {
            let native = error as NSError
            let domain = [NSPOSIXErrorDomain, NSCocoaErrorDomain].contains(native.domain) ? native.domain : "export"
            return Failure(stage: stage, domain: domain, code: native.code)
        }
    }
    enum Phase: Equatable {
        case idle, creating, presenting, sharing, failed(Failure)
        var busy: Bool { self == .creating || self == .presenting || self == .sharing }
    }
    private(set) var phase: Phase = .idle { didSet { onPhase?(phase) } }
    private(set) var archive: URL?
    var onPhase: ((Phase) -> Void)?
    var onFailure: ((Failure) -> Void)?
    private var task: Task<Void, Never>?
    private(set) var request = 0
    private var record: (String) -> Void = { _ in }

    @discardableResult
    func start(export: @escaping () async throws -> URL,
               present: @escaping (URL) async throws -> Void,
               record: @escaping (String) -> Void) -> Bool {
        guard !phase.busy else { return false }
        request += 1
        let identity = request
        self.record = record
        archive = nil
        phase = .creating
        record("[run-export-v1] event=requested request=\(identity)")
        task = Task { [self] in
            var stage = Stage.archive
            do {
                let result = try await export()
                guard result.isFileURL else { throw Failure(stage: .archive, domain: "export", code: 1) }
                let properties = try result.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
                guard properties.isRegularFile == true,
                      properties.isSymbolicLink != true, let bytes = properties.fileSize, bytes >= 22,
                      FileManager.default.isReadableFile(atPath: result.path) else {
                    throw Failure(stage: .archive, domain: "export", code: 1)
                }
                archive = result
                record("[run-export-v1] event=archive-created request=\(identity) bytes=\(bytes)")
                phase = .presenting
                stage = .presentation
                try await present(result)
                // An activity can finish during UIKit's presentation callback.
                // Never resurrect it after the completion has reset the state.
                didPresent(request: identity)
            } catch {
                if identity == request { fail((error as? Failure) ?? Failure.capture(error, at: stage)) }
            }
            if identity == request { task = nil }
        }
        return true
    }

    func didPresent(request identity: Int? = nil) {
        guard identity == nil || identity == request else { return }
        guard phase == .presenting else { return }
        phase = .sharing
        record("[run-export-v1] event=share-presented request=\(request)")
    }

    func finish(request identity: Int? = nil, completed: Bool, error: Error?) {
        guard identity == nil || identity == request else { return }
        guard phase == .presenting || phase == .sharing else { return }
        if let error { fail(Failure.capture(error, at: .activity)); return }
        record("[run-export-v1] event=share-finished request=\(request) completed=\(completed ? 1 : 0)")
        // The file remains on disk for asynchronous Files/share extensions.
        archive = nil
        phase = .idle
    }

    private func fail(_ failure: Failure) {
        phase = .failed(failure)
        record("[run-export-v1] event=failed request=\(request) stage=\(failure.stage.rawValue) domain=\(failure.domain) code=\(failure.code)")
        onFailure?(failure)
    }
}

#if canImport(UIKit) && canImport(SwiftUI)
import UIKit
import SwiftUI

/// A native presentation surface above both the Metal surface and the controls
/// window. It is retained until the activity finishes, even if the game/menu
/// disappears while the archive is being produced.
@MainActor
final class RunExportCoordinator: ObservableObject {
    static let shared = RunExportCoordinator()
    @Published private(set) var phase = RunExportOperation.Phase.idle
    let operation = RunExportOperation()
    private var window: UIWindow?
    private weak var previousKeyWindow: UIWindow?
    private weak var scene: UIWindowScene?
    private var presentationTimeout: Task<Void, Never>?

    init() {
        operation.onPhase = { [weak self] phase in self?.phase = phase }
        operation.onFailure = { [weak self] failure in self?.showFailure(failure) }
    }

    func request(from source: UIView?, export: @escaping () async throws -> URL,
                 record: @escaping (String) -> Void) {
        guard !phase.busy else { return }
        // Capture the source scene synchronously, before the menu can disappear.
        let activeScenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .filter { $0.activationState == .foregroundActive }
        scene = source?.window?.windowScene
        // A Menu may not materialize its background anchor. A single active
        // scene is unambiguous; never send an archive to an arbitrary scene.
        if scene == nil, activeScenes.count == 1 { scene = activeScenes[0] }
        operation.start(export: export, present: { [self] url in try await present(url) }, record: record)
    }

    private func presentationRoot() throws -> UIViewController {
        guard let scene, scene.activationState == .foregroundActive else {
            throw RunExportOperation.Failure(stage: .presentation, domain: "export", code: 2)
        }
        if let root = window?.rootViewController { return root }
        previousKeyWindow = scene.windows.first { $0.isKeyWindow }
        let host = UIWindow(windowScene: scene)
        host.windowLevel = .alert + 1
        host.backgroundColor = .clear
        let root = RunExportRootController()
        host.rootViewController = root
        window = host
        host.makeKeyAndVisible()
        root.loadViewIfNeeded()
        host.layoutIfNeeded()
        return root
    }

    private func present(_ url: URL) async throws {
        let root = try presentationRoot()
        let identity = operation.request
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var replied = false
            func reply(_ result: Result<Void, Error>) {
                guard !replied else { return }
                replied = true
                presentationTimeout?.cancel(); presentationTimeout = nil
                continuation.resume(with: result)
            }
            let activity = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            activity.completionWithItemsHandler = { [weak self] _, completed, _, error in
                Task { @MainActor in
                    guard let self else { return }
                    reply(.success(()))
                    guard self.operation.request == identity else { return }
                    self.operation.didPresent(request: identity)
                    self.closePresentation()
                    self.operation.finish(request: identity, completed: completed, error: error)
                }
            }
            if let popover = activity.popoverPresentationController {
                popover.sourceView = root.view
                popover.sourceRect = CGRect(x: root.view.bounds.midX, y: root.view.bounds.midY, width: 1, height: 1)
                popover.permittedArrowDirections = []
            }
            presentationTimeout = Task { [weak self] in
                try? await Task.sleep(for: .seconds(15))
                guard !Task.isCancelled, self != nil else { return }
                reply(.failure(RunExportOperation.Failure(stage: .presentation, domain: "export", code: 3)))
            }
            // A newly visible UIWindow needs one UIKit turn before presentation.
            DispatchQueue.main.async { [weak self] in
                guard let self, let window = self.window, !window.isHidden,
                      root.view.window === window, self.scene?.activationState == .foregroundActive else {
                    reply(.failure(RunExportOperation.Failure(stage: .presentation, domain: "export", code: 4)))
                    return
                }
                root.present(activity, animated: true) {
                    guard activity.presentingViewController != nil, activity.viewIfLoaded?.window != nil else {
                        reply(.failure(RunExportOperation.Failure(stage: .presentation, domain: "export", code: 5)))
                        return
                    }
                    self.operation.didPresent(request: identity)
                    reply(.success(()))
                }
            }
        }
    }

    private func showFailure(_ failure: RunExportOperation.Failure) {
        closePresentation()
        guard let root = try? presentationRoot() else { return }
        let alert = UIAlertController(title: "Run export failed", message: failure.message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in self?.closePresentation() })
        DispatchQueue.main.async { root.present(alert, animated: true) }
    }

    private func closePresentation() {
        presentationTimeout?.cancel(); presentationTimeout = nil
        window?.isHidden = true
        window?.rootViewController = nil
        window = nil
        if let previousKeyWindow, !previousKeyWindow.isHidden { previousKeyWindow.makeKey() }
        else if let fallback = scene?.windows.first(where: { !$0.isHidden && $0.windowLevel == .normal && $0.rootViewController != nil }) {
            fallback.makeKey()
        }
        previousKeyWindow = nil
    }
}

private final class RunExportRootController: UIViewController {
    override func loadView() { view = UIView(); view.backgroundColor = .clear }
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .allButUpsideDown }
}

private final class RunExportSource {
    weak var view: UIView?
}

private struct RunExportAnchor: UIViewRepresentable {
    let source: RunExportSource
    func makeUIView(context: Context) -> UIView {
        let view = UIView(); view.isUserInteractionEnabled = false; source.view = view; return view
    }
    func updateUIView(_ view: UIView, context: Context) { source.view = view }
}

struct RunExportButton: View {
    @ObservedObject private var coordinator = RunExportCoordinator.shared
    @State private var source = RunExportSource()
    let export: () async throws -> URL
    let record: (String) -> Void
    var body: some View {
        Button {
            coordinator.request(from: source.view, export: export, record: record)
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Label("Export Run", systemImage: "square.and.arrow.up")
                    if coordinator.phase.busy { Spacer(); ProgressView() }
                }
                if case .failed(let failure) = coordinator.phase {
                    Text(failure.message).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .background(RunExportAnchor(source: source).frame(width: 0, height: 0))
        .disabled(coordinator.phase.busy)
        .accessibilityIdentifier("madeira.export-run")
    }
}
#endif
