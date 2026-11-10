// SPDX-License-Identifier: GPL-3.0-or-later
// Isolated UI host. No Wine, Steam, game files or account data are loaded.
import Foundation
import SwiftUI
import UIKit

@MainActor
final class ExportHostState: ObservableObject {
    static let shared = ExportHostState()
    @Published var originGeneration = 0
    @Published var events: [String] = []
    @Published var gameActive = false
    private var controls: UIWindow?
    private var didStart = false
    private let evidenceName = "run-export-events-" + UUID().uuidString + ".txt"
    let baseline = ProcessInfo.processInfo.arguments.contains("--baseline-d6")
    let failArchive = ProcessInfo.processInfo.arguments.contains("--fail-archive")
    let dropOrigin = ProcessInfo.processInfo.arguments.contains("--drop-origin")

    func onAppear() {
        guard !didStart else { return }; didStart = true
        if ProcessInfo.processInfo.arguments.contains("--active-game") {
            Task {
                for _ in 0..<40 {
                    if let scene = activeScene() {
                        let window = UIWindow(windowScene: scene)
                        window.windowLevel = .normal + 101
                        window.backgroundColor = .clear
                        window.rootViewController = UIHostingController(rootView: ControlsHost())
                        controls = window; gameActive = true
                        window.makeKeyAndVisible()
                        return
                    }
                    try? await Task.sleep(nanoseconds: 50_000_000)
                }
                record("[fixture] event=scene-unavailable")
            }
        }
    }

    func activeScene() -> UIWindowScene? {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
    }

    var keyWindowName: String {
        guard let key = activeScene()?.windows.first(where: { $0.isKeyWindow }) else { return "none" }
        if key === controls { return "controls" }
        return key.windowLevel == .normal ? "library" : "native-modal"
    }

    func record(_ line: String) {
        events.append(line); events = Array(events.suffix(32))
        // File evidence comes from actual production callbacks, not assertions
        // that a presenter ought to have been invoked.
        if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let context = "[fixture-context] baseline=\(baseline ? 1 : 0) fail=\(failArchive ? 1 : 0) drop-origin=\(dropOrigin ? 1 : 0)"
            try? Data((context + "\n" + events.joined(separator: "\n") + "\n").utf8)
                .write(to: docs.appendingPathComponent(evidenceName), options: .atomic)
        }
        if line.contains("event=requested") || (baseline && line.contains("event=factory-requested")) {
            Task {
                try? await Task.sleep(nanoseconds: 100_000_000)
                originGeneration += 1
                if dropOrigin { endGame() }
            }
        }
    }

    func makeArchive() async throws -> URL {
        record("[fixture] event=factory-requested")
        try await Task.sleep(nanoseconds: 650_000_000)
        if failArchive {
            throw NSError(domain: NSCocoaErrorDomain, code: 640,
                          userInfo: [NSFilePathErrorKey: "/private/credential-canary/must-never-appear"])
        }
        let source = Bundle.main.url(forResource: "archive", withExtension: "base64")!
        let encoded = try String(contentsOf: source, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let archive = Data(base64Encoded: encoded) else { throw CocoaError(.fileReadCorruptFile) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("RunExportUI", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        let file = directory.appendingPathComponent("RunExportFixture.zip")
        try archive.write(to: file, options: .atomic)
        record("[fixture] event=factory-created bytes=\(archive.count)")
        return file
    }

    func endGame() {
        controls?.isHidden = true; controls?.rootViewController = nil; controls = nil
        gameActive = false
        activeScene()?.windows.first { !$0.isHidden && $0.windowLevel == .normal }?.makeKey()
    }
}

// The D6 view's only application dependency is the archive producer. Its task,
// state and sheet implementation remain literal production source in fixtures/.
@MainActor
final class LogStore {
    static let shared = LogStore()
    func exportRunDiagnostics() async throws -> URL { try await ExportHostState.shared.makeArchive() }
    func exportSteamGameDiagnostics() async throws -> URL { try await ExportHostState.shared.makeArchive() }
}

@MainActor
private struct ExportMenu: View {
    let controls: Bool
    @ObservedObject private var state = ExportHostState.shared
    var body: some View {
        Menu {
            if state.baseline {
                SteamGameDiagnosticsExportButton(run: true)
            } else {
                RunExportButton(export: { try await state.makeArchive() }, record: { state.record($0) })
            }
        } label: { Text("Session menu").padding() }
            .accessibilityIdentifier(controls ? "controls-menu" : "library-menu")
            .id(state.originGeneration)
    }
}

@MainActor
private struct Status: View {
    @ObservedObject private var state = ExportHostState.shared
    @ObservedObject private var coordinator = RunExportCoordinator.shared
    var body: some View {
        VStack {
            Text(state.gameActive ? "game-active" : "session-ended").accessibilityIdentifier("host.session")
            Text("key-window=\(state.keyWindowName)").accessibilityIdentifier("host.key-window")
            Text("origin-generation=\(state.originGeneration)").accessibilityIdentifier("host.origin")
            Text(state.events.joined(separator: "\n")).font(.caption2).lineLimit(8)
                .accessibilityIdentifier("host.events")
            Text(String(describing: coordinator.phase)).accessibilityIdentifier("host.phase")
        }
    }
}

@MainActor
private struct ControlsHost: View {
    @ObservedObject private var state = ExportHostState.shared
    var body: some View {
        VStack(spacing: 12) {
            Text("Owned game-controls window at normal + 101")
            ExportMenu(controls: true)
            Button("End session") { state.endGame() }.accessibilityIdentifier("end-controls")
            Status()
        }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Color.black).foregroundStyle(.white)
    }
}

@main
struct RunExportHostApp: App {
    var body: some Scene {
        WindowGroup {
            VStack(spacing: 12) {
                Text("Madeira Run Export UI Host")
                ExportMenu(controls: false)
                Status()
            }.padding().onAppear { ExportHostState.shared.onAppear() }
        }
    }
}
