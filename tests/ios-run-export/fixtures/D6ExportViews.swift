// SPDX-License-Identifier: GPL-3.0-or-later
// Literal production UI from d6d40213695db7b1ab0f7a9b1dd95edbcda0d7ec; no changes inside either view.
import SwiftUI
import UIKit

struct SteamGameDiagnosticsExportButton: View {
    private let run: Bool
    init(run: Bool = false) { self.run = run }
    private struct Export: Identifiable { let id = UUID(); let url: URL }
    @State private var preparing = false
    @State private var export: Export?
    @State private var failed = false
    var body: some View {
        Button {
            preparing = true
            Task {
                do {
                    let url: URL
                    if run { url = try await LogStore.shared.exportRunDiagnostics() }
                    else { url = try await LogStore.shared.exportSteamGameDiagnostics() }
                    export = Export(url: url)
                }
                catch { failed = true }
                preparing = false
            }
        } label: {
            HStack {
                Label(run ? "Export Run Diagnostics" : "Export CS2 VAC Diagnostics", systemImage: "square.and.arrow.up")
                if preparing { Spacer(); ProgressView() }
            }
        }
        .disabled(preparing)
        .sheet(item: $export) { ActivitySheet(items: [$0.url]) }
        .alert("Diagnostics unavailable", isPresented: $failed) {
            Button("OK", role: .cancel) { }
        } message: { Text("The diagnostic package could not be prepared. Your existing logs and game files are unchanged.") }
    }
}

struct ActivitySheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
