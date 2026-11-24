// Type-only boundary for the standalone iOS SDK check. Real implementations
// and native symbols are linked/verified by the full app package build.
import Foundation
enum SteamGameDiagnostics {
    static func openOwned(_ root: Int32, _ parts: [String]) -> Int32? { nil }
}

@MainActor final class SteamLibraryDiagnostics {static let shared=SteamLibraryDiagnostics();func launchAttention(){}}
