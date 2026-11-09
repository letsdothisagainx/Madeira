import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Stages only Madeira's bundled, owned test executable. Every request gets an
/// exclusively created directory; no existing prefix file is adopted or replaced.
enum GraphicsPixelProbe {
    static let filename = "pixel-readback-x64.exe"
    enum Failure: LocalizedError {
        case unavailable, invalidImage, invalidDrive
        var errorDescription: String? {
            switch self {
            case .unavailable: return "This build's graphics test could not be prepared."
            case .invalidImage: return "This build's graphics test is not a valid x64 console executable."
            case .invalidDrive: return "The Wine drive is unavailable for the graphics test."
            }
        }
    }
    static func stage(executable: URL, drive: URL) throws -> String {
        let fm = FileManager.default
        guard executable.isFileURL, drive.isFileURL,
              let source = try? fm.attributesOfItem(atPath: executable.path),
              source[.type] as? FileAttributeType == .typeRegular,
              let count = source[.size] as? NSNumber, count.intValue >= 256, count.intValue <= 4 * 1024 * 1024
        else { throw Failure.unavailable }
        guard let parent = try? fm.attributesOfItem(atPath: drive.path),
              parent[.type] as? FileAttributeType == .typeDirectory
        else { throw Failure.invalidDrive }
        let bytes = try Data(contentsOf: executable)
        func u16(_ offset: Int) -> Int { Int(bytes[offset]) | Int(bytes[offset + 1]) << 8 }
        guard bytes.count == count.intValue, bytes.prefix(2) == Data([0x4d, 0x5a]) else { throw Failure.invalidImage }
        let pe = Int(bytes[60]) | Int(bytes[61]) << 8 | Int(bytes[62]) << 16 | Int(bytes[63]) << 24
        guard pe >= 64, pe <= bytes.count - 96, bytes[pe..<pe + 4] == Data([0x50, 0x45, 0, 0]),
              u16(pe + 4) == 0x8664, u16(pe + 24) == 0x20b, u16(pe + 24 + 68) == 3,
              bytes.range(of: Data("[d3d11-pixels]".utf8)) != nil,
              bytes.range(of: Data("DXMT device identity".utf8)) != nil
        else { throw Failure.invalidImage }
        let directoryName = "madeira-graphics-probe-" + UUID().uuidString.lowercased()
        let directory = drive.appendingPathComponent(directoryName, isDirectory: true)
        // POSIX mkdir proves this call created the directory: EEXIST refuses
        // existing directories and symlinks. Never adopt an unowned stage.
        guard mkdir(directory.path, mode_t(0o700)) == 0 else { throw Failure.unavailable }
        let target = directory.appendingPathComponent(filename)
        try bytes.write(to: target, options: .withoutOverwriting)
        return directoryName + "/" + filename
    }
}
