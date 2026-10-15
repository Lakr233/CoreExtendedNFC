import Foundation

/// Builds collision-free temporary file URLs for exported records.
///
/// Every export is written into its own directory named after the record ID,
/// so exporting several records that share a display name (two dumps of the
/// same card, two NDEF records called "Text") never overwrites an earlier file
/// that is still queued in the share sheet.
nonisolated enum ExportFileLocation {
    static let rootDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("cenfc-export", isDirectory: true)

    static func url(
        for id: UUID,
        baseName: String,
        fallbackName: String,
        pathExtension: String
    ) throws -> URL {
        let directory = rootDirectory.appendingPathComponent(id.uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let name = sanitized(baseName)
        return directory
            .appendingPathComponent(name.isEmpty ? fallbackName : name)
            .appendingPathExtension(pathExtension)
    }

    static func sanitized(_ name: String) -> String {
        var result = name
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: " ", with: "-")
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        // A leading dot would produce a hidden file.
        while result.hasPrefix(".") {
            result.removeFirst()
        }
        // APFS limits a file name to 255 UTF-8 bytes; leave room for the extension.
        while result.utf8.count > maxNameBytes {
            result.removeLast()
        }
        return result
    }

    /// Longest sanitized base name, in UTF-8 bytes.
    static let maxNameBytes = 200
}
