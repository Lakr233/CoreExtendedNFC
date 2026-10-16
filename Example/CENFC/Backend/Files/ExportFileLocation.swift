import Foundation

/// Builds collision-free temporary file URLs for exported records.
///
/// Every export is written into its own directory named after the record ID,
/// so exporting several records that share a display name (two dumps of the
/// same card, two NDEF records called "Text") never overwrites an earlier file
/// that is still queued in the share sheet.
///
/// Exported files can hold personal data (passport DG1/DG2, card UIDs, transit
/// history), so they are written with complete file protection, removed as soon
/// as the share sheet closes (``remove(_:)``), and anything left behind by a
/// crash is purged at the next launch (``purgeAll()``).
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

    /// Writes an export file atomically with complete file protection.
    static func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    /// Removes the per-record export directories holding `urls`.
    ///
    /// Only directories directly inside ``rootDirectory`` are removed, so a URL
    /// that does not come from ``url(for:baseName:fallbackName:pathExtension:)``
    /// is left alone.
    static func remove(_ urls: [URL]) {
        let root = rootDirectory.standardizedFileURL.resolvingSymlinksInPath().path
        for url in urls {
            let directory = url.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath()
            guard directory.deletingLastPathComponent().path == root else { continue }
            try? FileManager.default.removeItem(at: directory)
        }
    }

    /// Removes every export file, including ones left behind when the app was
    /// terminated while a share sheet was open.
    static func purgeAll() {
        try? FileManager.default.removeItem(at: rootDirectory)
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
