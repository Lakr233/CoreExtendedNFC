import Foundation

/// Reads files the user imports (document picker, "Open in", AirDrop).
///
/// The size is checked before anything is read, so a huge or hostile file is
/// refused without loading it into memory. Exported records are small (a
/// passport record with a face image is well under 1 MB), so the cap leaves a
/// wide margin.
nonisolated enum ImportFileReader {
    /// Largest file accepted for import, in bytes.
    static let maxFileSize = 50 * 1024 * 1024

    enum ImportError: LocalizedError, Equatable {
        case fileTooLarge(size: Int, limit: Int)

        var errorDescription: String? {
            switch self {
            case let .fileTooLarge(size, limit):
                let formatter = ByteCountFormatter()
                formatter.countStyle = .file
                let sizeText = formatter.string(fromByteCount: Int64(size))
                let limitText = formatter.string(fromByteCount: Int64(limit))
                return String(localized: "The file is too large to import (\(sizeText); the limit is \(limitText)).")
            }
        }
    }

    /// Reads `url`, refusing files larger than `limit` before reading them.
    ///
    /// Blocks on disk I/O; call it off the main thread (``readInBackground(_:limit:)``).
    ///
    /// With `consumingInboxCopy`, a file the system copied into `Documents/Inbox`
    /// (AirDrop, Mail, "Open in") is deleted once read, whether or not the
    /// read succeeds: it can hold passport data and would otherwise stay in the
    /// app's Documents directory and its backups.
    static func read(_ url: URL, limit: Int = maxFileSize, consumingInboxCopy: Bool = true) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing {
                url.stopAccessingSecurityScopedResource()
            }
            if consumingInboxCopy {
                removeIfInInbox(url)
            }
        }
        if let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > limit {
            throw ImportError.fileTooLarge(size: size, limit: limit)
        }
        // An Inbox copy is deleted right after this read, so do not map it.
        let options: Data.ReadingOptions = consumingInboxCopy && isInInbox(url) ? [] : .mappedIfSafe
        // The size can change between the check and the read; never accept more than the limit.
        let data = try Data(contentsOf: url, options: options)
        guard data.count <= limit else {
            throw ImportError.fileTooLarge(size: data.count, limit: limit)
        }
        return data
    }

    /// Reads `url` and decodes it with `decode` on a background thread.
    static func readInBackground<Value: Sendable>(
        _ url: URL,
        limit: Int = maxFileSize,
        decode: @escaping @Sendable (Data) throws -> Value
    ) async throws -> Value {
        try await Task.detached(priority: .userInitiated) {
            try decode(read(url, limit: limit))
        }.value
    }

    // MARK: - Inbox

    /// Where the system copies files handed to the app by AirDrop, Mail and
    /// "Open in" when they cannot be opened in place.
    static var inboxDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Inbox", isDirectory: true)
    }

    /// Whether `url` is a file inside `inbox`.
    static func isInInbox(_ url: URL, inbox: URL = inboxDirectory) -> Bool {
        guard url.isFileURL else { return false }
        let root = inbox.standardizedFileURL.resolvingSymlinksInPath().path
        let path = url.standardizedFileURL.resolvingSymlinksInPath().path
        return path.hasPrefix(root + "/")
    }

    /// Deletes `url` when it is an Inbox copy; any other file (one opened in
    /// place, or picked from Files) is left alone.
    /// - Returns: Whether the file was removed.
    @discardableResult
    static func removeIfInInbox(_ url: URL, inbox: URL = inboxDirectory) -> Bool {
        guard isInInbox(url, inbox: inbox) else { return false }
        return (try? FileManager.default.removeItem(at: url)) != nil
    }

    /// Deletes everything in the Inbox, including copies left by an import that
    /// never finished (the app was terminated, or the file was never routed).
    ///
    /// Files in `keeping` (the ones the app was just launched to open) are left
    /// for their import, which deletes them.
    static func purgeInbox(_ inbox: URL = inboxDirectory, keeping: [URL] = []) {
        let kept = Set(keeping.map { $0.standardizedFileURL.resolvingSymlinksInPath().path })
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: inbox,
            includingPropertiesForKeys: nil
        )) ?? []
        for item in contents where !kept.contains(item.standardizedFileURL.resolvingSymlinksInPath().path) {
            try? FileManager.default.removeItem(at: item)
        }
    }
}
