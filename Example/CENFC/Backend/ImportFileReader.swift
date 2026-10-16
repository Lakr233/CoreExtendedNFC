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
    static func read(_ url: URL, limit: Int = maxFileSize) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        if let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > limit {
            throw ImportError.fileTooLarge(size: size, limit: limit)
        }
        // The size can change between the check and the read; never accept more than the limit.
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
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
}
