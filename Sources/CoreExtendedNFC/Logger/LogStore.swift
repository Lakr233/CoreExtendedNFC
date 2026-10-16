import Foundation

public final class LogStore: @unchecked Sendable {
    public static let shared = LogStore()

    let queue: DispatchQueue
    let fileManager: FileManager
    let maxFileSize: Int
    let maxFiles: Int
    let logDirectory: URL
    let logFileName: String

    /// Formatting with `ISO8601DateFormatter` is thread-safe; it is created eagerly so
    /// concurrent first calls to ``append(level:category:message:)`` never race on lazy init.
    private let timestampFormatter: ISO8601DateFormatter

    /// Identifies `queue` so synchronous entry points can run inline when the caller
    /// is already on it (a custom queue passed to `init`), instead of deadlocking.
    private let queueKey = DispatchSpecificKey<ObjectIdentifier>()

    public init(
        directory: URL? = nil,
        fileManager: FileManager = .default,
        queue: DispatchQueue? = nil,
        maxFileSize: Int = 5 * 1024 * 1024,
        maxFiles: Int = 5,
        fileName: String = "CoreExtendedNFC.log"
    ) {
        self.fileManager = fileManager
        self.maxFileSize = maxFileSize
        // At least one rotated file is always kept; `maxFiles < 1` would otherwise
        // build an invalid `1 ... maxFiles` range in `clear()`.
        self.maxFiles = max(1, maxFiles)
        logFileName = fileName
        let resolvedQueue = queue ?? DispatchQueue(label: "wiki.qaq.coreextendednfc.logstore", qos: .utility)
        self.queue = resolvedQueue

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        timestampFormatter = formatter

        let base = directory ?? fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("Logs", isDirectory: true)
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        logDirectory = dir
        resolvedQueue.setSpecific(key: queueKey, value: ObjectIdentifier(self))
        upgradeExistingFileProtection()
    }

    /// Files written by earlier versions used the default protection class.
    private func upgradeExistingFileProtection() {
        let urls = [logFileURL] + (1 ... maxFiles).map { rotatedFileURL(index: $0) }
        for url in urls where fileManager.fileExists(atPath: url.path) {
            try? fileManager.setAttributes(Self.fileAttributes, ofItemAtPath: url.path)
        }
    }

    /// Log files can contain card identifiers and protocol traces, so they are
    /// unreadable while the device is locked unless already open for appending.
    static var fileAttributes: [FileAttributeKey: Any] {
        [.protectionKey: FileProtectionType.completeUnlessOpen]
    }

    var logFileURL: URL {
        logDirectory.appendingPathComponent(logFileName)
    }

    public func append(level: LogLevel, category: String, message: String) {
        let line = formattedLine(level: level, category: category, message: message)
        queue.async { [weak self] in
            guard let self else { return }
            do {
                try ensureLogFileExists()
                let handle = try FileHandle(forWritingTo: logFileURL)
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
                try handle.close()
                try rotateIfNeeded()
            } catch {
                // Ignore disk write failures to avoid crashing logging callers
            }
        }
    }

    /// Read at most `maxBytes` UTF-8 bytes from the end of the current log file.
    ///
    /// When the file is longer than `maxBytes`, the leading partial line is dropped,
    /// so the result starts on a line boundary and never on a split multi-byte character.
    public func readTail(maxBytes: Int = 128 * 1024) -> String {
        performSync {
            guard let handle = try? FileHandle(forReadingFrom: logFileURL) else { return "" }
            defer { try? handle.close() }

            let limit = UInt64(max(0, maxBytes))
            let fileSize = (try? handle.seekToEnd()) ?? 0
            let startOffset = fileSize > limit ? fileSize - limit : 0
            try? handle.seek(toOffset: startOffset)
            let data = (try? handle.readToEnd()) ?? Data()
            return Self.decodeTail(data, isTruncated: startOffset > 0)
        }
    }

    public func clear() {
        performSync {
            try? fileManager.removeItem(at: logFileURL)
            removeRotatedFiles()
        }
    }

    public func flush() {
        performSync {}
    }

    /// Decode a tail slice of the log as UTF-8 without ever failing outright.
    static func decodeTail(_ data: Data, isTruncated: Bool) -> String {
        var bytes = data[...]
        if isTruncated {
            if let newline = bytes.firstIndex(of: 0x0A) {
                // Drop the partial first line.
                bytes = bytes[bytes.index(after: newline)...]
            } else {
                // A single partial line: skip UTF-8 continuation bytes (10xxxxxx).
                while let first = bytes.first, first & 0xC0 == 0x80 {
                    bytes = bytes.dropFirst()
                }
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func performSync<T>(_ work: () -> T) -> T {
        if DispatchQueue.getSpecific(key: queueKey) == ObjectIdentifier(self) {
            return work()
        }
        return queue.sync(execute: work)
    }

    private func formattedLine(level: LogLevel, category: String, message: String) -> Data {
        let timestamp = timestampFormatter.string(from: Date())
        return "\(timestamp) [\(level.rawValue)] [\(category)] \(message)\n".data(using: .utf8) ?? Data()
    }

    private func ensureLogFileExists() throws {
        if !fileManager.fileExists(atPath: logFileURL.path) {
            let dir = logFileURL.deletingLastPathComponent()
            try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
            fileManager.createFile(atPath: logFileURL.path, contents: nil, attributes: Self.fileAttributes)
        }
    }

    private func rotateIfNeeded() throws {
        let attributes = try fileManager.attributesOfItem(atPath: logFileURL.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue >= maxFileSize else { return }

        for index in stride(from: maxFiles - 1, through: 1, by: -1) {
            let source = rotatedFileURL(index: index)
            let destination = rotatedFileURL(index: index + 1)
            if fileManager.fileExists(atPath: destination.path) {
                try? fileManager.removeItem(at: destination)
            }
            if fileManager.fileExists(atPath: source.path) {
                try? fileManager.moveItem(at: source, to: destination)
            }
        }

        let first = rotatedFileURL(index: 1)
        if fileManager.fileExists(atPath: first.path) {
            try? fileManager.removeItem(at: first)
        }
        try fileManager.moveItem(at: logFileURL, to: first)
        fileManager.createFile(atPath: logFileURL.path, contents: nil, attributes: Self.fileAttributes)
    }

    func rotatedFileURL(index: Int) -> URL {
        logDirectory.appendingPathComponent("\(logFileName).\(index)")
    }

    private func removeRotatedFiles() {
        for index in 1 ... maxFiles {
            try? fileManager.removeItem(at: rotatedFileURL(index: index))
        }
    }
}
