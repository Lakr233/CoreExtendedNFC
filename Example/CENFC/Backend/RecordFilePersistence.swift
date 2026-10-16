import Foundation

/// JSON file persistence shared by the record stores.
///
/// - Loading never silently discards history: when the file cannot be decoded
///   as a whole, the original bytes are copied to a `*.corrupt-<timestamp>.json`
///   backup before anything else can overwrite the file, and every element that
///   still decodes is kept.
/// - Saving encodes and writes on a background actor so the main thread never
///   blocks on JSON encoding or disk I/O. Each save carries a generation number
///   and an older snapshot never overwrites a newer one.
/// - Every file (the store and its corrupt backups) is written with
///   `completeFileProtectionUnlessOpen`: unreadable while the device is locked,
///   yet a save that finishes in a background task after the device locks
///   still succeeds (creating a file is allowed under that class).
/// - A store created with `excludedFromBackup` (the passport store: DG1/DG2
///   personal data and the face image) marks its file and its backups as
///   excluded from iCloud and computer backups after every write, because an
///   atomic write replaces the file and drops the flag. The scan, dump and NDEF
///   stores stay in backups so users do not lose their records when restoring
///   a device; they hold card identifiers, not identity documents.
nonisolated struct RecordFilePersistence<Record: Codable & Sendable>: Sendable {
    struct LoadResult {
        let records: [Record]
        /// Location of the backup copy when the file could not be decoded cleanly.
        let backupURL: URL?
        /// Number of elements that could not be decoded and were dropped.
        let droppedCount: Int
        /// Why the file must not be overwritten, or `nil` when saving is safe.
        ///
        /// Set when the file exists but could not be read (data protection, I/O
        /// error), or when it could not be decoded and the backup copy failed.
        /// Saving would then replace history that is still only on disk.
        var writeBlockedReason: String? = nil

        /// Whether the file was only partly decoded and should be re-saved, so the
        /// next launch does not back it up again.
        var needsResave: Bool {
            backupURL != nil && writeBlockedReason == nil
        }
    }

    let fileURL: URL
    let excludedFromBackup: Bool
    private let writer: RecordFileWriter

    init(fileURL: URL, excludedFromBackup: Bool = false) {
        self.fileURL = fileURL
        self.excludedFromBackup = excludedFromBackup
        writer = RecordFileWriter(fileURL: fileURL, excludedFromBackup: excludedFromBackup)
    }

    /// Data protection class of every file this type writes.
    static var writingOptions: Data.WritingOptions {
        RecordFileWriting.options
    }

    static func write(_ data: Data, to url: URL, excludedFromBackup: Bool) throws {
        try RecordFileWriting.write(data, to: url, excludedFromBackup: excludedFromBackup)
    }

    static func documentsFile(named name: String) -> URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent(name)
    }

    // MARK: - Load

    func load(now: Date = Date()) -> LoadResult {
        applyStorageAttributesToExistingFile()
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            guard Self.isFileMissing(error) else {
                return LoadResult(
                    records: [],
                    backupURL: nil,
                    droppedCount: 0,
                    writeBlockedReason: "could not read file: \(error.localizedDescription)"
                )
            }
            return LoadResult(records: [], backupURL: nil, droppedCount: 0)
        }
        let decoder = RecordJSON.makeDecoder()
        if let records = try? decoder.decode([Record].self, from: data) {
            return LoadResult(records: records, backupURL: nil, droppedCount: 0)
        }

        let backupURL = backup(data, now: now)
        let elements = (try? decoder.decode([LossyElement].self, from: data)) ?? []
        let records = elements.compactMap(\.value)
        return LoadResult(
            records: records,
            backupURL: backupURL,
            droppedCount: max(elements.count - records.count, 0),
            writeBlockedReason: backupURL == nil ? "could not decode file and backup failed" : nil
        )
    }

    /// Gives a file written by an older build the protection class and backup
    /// exclusion that new writes get. Missing files and failures are ignored:
    /// the next save writes the attributes anyway.
    private func applyStorageAttributesToExistingFile() {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUnlessOpen],
            ofItemAtPath: fileURL.path
        )
        guard excludedFromBackup else { return }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = fileURL
        try? mutableURL.setResourceValues(values)
    }

    /// Whether `error` from reading the store file means the file does not exist yet.
    static func isFileMissing(_ error: Error) -> Bool {
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain, nsError.code == NSFileReadNoSuchFileError {
            return true
        }
        if nsError.domain == NSPOSIXErrorDomain, nsError.code == Int(ENOENT) {
            return true
        }
        if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? Error {
            return isFileMissing(underlying)
        }
        return false
    }

    @MainActor
    func reportLoadIssues(_ result: LoadResult, source: String) {
        if let reason = result.writeBlockedReason {
            AppLogStore.shared.error(
                "\(fileURL.lastPathComponent): \(reason); changes will not be saved this session so the file is not overwritten",
                source: source
            )
        }
        guard result.backupURL != nil || result.droppedCount > 0 else { return }
        let backupName = result.backupURL?.lastPathComponent ?? "none (backup failed)"
        AppLogStore.shared.error(
            "Could not decode \(fileURL.lastPathComponent); kept \(result.records.count) record(s), dropped \(result.droppedCount), original saved as \(backupName)",
            source: source
        )
    }

    private func backup(_ data: Data, now: Date) -> URL? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let stem = fileURL.deletingPathExtension().lastPathComponent
        let backupURL = fileURL.deletingLastPathComponent()
            .appendingPathComponent("\(stem).corrupt-\(formatter.string(from: now))-\(UUID().uuidString.prefix(8))")
            .appendingPathExtension("json")
        do {
            try Self.write(data, to: backupURL, excludedFromBackup: excludedFromBackup)
            return backupURL
        } catch {
            return nil
        }
    }

    // MARK: - Save

    /// Encodes and writes `records` off the main thread.
    func save(_ records: [Record], generation: Int) async {
        await writer.write(records, generation: generation)
    }

    private struct LossyElement: Decodable {
        let value: Record?

        init(from decoder: Decoder) throws {
            value = try? decoder.singleValueContainer().decode(Record.self)
        }
    }
}

/// Serialises file writes for one store and drops snapshots older than the last one written.
private actor RecordFileWriter {
    private let fileURL: URL
    private let excludedFromBackup: Bool
    private var lastWrittenGeneration = Int.min

    init(fileURL: URL, excludedFromBackup: Bool) {
        self.fileURL = fileURL
        self.excludedFromBackup = excludedFromBackup
    }

    func write<Record: Encodable & Sendable>(_ records: [Record], generation: Int) {
        guard generation > lastWrittenGeneration else { return }
        lastWrittenGeneration = generation
        guard let data = try? RecordJSON.makeEncoder().encode(records) else { return }
        try? RecordFileWriting.write(data, to: fileURL, excludedFromBackup: excludedFromBackup)
    }
}

/// How record store files are written to disk.
nonisolated enum RecordFileWriting {
    static let options: Data.WritingOptions = [.atomic, .completeFileProtectionUnlessOpen]

    /// Writes `data` to `url` with ``options`` and, when requested, marks the
    /// new file as excluded from backup (an atomic write replaces the file, so
    /// the flag must be set again after every write).
    static func write(_ data: Data, to url: URL, excludedFromBackup: Bool) throws {
        try data.write(to: url, options: options)
        if excludedFromBackup {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableURL = url
            try mutableURL.setResourceValues(values)
        }
    }
}

/// The JSON format used by the record store files.
nonisolated enum RecordJSON {
    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
