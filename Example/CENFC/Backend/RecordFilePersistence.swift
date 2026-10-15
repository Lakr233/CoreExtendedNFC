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
nonisolated struct RecordFilePersistence<Record: Codable & Sendable>: Sendable {
    struct LoadResult {
        let records: [Record]
        /// Location of the backup copy when the file could not be decoded cleanly.
        let backupURL: URL?
        /// Number of elements that could not be decoded and were dropped.
        let droppedCount: Int
    }

    let fileURL: URL
    private let writer: RecordFileWriter

    init(fileURL: URL) {
        self.fileURL = fileURL
        writer = RecordFileWriter(fileURL: fileURL)
    }

    static func documentsFile(named name: String) -> URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent(name)
    }

    // MARK: - Load

    func load(now: Date = Date()) -> LoadResult {
        guard let data = try? Data(contentsOf: fileURL) else {
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
            droppedCount: max(elements.count - records.count, 0)
        )
    }

    @MainActor
    func reportLoadIssues(_ result: LoadResult, source: String) {
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
            try data.write(to: backupURL, options: .atomic)
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
    private var lastWrittenGeneration = Int.min

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    func write<Record: Encodable & Sendable>(_ records: [Record], generation: Int) {
        guard generation > lastWrittenGeneration else { return }
        lastWrittenGeneration = generation
        guard let data = try? RecordJSON.makeEncoder().encode(records) else { return }
        try? data.write(to: fileURL, options: .atomic)
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
