import Foundation

/// A record kept in one of the app's lists, identified by a UUID.
///
/// Lists are driven by diffable data sources keyed on `id`, so two records in
/// one store must never share an ID (UIKit raises "supplied item identifiers
/// are not unique").
nonisolated protocol StoredRecord: Codable, Sendable, Identifiable where ID == UUID {
    /// A copy with a new ID and otherwise identical content.
    func withNewID() -> Self
}

/// Keeps record IDs unique within a store.
nonisolated enum RecordIdentity {
    /// `record`, given a new ID when `records` already holds one with its ID.
    ///
    /// Imported files carry the ID of the record they were exported from, so
    /// importing the same file twice would otherwise insert a duplicate ID.
    static func unique<Record: StoredRecord>(_ record: Record, among records: [Record]) -> Record {
        records.contains { $0.id == record.id } ? record.withNewID() : record
    }

    /// `records` with every repeated ID after its first use replaced by a new one.
    ///
    /// Nothing is dropped: a store saved by an older build may hold the same ID
    /// twice, and both copies are kept.
    static func deduplicated<Record: StoredRecord>(_ records: [Record]) -> (records: [Record], changed: Bool) {
        var seen = Set<UUID>()
        var changed = false
        let result = records.map { record -> Record in
            guard seen.insert(record.id).inserted else {
                changed = true
                let fresh = record.withNewID()
                seen.insert(fresh.id)
                return fresh
            }
            return record
        }
        return (result, changed)
    }

    /// `records` in the order of `orderedIDs`, or `nil` when the IDs do not name every record exactly once.
    static func reordered<Record: StoredRecord>(_ records: [Record], by orderedIDs: [UUID]) -> [Record]? {
        guard orderedIDs.count == records.count else { return nil }
        let recordByID = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        guard recordByID.count == records.count, Set(orderedIDs).count == orderedIDs.count else { return nil }
        let reordered = orderedIDs.compactMap { recordByID[$0] }
        return reordered.count == records.count ? reordered : nil
    }
}

/// Loading and saving of one store's records file.
///
/// - Records with repeated IDs are given new IDs on load, and the repaired list
///   is written back, as is a list recovered from a partly corrupt file (so the
///   next launch does not back the same file up again).
/// - When the file exists but cannot be read, or could not be backed up, every
///   save is refused for the rest of the session so the file on disk is not
///   replaced by an incomplete list.
@MainActor
final class RecordFileStore<Record: StoredRecord> {
    private let persistence: RecordFilePersistence<Record>
    private let source: String
    private var saveGeneration = 0
    private var latestSnapshot: [Record]?

    /// Why saving is refused, or `nil` when the store may write its file.
    private(set) var writeBlockedReason: String?

    init(fileURL: URL, source: String, excludedFromBackup: Bool = false) {
        persistence = RecordFilePersistence(fileURL: fileURL, excludedFromBackup: excludedFromBackup)
        self.source = source
    }

    var fileURL: URL {
        persistence.fileURL
    }

    func load() -> [Record] {
        let result = persistence.load()
        persistence.reportLoadIssues(result, source: source)
        writeBlockedReason = result.writeBlockedReason

        let (records, changed) = RecordIdentity.deduplicated(result.records)
        if changed {
            AppLogStore.shared.warning(
                "\(fileURL.lastPathComponent) held records with the same ID; gave the duplicates new IDs",
                source: source
            )
        }
        if changed || result.needsResave {
            save(records)
        }
        return records
    }

    /// Writes `records` off the main thread. Older snapshots never overwrite newer ones.
    func save(_ records: [Record]) {
        guard writeBlockedReason == nil else {
            AppLogStore.shared.warning(
                "Not saving \(fileURL.lastPathComponent): \(writeBlockedReason ?? "")",
                source: source
            )
            return
        }
        saveGeneration += 1
        latestSnapshot = records
        let generation = saveGeneration
        let persistence = persistence
        Task {
            await persistence.save(records, generation: generation)
        }
    }

    /// Returns once the latest snapshot passed to ``save(_:)`` is on disk.
    func flush() async {
        guard let latestSnapshot else { return }
        await persistence.save(latestSnapshot, generation: saveGeneration)
    }
}
