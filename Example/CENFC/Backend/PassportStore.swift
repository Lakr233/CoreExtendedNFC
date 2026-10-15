import CoreExtendedNFC
import Foundation

class PassportStore {
    static let shared = PassportStore(
        fileURL: RecordFilePersistence<PassportRecord>.documentsFile(named: "passport_records.json")
    )

    private let file: RecordFileStore<PassportRecord>

    private(set) var records: [PassportRecord] = []

    /// Creates a store backed by `fileURL`. The app uses ``shared``; tests pass a temporary file.
    init(fileURL: URL) {
        file = RecordFileStore(fileURL: fileURL, source: "PassportStore")
        load()
    }

    // MARK: - CRUD

    func load() {
        records = file.load()
    }

    /// Persists the current records without blocking the main thread.
    func save() {
        file.save(records)
    }

    /// Returns once the latest saved records are on disk.
    func flush() async {
        await file.flush()
    }

    /// Inserts `record` at the top. A record whose ID is already in the store
    /// (a re-imported file) is stored under a new ID.
    /// - Returns: The record as stored.
    @discardableResult
    func add(_ record: PassportRecord) -> PassportRecord {
        let stored = RecordIdentity.unique(record, among: records)
        records.insert(stored, at: 0)
        save()
        return stored
    }

    /// Stores an imported record: it replaces the record with the same document
    /// number, or is added (under a new ID when its ID is already taken).
    func importRecord(_ record: PassportRecord) {
        let documentNumber = record.passport.mrz?.documentNumber ?? ""
        if !documentNumber.isEmpty, let existing = self.record(withDocumentNumber: documentNumber) {
            replace(existing.id, with: record)
        } else {
            add(record)
        }
    }

    func remove(id: UUID) {
        records.removeAll { $0.id == id }
        save()
    }

    func replace(_ existingID: UUID, with record: PassportRecord) {
        guard let index = records.firstIndex(where: { $0.id == existingID }) else { return }
        records[index] = record.replacingID(existingID)
        save()
    }

    func sort(by comparator: (PassportRecord, PassportRecord) -> Bool) {
        records.sort(by: comparator)
        save()
    }

    func reorder(by orderedIDs: [UUID]) {
        guard let reordered = RecordIdentity.reordered(records, by: orderedIDs) else { return }
        records = reordered
        save()
    }

    // MARK: - Lookup

    func record(for id: UUID) -> PassportRecord? {
        records.first { $0.id == id }
    }

    func record(withDocumentNumber docNum: String) -> PassportRecord? {
        records.first { $0.passport.mrz?.documentNumber == docNum }
    }
}
