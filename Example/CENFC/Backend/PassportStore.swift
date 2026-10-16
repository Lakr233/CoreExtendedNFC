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
        // Passport records hold DG1/DG2 personal data and the face image: keep
        // them out of iCloud and computer backups.
        file = RecordFileStore(fileURL: fileURL, source: "PassportStore", excludedFromBackup: true)
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

    /// The stored record an import of `record` would replace: the one with the
    /// same document number, or `nil` when the import simply adds a record.
    ///
    /// The import screen asks the user before replacing it.
    func importConflict(for record: PassportRecord) -> PassportRecord? {
        let documentNumber = record.passport.mrz?.documentNumber ?? ""
        guard !documentNumber.isEmpty else { return nil }
        return self.record(withDocumentNumber: documentNumber)
    }

    /// Stores an imported record. With `replacingExisting`, it replaces the
    /// record with the same document number (``importConflict(for:)``);
    /// otherwise, or when there is none, it is added (under a new ID when its ID
    /// is already taken).
    func importRecord(_ record: PassportRecord, replacingExisting: Bool = true) {
        if replacingExisting, let existing = importConflict(for: record) {
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
