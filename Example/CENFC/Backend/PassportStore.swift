import CoreExtendedNFC
import Foundation

class PassportStore {
    static let shared = PassportStore()

    private let persistence = RecordFilePersistence<PassportRecord>(
        fileURL: RecordFilePersistence<PassportRecord>.documentsFile(named: "passport_records.json")
    )
    private var saveGeneration = 0

    private(set) var records: [PassportRecord] = []


    private init() {
        load()
    }

    // MARK: - CRUD

    func load() {
        let result = persistence.load()
        records = result.records
        persistence.reportLoadIssues(result, source: "PassportStore")
    }

    /// Persists the current records without blocking the main thread.
    func save() {
        saveGeneration += 1
        let snapshot = records
        let generation = saveGeneration
        let persistence = persistence
        Task {
            await persistence.save(snapshot, generation: generation)
        }
    }

    func add(_ record: PassportRecord) {
        records.insert(record, at: 0)
        save()
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
        guard orderedIDs.count == records.count else { return }
        let recordByID = Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0) })
        let reordered = orderedIDs.compactMap { recordByID[$0] }
        guard reordered.count == records.count else { return }
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
