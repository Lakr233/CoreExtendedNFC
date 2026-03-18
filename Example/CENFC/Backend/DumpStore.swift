import CoreExtendedNFC
import Foundation
import Then

class DumpStore {
    static let shared = DumpStore()

    private let fileURL: URL = {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent("dump_records.json")
    }()

    private(set) var records: [DumpRecord] = []

    private let encoder = JSONEncoder().then {
        $0.dateEncodingStrategy = .iso8601
        $0.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    private let decoder = JSONDecoder().then {
        $0.dateDecodingStrategy = .iso8601
    }

    private init() {
        load()
    }

    // MARK: - CRUD

    func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        records = (try? decoder.decode([DumpRecord].self, from: data)) ?? []
    }

    func save() {
        guard let data = try? encoder.encode(records) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    func add(_ record: DumpRecord) {
        records.insert(record, at: 0)
        save()
    }

    func remove(id: UUID) {
        records.removeAll { $0.id == id }
        save()
    }

    func move(from source: Int, to destination: Int) {
        guard source != destination,
              records.indices.contains(source),
              destination >= 0, destination <= records.count
        else { return }
        let record = records.remove(at: source)
        let target = min(destination, records.count)
        records.insert(record, at: target)
        save()
    }

    func insert(_ record: DumpRecord, at index: Int) {
        let clamped = max(0, min(index, records.count))
        records.insert(record, at: clamped)
        save()
    }

    func sort(by comparator: (DumpRecord, DumpRecord) -> Bool) {
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

    func record(for id: UUID) -> DumpRecord? {
        records.first { $0.id == id }
    }

    func records(withUID uid: Data) -> [DumpRecord] {
        records.filter { $0.dump.cardInfo.uid == uid }
    }
}
