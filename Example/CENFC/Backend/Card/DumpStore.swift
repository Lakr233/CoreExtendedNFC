import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import UIKit

@MainActor
class DumpStore: @MainActor ObjectListDataSource {
    static let shared = DumpStore(
        fileURL: RecordFilePersistence<DumpRecord>.documentsFile(named: "dump_records.json")
    )

    private let file: RecordFileStore<DumpRecord>

    private(set) var records: [DumpRecord] = [] {
        didSet { changeSubject.send() }
    }

    private let changeSubject = PassthroughSubject<Void, Never>()

    /// Creates a store backed by `fileURL`. The app uses ``shared``; tests pass a temporary file.
    init(fileURL: URL) {
        file = RecordFileStore(fileURL: fileURL, source: "DumpStore")
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
    func add(_ record: DumpRecord) -> DumpRecord {
        let stored = RecordIdentity.unique(record, among: records)
        records.insert(stored, at: 0)
        save()
        return stored
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

    func sort(by comparator: (DumpRecord, DumpRecord) -> Bool) {
        records.sort(by: comparator)
        save()
    }

    func reorder(by orderedIDs: [UUID]) {
        guard let reordered = RecordIdentity.reordered(records, by: orderedIDs) else { return }
        records = reordered
        save()
    }

    // MARK: - Lookup

    func record(for id: UUID) -> DumpRecord? {
        records.first { $0.id == id }
    }

    func record(withUID uid: Data) -> DumpRecord? {
        guard uid.isStableCardUID else { return nil }
        return records.first { $0.dump.cardInfo.uid == uid }
    }

    // MARK: - ObjectListDataSource

    var items: [DumpRecord] {
        records
    }

    var dataDidChange: AnyPublisher<Void, Never> {
        changeSubject.eraseToAnyPublisher()
    }

    func createItem(from _: UIViewController) async -> DumpRecord? {
        nil // Creation handled by VC (NFC dump / import)
    }

    func editItem(_ item: DumpRecord, from viewController: UIViewController) async -> DumpRecord? {
        viewController.showRecordDetail(DumpDetailViewController(record: item))
        return nil
    }

    func removeItems(_ ids: Set<UUID>) {
        records.removeAll { ids.contains($0.id) }
        save()
    }

    func moveItem(from sourceIndex: Int, to destinationIndex: Int) {
        move(from: sourceIndex, to: destinationIndex)
    }

    func reorderItems(by orderedIDs: [UUID]) {
        reorder(by: orderedIDs)
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    func rowPresentation(for item: DumpRecord) -> ObjectListRowPresentation {
        let dateString = Self.dateFormatter.string(from: item.date)
        return ObjectListRowPresentation(
            icon: ScanStore.iconName(for: item.dump.cardInfo.type.family),
            title: item.dump.cardInfo.type.description,
            detail: "\(dateString) · \(item.dump.summary.technicalSummary)"
        )
    }
}
