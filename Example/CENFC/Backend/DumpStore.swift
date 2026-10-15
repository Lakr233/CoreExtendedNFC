import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import UIKit

@MainActor
class DumpStore: @MainActor ObjectListDataSource {
    static let shared = DumpStore()

    private let persistence = RecordFilePersistence<DumpRecord>(
        fileURL: RecordFilePersistence<DumpRecord>.documentsFile(named: "dump_records.json")
    )
    private var saveGeneration = 0

    private(set) var records: [DumpRecord] = [] {
        didSet { changeSubject.send() }
    }

    private let changeSubject = PassthroughSubject<Void, Never>()


    private init() {
        load()
    }

    // MARK: - CRUD

    func load() {
        let result = persistence.load()
        records = result.records
        persistence.reportLoadIssues(result, source: "DumpStore")
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

    func add(_ record: DumpRecord) {
        records.insert(record, at: 0)
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
        viewController.navigationController?.pushViewController(
            DumpDetailViewController(record: item), animated: true
        )
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
