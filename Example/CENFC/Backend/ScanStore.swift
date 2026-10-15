import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import UIKit

@MainActor
class ScanStore: @MainActor ObjectListDataSource {
    static let shared = ScanStore()

    private let persistence = RecordFilePersistence<ScanRecord>(
        fileURL: RecordFilePersistence<ScanRecord>.documentsFile(named: "scan_records.json")
    )
    private var saveGeneration = 0

    private(set) var records: [ScanRecord] = [] {
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
        persistence.reportLoadIssues(result, source: "ScanStore")
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

    func add(_ record: ScanRecord) {
        records.insert(record, at: 0)
        save()
    }

    func replace(_ existingID: UUID, with record: ScanRecord) {
        guard let index = records.firstIndex(where: { $0.id == existingID }) else { return }
        records[index] = record.replacingID(existingID)
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

    func insert(_ record: ScanRecord, at index: Int) {
        let clamped = max(0, min(index, records.count))
        records.insert(record, at: clamped)
        save()
    }

    /// Replaces the record with the same UID, or inserts a new one at `index`.
    func upsert(_ record: ScanRecord, at index: Int = 0) {
        if let existing = self.record(withUID: record.cardInfo.uid) {
            replace(existing.id, with: record)
        } else {
            insert(record, at: index)
        }
    }

    func sort(by comparator: (ScanRecord, ScanRecord) -> Bool) {
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

    func record(for id: UUID) -> ScanRecord? {
        records.first { $0.id == id }
    }

    func record(withUID uid: Data) -> ScanRecord? {
        guard uid.isStableCardUID else { return nil }
        return records.first { $0.cardInfo.uid == uid }
    }

    // MARK: - ObjectListDataSource

    var items: [ScanRecord] {
        records
    }

    var dataDidChange: AnyPublisher<Void, Never> {
        changeSubject.eraseToAnyPublisher()
    }

    func createItem(from _: UIViewController) async -> ScanRecord? {
        nil // Creation handled by VC (NFC scan / import)
    }

    func editItem(_ item: ScanRecord, from viewController: UIViewController) async -> ScanRecord? {
        viewController.navigationController?.pushViewController(
            CardDetailViewController(record: item), animated: true
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

    func rowPresentation(for item: ScanRecord) -> ObjectListRowPresentation {
        ObjectListRowPresentation(
            icon: Self.iconName(for: item.cardInfo.type.family),
            title: item.cardInfo.type.description,
            detail: item.cardInfo.uid.hexDump
        )
    }

    static func iconName(for family: CardFamily) -> String {
        switch family {
        case .mifareUltralight, .ntag: "creditcard"
        case .mifareClassic: "creditcard.trianglebadge.exclamationmark"
        case .mifarePlus: "creditcard.and.123"
        case .mifareDesfire: "lock.shield"
        case .type4: "doc.text"
        case .felica: "wave.3.right"
        case .iso15693: "barcode"
        case .passport: "person.text.rectangle"
        case .jewelTopaz: "diamond"
        case .iso14443B: "rectangle.on.rectangle"
        case .unknown: "questionmark.circle"
        }
    }
}
