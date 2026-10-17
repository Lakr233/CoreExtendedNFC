import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import UIKit

@MainActor
class ScanStore: @MainActor ObjectListDataSource {
    static let shared = ScanStore(
        fileURL: RecordFilePersistence<ScanRecord>.documentsFile(named: "scan_records.json")
    )

    private let file: RecordFileStore<ScanRecord>

    private(set) var records: [ScanRecord] = [] {
        didSet { changeSubject.send() }
    }

    private let changeSubject = PassthroughSubject<Void, Never>()

    /// Creates a store backed by `fileURL`. The app uses ``shared``; tests pass a temporary file.
    init(fileURL: URL) {
        file = RecordFileStore(fileURL: fileURL, source: "ScanStore")
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
    func add(_ record: ScanRecord) -> ScanRecord {
        let stored = RecordIdentity.unique(record, among: records)
        records.insert(stored, at: 0)
        save()
        return stored
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

    /// Inserts `record` at `index`, under a new ID when its ID is already in the store.
    func insert(_ record: ScanRecord, at index: Int) {
        let clamped = max(0, min(index, records.count))
        records.insert(RecordIdentity.unique(record, among: records), at: clamped)
        save()
    }

    /// Replaces the record with the same ID (the same exported record imported
    /// again) or the same stable UID, or inserts a new one at `index`.
    func upsert(_ record: ScanRecord, at index: Int = 0) {
        if self.record(for: record.id) != nil {
            replace(record.id, with: record)
        } else if let existing = self.record(withUID: record.cardInfo.uid) {
            replace(existing.id, with: record)
        } else {
            insert(record, at: index)
        }
    }

    /// The stored record an import of `record` would replace: the one with the
    /// same ID (the same exported record imported again) or the same stable
    /// UID, or `nil` when the import simply adds a record.
    ///
    /// The import screens ask the user before replacing it.
    func importConflict(for record: ScanRecord) -> ScanRecord? {
        self.record(for: record.id) ?? self.record(withUID: record.cardInfo.uid)
    }

    /// Stores an imported record. With `replacingExisting`, it replaces the
    /// record found by ``importConflict(for:)``; otherwise, or when there is
    /// none, it is inserted at `index` (under a new ID when its ID is taken).
    func importRecord(_ record: ScanRecord, replacingExisting: Bool, at index: Int = 0) {
        if replacingExisting, let existing = importConflict(for: record) {
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
        guard let reordered = RecordIdentity.reordered(records, by: orderedIDs) else { return }
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
        viewController.showRecordDetail(CardDetailViewController(record: item))
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
