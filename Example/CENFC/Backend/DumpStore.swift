import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import Then
import UIKit

@MainActor
class DumpStore: ObjectListDataSource {
    static let shared = DumpStore()

    private let fileURL: URL = {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent("dump_records.json")
    }()

    private(set) var records: [DumpRecord] = [] {
        didSet { changeSubject.send() }
    }

    private let changeSubject = PassthroughSubject<Void, Never>()

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

    func configure(cell: ConfigurableView, for item: DumpRecord) {
        let dateString = Self.dateFormatter.string(from: item.date)
        cell.configure(icon: UIImage(systemName: ScanStore.iconName(for: String(describing: item.dump.cardInfo.type.family))))
        cell.configure(title: String.LocalizationValue(stringLiteral: item.dump.cardInfo.type.description))
        cell.configure(description: String.LocalizationValue(stringLiteral: "\(dateString) · \(item.dump.summary.technicalSummary)"))
    }
}
