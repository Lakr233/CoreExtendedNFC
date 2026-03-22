import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import Then
import UIKit

@MainActor
class NDEFStore: ObjectListDataSource {
    static let shared = NDEFStore()

    private let fileURL: URL = {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent("ndef_records.json")
    }()

    private(set) var records: [NDEFDataRecord] = [] {
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
        records = (try? decoder.decode([NDEFDataRecord].self, from: data)) ?? []
    }

    func save() {
        guard let data = try? encoder.encode(records) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    func add(_ record: NDEFDataRecord) {
        records.insert(record, at: 0)
        save()
    }

    func remove(id: UUID) {
        records.removeAll { $0.id == id }
        save()
    }

    func replace(_ existingID: UUID, with record: NDEFDataRecord) {
        guard let index = records.firstIndex(where: { $0.id == existingID }) else { return }
        records[index] = record.replacingID(existingID)
        save()
    }

    func update(_ record: NDEFDataRecord) {
        guard let index = records.firstIndex(where: { $0.id == record.id }) else { return }
        records[index] = record
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

    func insert(_ record: NDEFDataRecord, at index: Int) {
        let clamped = max(0, min(index, records.count))
        records.insert(record, at: clamped)
        save()
    }

    func sort(by comparator: (NDEFDataRecord, NDEFDataRecord) -> Bool) {
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

    func record(for id: UUID) -> NDEFDataRecord? {
        records.first { $0.id == id }
    }

    func record(withMessageData data: Data) -> NDEFDataRecord? {
        records.first { $0.messageData == data }
    }

    // MARK: - ObjectListDataSource

    var items: [NDEFDataRecord] {
        records
    }

    var dataDidChange: AnyPublisher<Void, Never> {
        changeSubject.eraseToAnyPublisher()
    }

    func createItem(from _: UIViewController) async -> NDEFDataRecord? {
        nil // Creation handled by VC (create menu / scan / import)
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

    func configure(cell: ConfigurableView, for item: NDEFDataRecord) {
        cell.configure(icon: UIImage(systemName: Self.iconName(for: item)))
        cell.configure(title: String.LocalizationValue(stringLiteral: item.name))
        cell.configure(description: String.LocalizationValue(stringLiteral: item.displayValue))
    }

    static func iconName(for record: NDEFDataRecord) -> String {
        guard let parsed = record.parsedRecord else { return "circle.dashed" }
        switch parsed.parsedPayload {
        case .empty: return "circle.dashed"
        case .text: return "doc.plaintext"
        case .uri: return "link"
        case .smartPoster: return "rectangle.and.text.magnifyingglass"
        case .mime: return "doc.richtext"
        case .external: return "puzzlepiece.extension"
        case .unknown: return "questionmark.circle"
        }
    }
}
