import Combine
import ConfigurableKit
import CoreExtendedNFC
import Foundation
import Then
import UIKit

@MainActor
class NDEFStore: @MainActor ObjectListDataSource {
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

    /// Adds the record unless one with the same message data already exists. Returns whether it was added.
    func addIfNew(_ record: NDEFDataRecord) -> Bool {
        guard self.record(withMessageData: record.messageData) == nil else { return false }
        add(record)
        return true
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

    func rowPresentation(for item: NDEFDataRecord) -> ObjectListRowPresentation {
        ObjectListRowPresentation(
            icon: Self.iconName(for: item),
            title: item.name,
            detail: item.displayValue
        )
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
