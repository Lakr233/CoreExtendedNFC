import ConfigurableKit
import CoreExtendedNFC
import Foundation

struct DumpRecord: Codable, Identifiable {
    let id: UUID
    let date: Date
    let dump: MemoryDump

    init(from dump: MemoryDump, id: UUID = UUID(), date: Date = Date()) {
        self.id = id
        self.date = date
        self.dump = dump
    }

    func replacingID(_ newID: UUID = UUID(), date newDate: Date = Date()) -> DumpRecord {
        DumpRecord(from: dump, id: newID, date: newDate)
    }

    var hasMemoryData: Bool {
        !dump.pages.isEmpty || !dump.blocks.isEmpty || !dump.files.isEmpty || dump.ndefMessage != nil
    }
}

extension DumpRecord: Hashable {
    static func == (lhs: DumpRecord, rhs: DumpRecord) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

extension DumpRecord: ObjectListItem {
    func matches(query: String) -> Bool {
        dump.cardInfo.type.description.localizedCaseInsensitiveContains(query)
            || dump.cardInfo.uid.hexString.localizedCaseInsensitiveContains(query)
            || dump.cardInfo.uid.compactHexString.localizedCaseInsensitiveContains(query)
    }
}
