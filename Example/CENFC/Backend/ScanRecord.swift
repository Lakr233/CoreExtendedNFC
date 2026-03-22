import ConfigurableKit
import CoreExtendedNFC
import Foundation

struct ScanRecord: Codable, Identifiable {
    let id: UUID
    let date: Date
    let cardInfo: CardInfo

    init(cardInfo: CardInfo, id: UUID = UUID(), date: Date = Date()) {
        self.id = id
        self.date = date
        self.cardInfo = cardInfo
    }

    static func synthesized(from dump: DumpRecord) -> ScanRecord {
        ScanRecord(cardInfo: dump.dump.cardInfo, date: dump.date)
    }

    func replacingID(_ newID: UUID = UUID(), date newDate: Date = Date()) -> ScanRecord {
        ScanRecord(cardInfo: cardInfo, id: newID, date: newDate)
    }
}

extension ScanRecord: Hashable {
    static func == (lhs: ScanRecord, rhs: ScanRecord) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

extension ScanRecord: ObjectListItem {
    func matches(query: String) -> Bool {
        cardInfo.type.description.localizedCaseInsensitiveContains(query)
            || cardInfo.uid.hexString.localizedCaseInsensitiveContains(query)
            || cardInfo.uid.compactHexString.localizedCaseInsensitiveContains(query)
    }
}
