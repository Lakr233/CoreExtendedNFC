import ConfigurableKit
import CoreExtendedNFC
import Foundation

nonisolated struct ScanRecord: Codable, Identifiable, Sendable {
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

nonisolated extension ScanRecord: Hashable {
    static func == (lhs: ScanRecord, rhs: ScanRecord) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

nonisolated extension Data {
    /// Whether this UID names the same physical card on every read.
    ///
    /// Empty UIDs and ISO/IEC 14443-3 random UIDs (single-size, first byte `0x08`,
    /// used by eMRTDs and many ISO 7816 / DESFire EV cards) change per activation,
    /// so they must not be used to match records or verify a card.
    var isStableCardUID: Bool {
        guard !isEmpty else { return false }
        return !(count == 4 && first == 0x08)
    }
}

nonisolated extension ScanRecord: ObjectListItem {
    func matches(query: String) -> Bool {
        cardInfo.type.description.localizedCaseInsensitiveContains(query)
            || cardInfo.uid.hexDump.localizedCaseInsensitiveContains(query)
            || cardInfo.uid.hexString.localizedCaseInsensitiveContains(query)
    }
}
