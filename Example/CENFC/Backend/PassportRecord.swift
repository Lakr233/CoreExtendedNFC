import CoreExtendedNFC
import Foundation

nonisolated struct PassportRecord: StoredRecord {
    /// Where the record's data came from.
    enum Origin: String, Codable, Sendable {
        /// Read from a chip by this app; the security report reflects that read.
        case chip
        /// Imported from a file. Its security report was written by whoever made
        /// the file and was not re-verified here.
        case imported
    }

    let id: UUID
    let date: Date
    let passport: PassportModel
    let origin: Origin

    init(from passport: PassportModel, id: UUID = UUID(), date: Date = Date(), origin: Origin = .chip) {
        self.id = id
        self.date = date
        self.passport = passport
        self.origin = origin
    }

    private enum CodingKeys: String, CodingKey {
        case id, date, passport, origin
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        date = try container.decode(Date.self, forKey: .date)
        passport = try container.decode(PassportModel.self, forKey: .passport)
        // Records saved before the origin was tracked were all read from a chip.
        origin = try container.decodeIfPresent(Origin.self, forKey: .origin) ?? .chip
    }

    var isImported: Bool {
        origin == .imported
    }

    func withNewID() -> PassportRecord {
        replacingID(UUID(), date: date)
    }

    func replacingID(_ newID: UUID = UUID(), date newDate: Date = Date()) -> PassportRecord {
        PassportRecord(from: passport, id: newID, date: newDate, origin: origin)
    }

    /// The same record, marked as imported from a file.
    func markedImported() -> PassportRecord {
        PassportRecord(from: passport, id: id, date: date, origin: .imported)
    }

    // MARK: - Display Helpers

    var displayName: String {
        guard let mrz = passport.mrz else { return String(localized: "Unknown") }
        let name = [mrz.lastName, mrz.firstName].filter { !$0.isEmpty }.joined(separator: ", ")
        return name.isEmpty ? String(localized: "Unknown") : name
    }

    var formattedDOB: String {
        Self.formatMRZDate(passport.mrz?.dateOfBirth ?? "")
    }

    var formattedExpiry: String {
        Self.formatMRZDate(passport.mrz?.dateOfExpiry ?? "")
    }

    var dataGroupsSummary: String {
        passport.availableDataGroups.map(\.name).joined(separator: ", ")
    }

    var totalRawSize: Int {
        passport.rawDataGroups.values.reduce(0) { $0 + $1.count }
    }

    private static func formatMRZDate(_ yymmdd: String) -> String {
        guard yymmdd.count == 6 else { return yymmdd }
        let yy = String(yymmdd.prefix(2))
        let mm = String(yymmdd.dropFirst(2).prefix(2))
        let dd = String(yymmdd.dropFirst(4).prefix(2))
        return "\(dd)/\(mm)/\(yy)"
    }
}

nonisolated extension PassportRecord: Hashable {
    static func == (lhs: PassportRecord, rhs: PassportRecord) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
