import CoreExtendedNFC
import Foundation

nonisolated struct PassportRecord: StoredRecord {
    let id: UUID
    let date: Date
    let passport: PassportModel

    init(from passport: PassportModel, id: UUID = UUID(), date: Date = Date()) {
        self.id = id
        self.date = date
        self.passport = passport
    }

    func withNewID() -> PassportRecord {
        replacingID(UUID(), date: date)
    }

    func replacingID(_ newID: UUID = UUID(), date newDate: Date = Date()) -> PassportRecord {
        PassportRecord(from: passport, id: newID, date: newDate)
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
