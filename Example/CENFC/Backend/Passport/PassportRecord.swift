import CoreExtendedNFC
import Foundation

nonisolated struct PassportRecord: StoredRecord {
    /// Where the record's data came from.
    enum Origin: String, Codable, Sendable {
        /// Read from a chip by this app; the security report reflects that read.
        case chip
        /// Imported from a file. Its security report was written by whoever made
        /// the file and was not re-verified here. Its display fields are rebuilt
        /// from the file's raw data groups (see ``PassportRecord/reparsedFromRawDataGroups(_:)``).
        case imported
    }

    let id: UUID
    let date: Date
    let passport: PassportModel
    let origin: Origin

    init(from passport: PassportModel, id: UUID = UUID(), date: Date = Date(), origin: Origin = .chip) {
        self.id = id
        self.date = date
        self.passport = origin == .imported ? Self.reparsedFromRawDataGroups(passport) : passport
        self.origin = origin
    }

    private enum CodingKeys: String, CodingKey {
        case id, date, passport, origin
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        date = try container.decode(Date.self, forKey: .date)
        let passport = try container.decode(PassportModel.self, forKey: .passport)
        // Records saved before the origin was tracked were all read from a chip.
        origin = try container.decodeIfPresent(Origin.self, forKey: .origin) ?? .chip
        // Also covers imported records stored before display fields were re-parsed.
        self.passport = origin == .imported ? Self.reparsedFromRawDataGroups(passport) : passport
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

    // MARK: - Imported Records

    /// `passport` with every displayed field rebuilt from its raw data group bytes.
    ///
    /// An imported file carries both the raw data groups (which passive
    /// authentication hashes against the SOD) and pre-parsed fields such as `mrz`.
    /// A forged file could make the two disagree, so for imported records the
    /// app throws the pre-parsed fields away and lets the library parse the raw
    /// bytes again (`PassportModel(rawDataGroups:...)`, the parsing a chip read uses):
    ///
    /// - `mrz` comes from DG1, the portrait from DG2, the signature from DG7 and
    ///   the additional details from DG11/DG12; COM metadata, DG14, DG15, the SOD
    ///   and EF.CardAccess are re-parsed too. When a data group is missing or does
    ///   not parse, its field is `nil` and the screen shows nothing for it, rather
    ///   than the file's unverified value.
    /// - Passive authentication is not run here (it uses OpenSSL, and records are
    ///   decoded on the main thread), so `passiveAuthResult` is `nil`;
    ///   ``reverifiedSecurity()`` recomputes it off the main thread and re-judges
    ///   the kept `activeAuthResult` against it.
    /// - The file's `activeAuthResult`, security report and read status are kept:
    ///   they cannot be re-derived offline and are shown as not re-verified.
    nonisolated static func reparsedFromRawDataGroups(_ passport: PassportModel) -> PassportModel {
        // A file may carry the SOD, DG14 or DG15 bytes only in their dedicated fields.
        var raw = passport.rawDataGroups
        for (dgId, bytes) in [
            (DataGroupId.sod, passport.sodRaw),
            (DataGroupId.dg14, passport.securityInfoRaw),
            (DataGroupId.dg15, passport.activeAuthPublicKeyRaw),
        ] where raw[dgId] == nil {
            raw[dgId] = bytes
        }
        return PassportModel(
            rawDataGroups: raw,
            cardAccessRaw: passport.cardAccessRaw,
            performPassiveAuthentication: false,
            dataGroupReadStatus: passport.dataGroupReadStatus
        )
        .replacing(activeAuthResult: passport.activeAuthResult, securityReport: passport.securityReport)
    }

    /// Passive authentication re-run from the record's raw bytes, as a report stage.
    ///
    /// Re-hashes every raw data group against the SOD and verifies the SOD's CMS
    /// signature. No CSCA trust anchors are configured, so a genuine file reaches
    /// `.fallback` at best; a hash mismatch or bad signature is `.failed`, and a
    /// file without SOD is `.notSupported`. Uses OpenSSL: call it off the main thread.
    nonisolated func reverifiedPassiveAuthentication() -> PassportSecurityStageResult {
        reverifiedSecurity().passiveAuthentication
    }

    /// The security stages that can be re-derived offline for an imported record.
    nonisolated struct ReverifiedSecurity: Equatable, Sendable {
        /// Passive authentication re-run from the raw bytes.
        let passiveAuthentication: PassportSecurityStageResult
        /// The stored Active Authentication result re-judged against
        /// ``passiveAuthentication``, or `nil` when the file holds no AA result
        /// (its AA stage is then only what the file's author wrote).
        let activeAuthentication: PassportSecurityStageResult?
        /// The re-run passive authentication outcome, for a specific description.
        let passiveAuthStatus: PassiveAuthenticationStatus?
    }

    /// Passive authentication re-run from the raw bytes and the stored Active
    /// Authentication result re-judged against it
    /// (`PassportModel.reverifyingSecurity(trustAnchorsDER:)`).
    ///
    /// No CSCA trust anchors are configured, so neither stage can reach
    /// `.succeeded`: a genuine file is `.fallback` at best. Uses OpenSSL: call it
    /// off the main thread.
    nonisolated func reverifiedSecurity() -> ReverifiedSecurity {
        let reverified = passport.reverifyingSecurity(trustAnchorsDER: [])
        return ReverifiedSecurity(
            passiveAuthentication: reverified.securityReport.passiveAuthentication,
            activeAuthentication: passport.activeAuthResult == nil
                ? nil
                : reverified.securityReport.activeAuthentication,
            passiveAuthStatus: reverified.passiveAuthResult?.status
        )
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
