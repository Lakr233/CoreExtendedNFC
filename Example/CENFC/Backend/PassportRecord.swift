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
    /// app throws the pre-parsed fields away and parses the raw bytes itself:
    ///
    /// - `mrz` comes from DG1, the portrait from DG2 and the signature from DG7.
    ///   When that data group is missing or does not parse, the field is `nil`
    ///   and the screen shows nothing for it, rather than the file's unverified value.
    /// - DG11/DG12 details have no public parser and are not shown, so they are dropped.
    /// - `passiveAuthResult` is dropped; ``reverifiedPassiveAuthentication()`` recomputes it.
    /// - COM metadata (LDS/Unicode version, data group list) is kept: EF.COM is
    ///   not covered by the SOD, so re-parsing it would not make it any more trustworthy.
    nonisolated static func reparsedFromRawDataGroups(_ passport: PassportModel) -> PassportModel {
        let raw = passport.rawDataGroups
        // `resolved*ImageData` re-parse DG2/DG7 and only fall back to the stored
        // image, which this probe leaves empty.
        let probe = PassportModel(
            ldsVersion: nil, unicodeVersion: nil, availableDataGroups: [],
            mrz: nil, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: raw
        )
        return PassportModel(
            cardAccess: passport.cardAccess,
            cardAccessRaw: passport.cardAccessRaw,
            ldsVersion: passport.ldsVersion,
            unicodeVersion: passport.unicodeVersion,
            availableDataGroups: passport.availableDataGroups,
            mrz: raw[.dg1].flatMap(parseDG1),
            faceImageData: probe.resolvedFaceImageData,
            signatureImageData: probe.resolvedSignatureImageData,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: passport.securityInfos,
            securityInfoRaw: passport.securityInfoRaw,
            activeAuthPublicKey: passport.activeAuthPublicKey,
            activeAuthPublicKeyRaw: passport.activeAuthPublicKeyRaw,
            sod: passport.sod,
            sodRaw: passport.sodRaw,
            passiveAuthResult: nil,
            activeAuthResult: passport.activeAuthResult,
            rawDataGroups: raw,
            securityReport: passport.securityReport,
            dataGroupReadStatus: passport.dataGroupReadStatus
        )
    }

    /// DG1 → MRZ (ICAO 9303-10 §4.7.1: `61 { 5F1F <MRZ> }`).
    ///
    /// Mirrors the library's internal DG1 parser, which is not public.
    nonisolated static func parseDG1(_ data: Data) -> MRZData? {
        guard let wrapper = try? ASN1Parser.parseTLV(data).first(where: { $0.tag == 0x61 }),
              let mrzNode = try? wrapper.children().first(where: { $0.tag == 0x5F1F }),
              let mrzString = String(data: mrzNode.value, encoding: .utf8)
        else { return nil }
        return try? MRZData(mrzString: mrzString)
    }

    /// Passive authentication re-run from the record's raw bytes, as a report stage.
    ///
    /// Re-hashes every raw data group against the SOD and verifies the SOD's CMS
    /// signature. No CSCA trust anchors are configured, so a genuine file reaches
    /// `.fallback` at best; a hash mismatch or bad signature is `.failed`, and a
    /// file without SOD is `.notSupported`. Uses OpenSSL: call it off the main thread.
    nonisolated func reverifiedPassiveAuthentication() -> PassportSecurityStageResult {
        let sodPresent = (passport.sodRaw ?? passport.rawDataGroups[.sod]) != nil
        return .passiveAuthentication(passport.reverifyPassiveAuthentication(), sodPresent: sodPresent)
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
