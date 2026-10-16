import Foundation

public extension PassportModel {
    /// Build a model from raw data group bytes, with the same parsers and Passive
    /// Authentication that ``PassportReader`` applies after a chip read.
    ///
    /// Use it for data groups that did not come straight from a read, for example ones
    /// loaded from a file or a database. Every field is derived from the bytes passed
    /// in: EF.COM gives `ldsVersion`, `unicodeVersion` and `availableDataGroups`; DG1
    /// gives `mrz`; DG2 and DG7 the portrait and signature images; DG11 and DG12
    /// `additionalPersonalDetails` and `additionalDocumentDetails`; DG14
    /// `securityInfos`; DG15 `activeAuthPublicKey`; the SOD `sod`. A data group that is
    /// missing or does not parse leaves its field `nil` (or empty). No NFC is involved.
    ///
    /// Passive Authentication runs on the SOD and the data groups, as in
    /// ``reverifyPassiveAuthentication(trustAnchorsDER:)``, unless
    /// `performPassiveAuthentication` is `false`. It verifies a CMS signature with
    /// OpenSSL, so keep it off the main thread. `activeAuthResult` is `nil`:
    /// Active Authentication is a challenge–response with the chip and cannot be
    /// repeated offline. In `securityReport`, `passiveAuthentication` and
    /// `chipAuthentication` (whether DG14 advertises it) are derived from the bytes;
    /// the stages that need the chip (`cardAccess`, `pace`, `bac`,
    /// `activeAuthentication`) are `.skipped`. Use
    /// ``replacing(activeAuthResult:securityReport:)`` to attach results you kept
    /// from the original read.
    ///
    /// - Parameters:
    ///   - rawDataGroups: Raw data group bytes (including their TLV wrapper), as in
    ///     ``rawDataGroups``.
    ///   - cardAccessRaw: Raw EF.CardAccess bytes, parsed into ``cardAccess``.
    ///   - performPassiveAuthentication: Whether to run Passive Authentication. When
    ///     `false`, `passiveAuthResult` is `nil` and its stage is `.skipped`; run it later
    ///     with ``reverifyingSecurity(trustAnchorsDER:)``.
    ///   - trustAnchorsDER: DER-encoded CSCA certificates; empty skips certification path validation,
    ///     so Passive Authentication is at best ``PassiveAuthenticationStatus/signatureVerified``.
    ///   - dataGroupReadStatus: Per-data-group read outcomes to keep, if any.
    init(
        rawDataGroups: [DataGroupId: Data],
        cardAccessRaw: Data? = nil,
        performPassiveAuthentication: Bool = true,
        trustAnchorsDER: [Data] = [],
        dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]? = nil
    ) {
        let parsed = PassportModel(
            parsing: rawDataGroups,
            cardAccess: cardAccessRaw.flatMap { try? CardAccessParser.parse($0) },
            cardAccessRaw: cardAccessRaw,
            performPassiveAuthentication: performPassiveAuthentication,
            trustAnchorsDER: trustAnchorsDER,
            securityReport: PassportSecurityReport(),
            dataGroupReadStatus: dataGroupReadStatus
        )
        let notRun = PassportSecurityStageResult(
            status: .skipped,
            detail: "Not run: the model was built from raw data group bytes, without the chip."
        )
        self = parsed.replacing(
            activeAuthResult: nil,
            securityReport: PassportSecurityReport(
                cardAccess: notRun,
                pace: notRun,
                bac: notRun,
                chipAuthentication: .chipAuthentication(advertisedBy: parsed.securityInfos),
                passiveAuthentication: performPassiveAuthentication
                    ? .passiveAuthentication(parsed.passiveAuthResult, sodPresent: rawDataGroups[.sod] != nil)
                    : notRun,
                activeAuthentication: notRun
            )
        )
    }
}

extension PassportModel {
    /// Shared by ``init(rawDataGroups:cardAccessRaw:performPassiveAuthentication:trustAnchorsDER:dataGroupReadStatus:)``
    /// and ``PassportReader/assemblePassportModel(rawDataGroups:trustAnchorsDER:cardAccess:cardAccessRaw:securityReport:dataGroupReadStatus:)``.
    init(
        parsing rawDataGroups: [DataGroupId: Data],
        cardAccess: SecurityInfos?,
        cardAccessRaw: Data?,
        performPassiveAuthentication: Bool = true,
        trustAnchorsDER: [Data],
        securityReport: PassportSecurityReport,
        dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]?
    ) {
        // COM
        let com = rawDataGroups[.com].flatMap { try? DataGroupParser.parseCOM($0) }

        // DG1 — MRZ
        let mrz = rawDataGroups[.dg1].flatMap { try? DataGroupParser.parseDG1($0) }

        // DG2 — Face Image
        var faceImageData: Data?
        if let dg2Data = rawDataGroups[.dg2] {
            do {
                faceImageData = try DataGroupParser.parseDG2(dg2Data)
                if let faceImageData {
                    NFCLog.info("Parsed DG2 face image: \(faceImageData.count) bytes", source: "Passport")
                }
            } catch {
                NFCLog.error("DG2 parse failed: \(error.localizedDescription)", source: "Passport")
            }
        }

        // DG7 — Signature Image
        var signatureImageData: Data?
        if let dg7Data = rawDataGroups[.dg7] {
            do {
                signatureImageData = try DataGroupParser.parseDG7(dg7Data)
                if let signatureImageData {
                    NFCLog.info("Parsed DG7 signature image: \(signatureImageData.count) bytes", source: "Passport")
                } else {
                    NFCLog.info("DG7 present but did not contain an extractable signature image", source: "Passport")
                }
            } catch {
                NFCLog.error("DG7 parse failed: \(error.localizedDescription)", source: "Passport")
            }
        }

        // DG11 / DG12 — Additional Personal / Document Details
        let personalDetails = rawDataGroups[.dg11].flatMap { try? DataGroupParser.parseDG11($0) }
        let documentDetails = rawDataGroups[.dg12].flatMap { try? DataGroupParser.parseDG12($0) }

        // DG14 — Security Info; DG15 — Active Authentication Public Key
        let securityInfos = rawDataGroups[.dg14].flatMap { try? DG14Parser.parse($0) }
        let activeAuthPublicKey = rawDataGroups[.dg15].flatMap { try? DG15Parser.parse($0) }

        // EF.SOD — Document Security Object, then Passive Authentication against it
        let sodContent = rawDataGroups[.sod].flatMap { try? SODParser.parse($0) }
        let passiveAuthResult: PassiveAuthenticationResult? = if performPassiveAuthentication, let sodContent {
            SODParser.verifyPassiveAuthentication(
                sodContent: sodContent,
                rawDataGroups: rawDataGroups,
                trustAnchorsDER: trustAnchorsDER
            )
        } else {
            nil
        }

        self.init(
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            ldsVersion: com?.ldsVersion,
            unicodeVersion: com?.unicodeVersion,
            availableDataGroups: com?.dataGroups ?? [],
            mrz: mrz,
            faceImageData: faceImageData,
            signatureImageData: signatureImageData,
            additionalPersonalDetails: personalDetails,
            additionalDocumentDetails: documentDetails,
            securityInfos: securityInfos,
            securityInfoRaw: rawDataGroups[.dg14],
            activeAuthPublicKey: activeAuthPublicKey,
            activeAuthPublicKeyRaw: rawDataGroups[.dg15],
            sod: sodContent,
            sodRaw: rawDataGroups[.sod],
            passiveAuthResult: passiveAuthResult,
            activeAuthResult: nil,
            rawDataGroups: rawDataGroups,
            securityReport: securityReport,
            dataGroupReadStatus: dataGroupReadStatus
        )
    }
}

public extension PassportSecurityStageResult {
    /// Stage result for Chip Authentication, judged from the DG14 security infos.
    ///
    /// `.notAdvertised` without DG14 or when DG14 does not advertise Chip
    /// Authentication; `.notSupported` when it does, because this library does not
    /// perform the Chip Authentication key agreement.
    static func chipAuthentication(advertisedBy securityInfos: SecurityInfos?) -> PassportSecurityStageResult {
        guard let securityInfos else {
            return PassportSecurityStageResult(
                status: .notAdvertised,
                detail: "DG14 was not available, so Chip Authentication support could not be determined."
            )
        }

        guard securityInfos.supportsChipAuthentication else {
            return PassportSecurityStageResult(
                status: .notAdvertised,
                detail: "DG14 does not advertise Chip Authentication."
            )
        }

        return PassportSecurityStageResult(
            status: .notSupported,
            detail: "Chip Authentication is advertised, but session key transition is not implemented yet."
        )
    }
}
