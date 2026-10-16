import Foundation

/// Result of reading an eMRTD (electronic Machine Readable Travel Document).
/// Contains parsed data groups plus the raw bytes used for verification.
public struct PassportModel: Sendable, Codable, Equatable {
    /// Parsed EF.CardAccess security info, when the file is readable before BAC/PACE.
    public let cardAccess: SecurityInfos?

    /// Raw EF.CardAccess bytes.
    public let cardAccessRaw: Data?

    /// LDS version from COM data group (e.g., "0107").
    public let ldsVersion: String?

    /// Unicode version from COM data group.
    public let unicodeVersion: String?

    /// List of data groups available on the chip (from COM).
    public let availableDataGroups: [DataGroupId]

    /// Parsed MRZ data from DG1.
    public let mrz: MRZData?

    /// Face image data from DG2 (raw JPEG or JPEG2000 bytes).
    public let faceImageData: Data?

    /// Signature/usual mark image from DG7 (raw image bytes).
    public let signatureImageData: Data?

    /// Additional personal details from DG11 keyed by field name.
    public let additionalPersonalDetails: [String: String]?

    /// Additional document details from DG12 keyed by field name.
    public let additionalDocumentDetails: [String: String]?

    /// Parsed DG14 security info (PACE, CA, AA protocol parameters).
    public let securityInfos: SecurityInfos?

    /// Raw DG14 security info bytes.
    public let securityInfoRaw: Data?

    /// Parsed DG15 active authentication public key.
    public let activeAuthPublicKey: ActiveAuthenticationPublicKey?

    /// Raw DG15 active authentication public key bytes.
    public let activeAuthPublicKeyRaw: Data?

    /// Parsed SOD (Security Object Document) content.
    public let sod: SODContent?

    /// Raw SOD bytes.
    public let sodRaw: Data?

    /// Passive authentication result (hash verification).
    public let passiveAuthResult: PassiveAuthenticationResult?

    /// Active authentication result (chip genuineness verification).
    public let activeAuthResult: ActiveAuthenticationResult?

    /// Raw data group bytes indexed by `DataGroupId`.
    public let rawDataGroups: [DataGroupId: Data]

    /// Step-by-step status for passport security mechanisms.
    public let securityReport: PassportSecurityReport

    /// Outcome of each data group the reader tried or skipped, keyed by `DataGroupId`.
    ///
    /// `nil` for models built before per-data-group status existed.
    public let dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]?

    /// Best-effort face image bytes for DG2.
    ///
    /// Older saved records may have persisted the full ISO 19794-5 facial record
    /// instead of the extracted JPEG/JPEG2000 payload. When raw DG2 bytes are
    /// available, prefer reparsing them so UI consumers always receive the
    /// normalized image payload when possible.
    public var resolvedFaceImageData: Data? {
        if let rawDG2 = rawDataGroups[.dg2],
           let reparsed = try? DataGroupParser.parseDG2(rawDG2)
        {
            return reparsed
        }
        return faceImageData
    }

    /// Best-effort signature image bytes for DG7.
    public var resolvedSignatureImageData: Data? {
        if let rawDG7 = rawDataGroups[.dg7],
           let reparsed = try? DataGroupParser.parseDG7(rawDG7)
        {
            return reparsed
        }
        return signatureImageData
    }

    public init(
        cardAccess: SecurityInfos? = nil,
        cardAccessRaw: Data? = nil,
        ldsVersion: String?,
        unicodeVersion: String?,
        availableDataGroups: [DataGroupId],
        mrz: MRZData?,
        faceImageData: Data?,
        signatureImageData: Data?,
        additionalPersonalDetails: [String: String]?,
        additionalDocumentDetails: [String: String]?,
        securityInfos: SecurityInfos?,
        securityInfoRaw: Data?,
        activeAuthPublicKey: ActiveAuthenticationPublicKey?,
        activeAuthPublicKeyRaw: Data?,
        sod: SODContent?,
        sodRaw: Data?,
        passiveAuthResult: PassiveAuthenticationResult?,
        activeAuthResult: ActiveAuthenticationResult?,
        rawDataGroups: [DataGroupId: Data],
        securityReport: PassportSecurityReport = .init(),
        dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]? = nil
    ) {
        self.cardAccess = cardAccess
        self.cardAccessRaw = cardAccessRaw
        self.ldsVersion = ldsVersion
        self.unicodeVersion = unicodeVersion
        self.availableDataGroups = availableDataGroups
        self.mrz = mrz
        self.faceImageData = faceImageData
        self.signatureImageData = signatureImageData
        self.additionalPersonalDetails = additionalPersonalDetails
        self.additionalDocumentDetails = additionalDocumentDetails
        self.securityInfos = securityInfos
        self.securityInfoRaw = securityInfoRaw
        self.activeAuthPublicKey = activeAuthPublicKey
        self.activeAuthPublicKeyRaw = activeAuthPublicKeyRaw
        self.sod = sod
        self.sodRaw = sodRaw
        self.passiveAuthResult = passiveAuthResult
        self.activeAuthResult = activeAuthResult
        self.rawDataGroups = rawDataGroups
        self.securityReport = securityReport
        self.dataGroupReadStatus = dataGroupReadStatus
    }

    /// Run passive authentication again from this model's raw bytes.
    ///
    /// Use it for a model that did not come straight from ``PassportReader`` (for example
    /// one decoded from a file): its stored `passiveAuthResult` and `securityReport` are
    /// whatever the file says. This re-parses the SOD (`sodRaw`, else
    /// `rawDataGroups[.sod]`), re-hashes every raw data group and verifies the SOD's CMS
    /// signature; with `trustAnchorsDER` (DER CSCA certificates) it also validates the
    /// signer certificate's chain. No NFC is involved.
    ///
    /// Only passive authentication can be repeated offline. BAC/PACE, Chip Authentication
    /// and Active Authentication are challenge–response protocols with the chip, so their
    /// stored results cannot be re-checked; ``reverifyingSecurity(trustAnchorsDER:)``
    /// re-judges a stored Active Authentication result against a new passive
    /// authentication result. Fields such as `mrz` or `faceImageData` are
    /// not tied to this result; callers that show them should re-parse them from
    /// `rawDataGroups`.
    ///
    /// - Parameter trustAnchorsDER: DER-encoded CSCA certificates; empty skips chain validation.
    /// - Returns: `.sodNotAvailable` without SOD bytes, `.sodParseFailed` when they do not
    ///   parse, otherwise the full passive authentication result. Map it to a stage with
    ///   ``PassportSecurityStageResult/passiveAuthentication(_:sodPresent:)``.
    public func reverifyPassiveAuthentication(trustAnchorsDER: [Data] = []) -> PassiveAuthenticationResult {
        guard let sodData = sodRaw ?? rawDataGroups[.sod] else {
            return PassiveAuthenticationResult(dataGroupHashResults: [:], hasCertificate: false, status: .sodNotAvailable)
        }
        guard let sodContent = try? SODParser.parse(sodData) else {
            return PassiveAuthenticationResult(dataGroupHashResults: [:], hasCertificate: false, status: .sodParseFailed)
        }
        return SODParser.verifyPassiveAuthentication(
            sodContent: sodContent,
            rawDataGroups: rawDataGroups,
            trustAnchorsDER: trustAnchorsDER
        )
    }
}

extension PassportModel {
    /// A copy with passive authentication re-run from the raw bytes and Active
    /// Authentication re-judged against it.
    ///
    /// The Active Authentication challenge–response cannot be repeated offline, but
    /// whether its stored result proves the chip genuine depends on passive
    /// authentication, so both are re-derived together: `passiveAuthResult` becomes
    /// ``reverifyPassiveAuthentication(trustAnchorsDER:)``, `activeAuthResult` is
    /// re-classified with ``ActiveAuthenticationResult/classified(by:)``, and the report's
    /// `passiveAuthentication` and `activeAuthentication` stages are rebuilt. The other
    /// stages are kept as stored, and so is the AA stage when no AA result is stored (it
    /// then records why AA did not run). No NFC is involved.
    public func reverifyingSecurity(trustAnchorsDER: [Data] = []) -> PassportModel {
        let passive = reverifyPassiveAuthentication(trustAnchorsDER: trustAnchorsDER)
        let active = activeAuthResult?.classified(by: passive)
        let report = securityReport
        return PassportModel(
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            ldsVersion: ldsVersion,
            unicodeVersion: unicodeVersion,
            availableDataGroups: availableDataGroups,
            mrz: mrz,
            faceImageData: faceImageData,
            signatureImageData: signatureImageData,
            additionalPersonalDetails: additionalPersonalDetails,
            additionalDocumentDetails: additionalDocumentDetails,
            securityInfos: securityInfos,
            securityInfoRaw: securityInfoRaw,
            activeAuthPublicKey: activeAuthPublicKey,
            activeAuthPublicKeyRaw: activeAuthPublicKeyRaw,
            sod: sod,
            sodRaw: sodRaw,
            passiveAuthResult: passive,
            activeAuthResult: active,
            rawDataGroups: rawDataGroups,
            securityReport: PassportSecurityReport(
                cardAccess: report.cardAccess,
                pace: report.pace,
                bac: report.bac,
                chipAuthentication: report.chipAuthentication,
                passiveAuthentication: .passiveAuthentication(
                    passive,
                    sodPresent: (sodRaw ?? rawDataGroups[.sod]) != nil
                ),
                activeAuthentication: active.map {
                    .activeAuthentication($0, passiveAuthentication: passive)
                } ?? report.activeAuthentication
            ),
            dataGroupReadStatus: dataGroupReadStatus
        )
    }
}

/// What happened to one data group during `PassportReader.readPassport`.
public enum PassportDataGroupReadState: String, Sendable, Equatable, Codable {
    /// The file was read completely.
    case read
    /// The SOD (and EF.COM, when read) does not list this data group, so it was never
    /// selected. EF.COM alone never rules a data group out.
    case notPresent
    /// The chip reported the file as absent or protected (e.g. 6A82, or 6982 for EAC data groups).
    case unavailable
    /// Selected, but the file could not be read completely (short read, bad header);
    /// no partial bytes are kept.
    case failed
    /// Not read because secure messaging ended earlier in the session.
    case notRead
}

/// Per-data-group read outcome with a human-readable reason.
public struct PassportDataGroupReadResult: Sendable, Equatable, Codable {
    public let state: PassportDataGroupReadState
    public let detail: String

    public init(state: PassportDataGroupReadState, detail: String = "") {
        self.state = state
        self.detail = detail
    }
}

/// Overall status of one passport security stage.
public enum PassportSecurityStageStatus: String, Sendable, Equatable, Codable {
    case pending
    case succeeded
    case failed
    case fallback
    case skipped
    case notAdvertised
    case notSupported
}

/// Result of a single security stage in the passport workflow.
public struct PassportSecurityStageResult: Sendable, Equatable, Codable {
    public let status: PassportSecurityStageStatus
    public let detail: String

    public init(status: PassportSecurityStageStatus = .pending, detail: String = "") {
        self.status = status
        self.detail = detail
    }

    /// Stage result for a passive authentication outcome.
    ///
    /// - `.succeeded` only for ``PassiveAuthenticationStatus/fullyVerified``: hashes match, the SOD
    ///   signature verifies and its signer chains to a supplied CSCA (ICAO 9303-11 §5.1).
    /// - `.fallback` when the hashes match but the signature is not chained to a CSCA
    ///   (``PassiveAuthenticationStatus/signatureVerified`` without anchors, or no signature check).
    /// - `.failed` for an invalid signature, a broken trust chain, a hash mismatch, an
    ///   unparseable SOD or an unsupported hash algorithm.
    /// - `.skipped` when no data group the SOD covers was compared; `.notSupported`
    ///   when there was no SOD.
    public static func passiveAuthentication(
        _ result: PassiveAuthenticationResult?,
        sodPresent: Bool
    ) -> PassportSecurityStageResult {
        guard let result else {
            return PassportSecurityStageResult(
                status: sodPresent ? .failed : .notSupported,
                detail: sodPresent
                    ? "SOD was read, but passive authentication did not complete."
                    : "SOD was not available, so passive authentication could not run."
            )
        }

        switch result.status {
        case .sodNotAvailable:
            return PassportSecurityStageResult(
                status: .notSupported,
                detail: "SOD was not available, so passive authentication could not run."
            )
        case .sodParseFailed:
            return PassportSecurityStageResult(status: .failed, detail: "The SOD could not be parsed.")
        case .unsupportedHashAlgorithm:
            return PassportSecurityStageResult(
                status: .failed,
                detail: "The SOD uses a hash algorithm this library does not support, so no data group was verified."
            )
        default:
            break
        }

        if result.dataGroupHashResults.isEmpty {
            return PassportSecurityStageResult(
                status: .skipped,
                detail: "SOD was read, but no data group it covers was read, so no hashes were compared."
            )
        }

        let compared = result.dataGroupHashResults.count
        switch result.status {
        case .fullyVerified:
            return PassportSecurityStageResult(
                status: .succeeded,
                detail: "\(compared) data group hashes match, the SOD signature is valid and its signer chains to a trusted CSCA."
            )
        case .signatureVerified:
            return PassportSecurityStageResult(
                status: .fallback,
                detail: "\(compared) data group hashes match and the SOD signature is valid, but the signature is "
                    + "not chained to a CSCA (no trust anchors were supplied)."
            )
        case .signatureNotVerified, .dataGroupHashesVerified:
            return PassportSecurityStageResult(
                status: .fallback,
                detail: "\(compared) data group hashes match the SOD, but the SOD signature was not verified "
                    + "and is not chained to a CSCA."
            )
        case .signatureInvalid:
            return PassportSecurityStageResult(
                status: .failed,
                detail: "The SOD signature is invalid; the data group hashes cannot be trusted."
            )
        case .trustChainInvalid:
            return PassportSecurityStageResult(
                status: .failed,
                detail: "The SOD signature is valid, but its signer certificate does not chain to a supplied CSCA."
            )
        case .hashMismatch, .sodNotAvailable, .sodParseFailed, .unsupportedHashAlgorithm:
            return PassportSecurityStageResult(
                status: .failed,
                detail: "\(result.failedDataGroups.count) of \(compared) data groups do not match the SOD."
            )
        }
    }
}

extension PassportSecurityStageResult {
    /// Stage result for an Active Authentication outcome, judged against passive
    /// authentication.
    ///
    /// A valid signature only proves the chip holds the private key matching DG15; it
    /// proves the chip genuine only when DG15 itself is authenticated (ICAO 9303-11 §6.1,
    /// §5.1). So:
    /// - `.succeeded` only for a valid signature when passive authentication is
    ///   ``PassiveAuthenticationStatus/fullyVerified`` and the DG15 hash matched.
    /// - `.failed` for an invalid signature or a failed command, and for a valid signature
    ///   whose DG15 does not match its hash in the SOD (DG15 was altered).
    /// - `.fallback` for a valid signature over a DG15 that is not authenticated: no trust
    ///   anchors (``PassiveAuthenticationStatus/signatureVerified``; a clone can self-sign its SOD),
    ///   a broken trust chain, DG15 not covered by the SOD, or no passive authentication.
    /// - `.notSupported` for an unsupported key or signature format; `.skipped` when
    ///   `activeAuthentication` is `nil` (AA did not run).
    public static func activeAuthentication(
        _ activeAuthentication: ActiveAuthenticationResult?,
        passiveAuthentication: PassiveAuthenticationResult?
    ) -> PassportSecurityStageResult {
        guard let result = activeAuthentication else {
            return PassportSecurityStageResult(status: .skipped, detail: "Active Authentication did not run.")
        }

        switch result.status {
        case .verified, .verifiedUnauthenticatedKey:
            if ActiveAuthenticationResult.isDG15Authenticated(by: passiveAuthentication) {
                return PassportSecurityStageResult(status: .succeeded, detail: result.details)
            }
            let dg15Hash = passiveAuthentication?.dataGroupHashResults[.dg15]
            let paStatus = passiveAuthentication?.status.rawValue ?? "not run"
            if dg15Hash == false {
                return PassportSecurityStageResult(
                    status: .failed,
                    detail: "\(result.details). The chip signed the challenge with the DG15 key, but DG15 does not "
                        + "match its hash in the SOD, so the key was altered (passive authentication: \(paStatus))."
                )
            }
            return PassportSecurityStageResult(
                status: .fallback,
                detail: "\(result.details). The chip signed the challenge with the DG15 key, but DG15 is not "
                    + "authenticated by an SOD signature chained to a trusted CSCA (DG15 hash verified: "
                    + "\(dg15Hash == true), passive authentication: \(paStatus)), so this does not prove the "
                    + "chip is genuine."
            )
        case .notImplemented, .unsupportedKeyType:
            return PassportSecurityStageResult(status: .notSupported, detail: result.details)
        case .failed, .commandFailed:
            return PassportSecurityStageResult(status: .failed, detail: result.details)
        }
    }
}

/// Structured report for the main eMRTD security stages.
public struct PassportSecurityReport: Sendable, Equatable, Codable {
    public let cardAccess: PassportSecurityStageResult
    public let pace: PassportSecurityStageResult
    public let bac: PassportSecurityStageResult
    public let chipAuthentication: PassportSecurityStageResult
    public let passiveAuthentication: PassportSecurityStageResult
    public let activeAuthentication: PassportSecurityStageResult

    public init(
        cardAccess: PassportSecurityStageResult = .init(),
        pace: PassportSecurityStageResult = .init(),
        bac: PassportSecurityStageResult = .init(),
        chipAuthentication: PassportSecurityStageResult = .init(),
        passiveAuthentication: PassportSecurityStageResult = .init(),
        activeAuthentication: PassportSecurityStageResult = .init()
    ) {
        self.cardAccess = cardAccess
        self.pace = pace
        self.bac = bac
        self.chipAuthentication = chipAuthentication
        self.passiveAuthentication = passiveAuthentication
        self.activeAuthentication = activeAuthentication
    }
}

/// Result of active authentication.
///
/// `success` and `status` describe different things:
/// - `success` is the cryptographic outcome only: the chip signed the challenge with the
///   private key matching the DG15 public key.
/// - `status` says what that proves. ``ActiveAuthenticationStatus/verified`` is used only when DG15
///   itself is authenticated (its hash matches an SOD whose signature chains to a trusted
///   CSCA). A valid signature over an unauthenticated DG15 is
///   ``ActiveAuthenticationStatus/verifiedUnauthenticatedKey``: a clone can carry its own key pair
///   and a self-signed SOD and still produce it.
///
/// To decide whether the chip is genuine, check `status == .verified` or the
/// ``PassportSecurityReport/activeAuthentication`` stage, never `success` alone.
public struct ActiveAuthenticationResult: Sendable, Equatable, Codable {
    /// Whether the chip's signature verified against the DG15 public key. This is the
    /// cryptographic result only; it does not say whether the DG15 key is authentic.
    public let success: Bool
    /// Description of the result.
    public let details: String
    /// The verification status.
    public let status: ActiveAuthenticationStatus

    public init(success: Bool, details: String, status: ActiveAuthenticationStatus = .verified) {
        self.success = success
        self.details = details
        self.status = status
    }

    /// Whether the chip produced a valid signature with the DG15 key, whether or not
    /// that key is authenticated by passive authentication.
    public var signatureIsValid: Bool {
        status == .verified || status == .verifiedUnauthenticatedKey
    }

    /// This result with `status` re-derived against `passiveAuthentication`: a valid
    /// signature is ``ActiveAuthenticationStatus/verified`` only when DG15 is authenticated by
    /// fully verified passive authentication, otherwise
    /// ``ActiveAuthenticationStatus/verifiedUnauthenticatedKey``. Other statuses are unchanged.
    public func classified(by passiveAuthentication: PassiveAuthenticationResult?) -> ActiveAuthenticationResult {
        guard signatureIsValid else { return self }
        let status: ActiveAuthenticationStatus = Self.isDG15Authenticated(by: passiveAuthentication)
            ? .verified
            : .verifiedUnauthenticatedKey
        return ActiveAuthenticationResult(success: success, details: details, status: status)
    }

    /// DG15 is authenticated only when its hash matches the SOD and the SOD signature
    /// chains to a trusted CSCA (ICAO 9303-11 §5.1, §6.1).
    public static func isDG15Authenticated(by passiveAuthentication: PassiveAuthenticationResult?) -> Bool {
        passiveAuthentication?.status == .fullyVerified
            && passiveAuthentication?.dataGroupHashResults[.dg15] == true
    }
}

@available(*, deprecated, renamed: "ActiveAuthenticationStatus")
public typealias ActiveAuthStatus = ActiveAuthenticationStatus

/// Active Authentication verification status.
public enum ActiveAuthenticationStatus: String, Sendable, Codable {
    /// The signature is valid and the DG15 key is authenticated by fully verified
    /// passive authentication, so the chip is genuine. ``PassportReader`` reports a
    /// valid signature over an unauthenticated key as ``verifiedUnauthenticatedKey``.
    case verified
    /// The signature is valid, but DG15 is not authenticated by fully verified passive
    /// authentication (no trust anchors, broken trust chain, DG15 not covered or not
    /// matching the SOD). This does not prove the chip is genuine.
    case verifiedUnauthenticatedKey
    /// Verification completed but signature is invalid.
    case failed
    /// AA is not implemented for this key or signature format.
    case notImplemented
    /// INTERNAL AUTHENTICATE command failed.
    case commandFailed
    /// Public key type not recognized.
    case unsupportedKeyType
}
