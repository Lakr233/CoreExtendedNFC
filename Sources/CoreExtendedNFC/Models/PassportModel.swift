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
    public let activeAuthPublicKey: ActiveAuthPublicKey?

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
        activeAuthPublicKey: ActiveAuthPublicKey?,
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
    /// stored results cannot be re-checked. Fields such as `mrz` or `faceImageData` are
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

/// What happened to one data group during `PassportReader.readPassport`.
public enum PassportDataGroupReadState: String, Sendable, Equatable, Codable {
    /// The file was read completely.
    case read
    /// EF.COM does not list this data group, so it was never selected.
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
    /// - `.succeeded` only for ``PassiveAuthStatus/fullyVerified``: hashes match, the SOD
    ///   signature verifies and its signer chains to a supplied CSCA (ICAO 9303-11 §5.1).
    /// - `.fallback` when the hashes match but the signature is not chained to a CSCA
    ///   (``PassiveAuthStatus/signatureVerified`` without anchors, or no signature check).
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
public struct ActiveAuthenticationResult: Sendable, Equatable, Codable {
    /// Whether the signature verification succeeded.
    public let success: Bool
    /// Description of the result.
    public let details: String
    /// The verification status.
    public let status: ActiveAuthStatus

    public init(success: Bool, details: String, status: ActiveAuthStatus = .verified) {
        self.success = success
        self.details = details
        self.status = status
    }
}

/// Active Authentication verification status.
public enum ActiveAuthStatus: String, Sendable, Codable {
    /// Verification completed and signature is valid.
    case verified
    /// Verification completed but signature is invalid.
    case failed
    /// AA is not implemented for this key or signature format.
    case notImplemented
    /// INTERNAL AUTHENTICATE command failed.
    case commandFailed
    /// Public key type not recognized.
    case unsupportedKeyType
}
