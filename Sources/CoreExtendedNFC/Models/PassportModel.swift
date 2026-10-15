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
