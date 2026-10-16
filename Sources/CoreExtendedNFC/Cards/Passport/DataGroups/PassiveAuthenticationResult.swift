import Foundation

/// Result of Passive Authentication verification.
public struct PassiveAuthenticationResult: Sendable, Equatable, Codable {
    /// Whether hash verification passed for each data group.
    public let dataGroupHashResults: [DataGroupId: Bool]

    /// Whether at least one data group hash was compared and every comparison matched.
    ///
    /// An empty result (nothing compared, e.g. unsupported hash algorithm) is not valid.
    public var allHashesValid: Bool {
        !dataGroupHashResults.isEmpty && dataGroupHashResults.values.allSatisfy(\.self)
    }

    /// Data groups that failed hash verification.
    public var failedDataGroups: [DataGroupId] {
        dataGroupHashResults.filter { !$0.value }.map(\.key)
    }

    /// Whether the Document Signer certificate (DSC) was found in the EF.SOD.
    public let hasCertificate: Bool

    /// CMS/PKCS#7 signature verification result, if attempted.
    public let cmsSignatureValid: Bool?

    /// Result of certification path validation from the DSC to a provided CSCA, if attempted.
    public let trustChainValid: Bool?

    /// Overall Passive Authentication status.
    public let status: PassiveAuthenticationStatus

    public init(
        dataGroupHashResults: [DataGroupId: Bool],
        hasCertificate: Bool,
        cmsSignatureValid: Bool? = nil,
        trustChainValid: Bool? = nil,
        status: PassiveAuthenticationStatus
    ) {
        self.dataGroupHashResults = dataGroupHashResults
        self.hasCertificate = hasCertificate
        self.cmsSignatureValid = cmsSignatureValid
        self.trustChainValid = trustChainValid
        self.status = status
    }
}

@available(*, deprecated, renamed: "PassiveAuthenticationStatus")
public typealias PassiveAuthStatus = PassiveAuthenticationStatus

/// Passive Authentication status.
///
/// Full Passive Authentication (ICAO 9303-11 §5.1) combines data group hash
/// verification against the Document Security Object (EF.SOD), verification of its
/// CMS signature with the embedded Document Signer certificate (DSC), and
/// certification path validation from that DSC to a trusted CSCA. Hashes are
/// always compared; the signature and certificate path are checked with OpenSSL,
/// and the certificate path only when CSCA trust anchors are supplied.
public enum PassiveAuthenticationStatus: String, Sendable, Codable {
    /// Data group hashes verified successfully against the EF.SOD.
    /// - Important: This does NOT mean full Passive Authentication is complete.
    ///   The EF.SOD signature itself has NOT been verified, and no Document Signer
    ///   certificate was validated to a CSCA. A cloned chip could present matching
    ///   hashes with a forged EF.SOD. Not produced by the current verifier, which
    ///   reports ``signatureNotVerified`` instead; kept for decoding older results.
    case dataGroupHashesVerified
    /// Some or all data group hashes failed.
    case hashMismatch
    /// The EF.SOD could not be parsed.
    case sodParseFailed
    /// The EF.SOD was not read from the chip.
    case sodNotAvailable
    /// The hash algorithm in the EF.SOD is not recognized or not supported.
    case unsupportedHashAlgorithm
    /// Data group hashes match, but the EF.SOD CMS signature could not be verified
    /// (the EF.SOD carries no signer certificate or signature, or OpenSSL is unavailable).
    case signatureNotVerified
    /// Data group hashes match and the EF.SOD CMS signature verifies with the embedded
    /// Document Signer certificate. No CSCA trust anchors were supplied, so the
    /// certificate was not validated to a trusted CSCA.
    case signatureVerified
    /// The EF.SOD CMS signature was checked and is invalid.
    case signatureInvalid
    /// Data group hashes match, the EF.SOD CMS signature verifies, and certification
    /// path validation from the Document Signer certificate to a supplied CSCA succeeded.
    case fullyVerified
    /// The EF.SOD CMS signature verifies, but certification path validation from the
    /// Document Signer certificate to the supplied CSCAs failed.
    case trustChainInvalid
}
