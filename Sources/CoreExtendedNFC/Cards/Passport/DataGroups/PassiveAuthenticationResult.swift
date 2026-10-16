import Foundation

/// Result of passive authentication verification.
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

    /// Whether the document signer certificate was found in SOD.
    public let hasCertificate: Bool

    /// CMS/PKCS#7 signature verification result, if attempted.
    public let cmsSignatureValid: Bool?

    /// DSC trust-chain verification result against provided CSCA anchors, if attempted.
    public let trustChainValid: Bool?

    /// Overall passive authentication status.
    public let status: PassiveAuthStatus

    public init(
        dataGroupHashResults: [DataGroupId: Bool],
        hasCertificate: Bool,
        cmsSignatureValid: Bool? = nil,
        trustChainValid: Bool? = nil,
        status: PassiveAuthStatus
    ) {
        self.dataGroupHashResults = dataGroupHashResults
        self.hasCertificate = hasCertificate
        self.cmsSignatureValid = cmsSignatureValid
        self.trustChainValid = trustChainValid
        self.status = status
    }
}

/// Passive authentication status.
///
/// Full passive authentication combines CMS signature validation on the SOD with
/// data-group hash verification. Hash comparison is always available here; CMS and
/// trust-chain validation depend on OpenSSL support.
public enum PassiveAuthStatus: String, Sendable, Codable {
    /// Data group hashes verified successfully against SOD.
    /// - Important: This does NOT mean full passive authentication is complete.
    ///   The SOD signature itself has NOT been verified against the DSC/CSCA.
    ///   A cloned chip could present matching hashes with a forged SOD.
    case dataGroupHashesVerified
    /// Some or all data group hashes failed.
    case hashMismatch
    /// SOD could not be parsed.
    case sodParseFailed
    /// SOD was not read from the chip.
    case sodNotAvailable
    /// Hash algorithm in SOD is not recognized/supported.
    case unsupportedHashAlgorithm
    /// SOD signature verification not yet implemented.
    /// Hash comparison was done but the CMS signature was not verified.
    case signatureNotVerified
    /// SOD CMS signature verified successfully against the embedded DSC.
    /// Trust chain validation against CSCA is still out of scope.
    case signatureVerified
    /// SOD CMS signature verification was attempted and failed.
    case signatureInvalid
    /// SOD CMS signature verified and DSC trust chain validated against provided anchors.
    case fullyVerified
    /// SOD CMS signature verified, but DSC trust validation failed.
    case trustChainInvalid
}
