import Foundation

/// Parsed SOD (Security Object Document) data.
///
/// The SOD contains a CMS (PKCS#7) SignedData structure with:
/// - LDS Security Object: hash algorithm + hash values for each DataGroup
/// - Document Signer Certificate (DSC): X.509 certificate
///
/// Reference: ICAO Doc 9303 Part 10, Section 4.6.2
public struct SODContent: Sendable, Equatable, Codable {
    /// The hash algorithm used (e.g., "2.16.840.1.101.3.4.2.1" for SHA-256).
    public let hashAlgorithmOID: String

    /// Human-readable hash algorithm name.
    public let hashAlgorithm: String

    /// Hash values for each data group, keyed by DataGroupId.
    public let dataGroupHashes: [DataGroupId: Data]

    /// LDS version (from LDS Security Object, if present).
    public let ldsVersion: String?

    /// Unicode version (from LDS Security Object, if present).
    public let unicodeVersion: String?

    /// Raw Document Signer Certificate bytes (DER-encoded X.509).
    ///
    /// This is the embedded certificate the SignerInfo's SID identifies, i.e. the one
    /// whose key signed the SOD. When no embedded certificate matches, it falls back
    /// to the first embedded certificate (for display only; CMS verification then fails).
    public let documentSignerCertificate: Data?

    /// Raw signed attributes bytes (for signature verification).
    public let signedAttributes: Data?

    /// Raw signature bytes.
    public let signature: Data?

    /// Signature algorithm OID.
    public let signatureAlgorithmOID: String?

    /// The encapsulated content (LDS Security Object) raw bytes.
    public let encapsulatedContent: Data?

    /// Raw CMS ContentInfo DER bytes (without the outer 0x77 wrapper).
    public let rawCMSData: Data?

    public init(
        hashAlgorithmOID: String,
        hashAlgorithm: String,
        dataGroupHashes: [DataGroupId: Data],
        ldsVersion: String?,
        unicodeVersion: String?,
        documentSignerCertificate: Data?,
        signedAttributes: Data?,
        signature: Data?,
        signatureAlgorithmOID: String?,
        encapsulatedContent: Data?,
        rawCMSData: Data? = nil
    ) {
        self.hashAlgorithmOID = hashAlgorithmOID
        self.hashAlgorithm = hashAlgorithm
        self.dataGroupHashes = dataGroupHashes
        self.ldsVersion = ldsVersion
        self.unicodeVersion = unicodeVersion
        self.documentSignerCertificate = documentSignerCertificate
        self.signedAttributes = signedAttributes
        self.signature = signature
        self.signatureAlgorithmOID = signatureAlgorithmOID
        self.encapsulatedContent = encapsulatedContent
        self.rawCMSData = rawCMSData
    }
}
