import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

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

/// Parser for SOD (Security Object Document).
///
/// TLV wrapper tag: 0x77
/// Contains a CMS SignedData structure wrapping the LDS Security Object.
///
/// Structure overview:
/// ```
/// 0x77 [SOD wrapper]
///   └── 0x30 SEQUENCE (ContentInfo)
///       ├── 0x06 OID (1.2.840.113549.1.7.2 = id-signedData)
///       └── [0] EXPLICIT (A0)
///           └── 0x30 SEQUENCE (SignedData)
///               ├── 0x02 INTEGER (version = 3)
///               ├── 0x31 SET (digestAlgorithms)
///               ├── 0x30 SEQUENCE (encapContentInfo)
///               │   ├── 0x06 OID (2.23.136.1.1.1 = id-icao-ldsSecurityObject)
///               │   └── [0] EXPLICIT (A0)
///               │       └── 0x04 OCTET STRING (LDSSecurityObject)
///               ├── [0] IMPLICIT (A0) OPTIONAL (certificates)
///               └── 0x31 SET (signerInfos)
/// ```
///
/// References:
/// - ICAO Doc 9303 Part 10, Section 4.6.2 (LDS Security Object / SOD)
/// - ICAO Doc 9303 Part 10, Section 4.6.2.2 (LDSSecurityObject ASN.1 schema)
/// - RFC 5652, Section 5 (SignedData type — CMS/PKCS#7)
/// - RFC 5652, Section 5.4 (Message Digest Calculation: re-tag IMPLICIT [0] → SET 0x31)
/// - RFC 5280, Section 4.1.1.2 (AlgorithmIdentifier for hash algorithms)
/// - JMRTD source: SODFile.java (reference implementation)
enum SODParser {
    // MARK: - Known OIDs

    private static let signedDataOID = "1.2.840.113549.1.7.2"
    /// Hash algorithm OIDs to names.
    private static let hashAlgorithmNames: [String: String] = [
        "1.3.14.3.2.26": "SHA-1",
        "2.16.840.1.101.3.4.2.1": "SHA-256",
        "2.16.840.1.101.3.4.2.2": "SHA-384",
        "2.16.840.1.101.3.4.2.3": "SHA-512",
        "2.16.840.1.101.3.4.2.4": "SHA-224",
    ]

    /// DataGroup tag to DataGroupId mapping for hash table.
    private static let dgTagMap: [Int: DataGroupId] = [
        1: .dg1, 2: .dg2, 3: .dg3, 4: .dg4, 5: .dg5,
        6: .dg6, 7: .dg7, 8: .dg8, 9: .dg9, 10: .dg10,
        11: .dg11, 12: .dg12, 13: .dg13, 14: .dg14, 15: .dg15, 16: .dg16,
    ]

    /// Parse SOD raw data into SODContent.
    static func parse(_ data: Data) throws -> SODContent {
        let nodes = try ASN1Parser.parseTLV(data)

        // Unwrap 0x77 wrapper if present
        let contentInfoData: Data = if let sodNode = nodes.first(where: { $0.tag == 0x77 }) {
            sodNode.value
        } else {
            data
        }

        // Parse ContentInfo SEQUENCE
        let contentInfoNodes = try ASN1Parser.parseTLV(contentInfoData)
        guard let contentInfoSeq = contentInfoNodes.first(where: { $0.tag == 0x30 }) else {
            throw NFCError.dataGroupParseFailed("SOD: Missing ContentInfo SEQUENCE")
        }

        let contentInfoChildren = try contentInfoSeq.children()
        guard contentInfoChildren.count >= 2 else {
            throw NFCError.dataGroupParseFailed("SOD: ContentInfo has fewer than 2 children")
        }

        // Verify OID is signedData
        if contentInfoChildren[0].tag == 0x06 {
            let oid = DG14Parser.decodeOID(contentInfoChildren[0].value)
            guard oid == Self.signedDataOID else {
                throw NFCError.dataGroupParseFailed("SOD: Expected signedData OID, got \(oid)")
            }
        }

        // Find explicit [0] context tag (0xA0) containing SignedData
        guard let explicitContent = contentInfoChildren.first(where: { $0.tag == 0xA0 }) else {
            throw NFCError.dataGroupParseFailed("SOD: Missing explicit [0] wrapper for SignedData")
        }

        // Parse SignedData SEQUENCE
        let signedDataNodes = try ASN1Parser.parseTLV(explicitContent.value)
        guard let signedDataSeq = signedDataNodes.first(where: { $0.tag == 0x30 }) else {
            throw NFCError.dataGroupParseFailed("SOD: Missing SignedData SEQUENCE")
        }
        let sdChildren = try signedDataSeq.children()

        // Extract components
        var hashAlgOID = ""
        var hashAlgName = "Unknown"
        var dgHashes: [DataGroupId: Data] = [:]
        var ldsVersion: String?
        var unicodeVersion: String?
        var dscData: Data?
        var signedAttrs: Data?
        var signatureData: Data?
        var sigAlgOID: String?
        var encapContent: Data?

        for child in sdChildren {
            switch child.tag {
            case 0x31:
                // Could be digestAlgorithms SET or signerInfos SET
                if hashAlgOID.isEmpty {
                    // First SET = digestAlgorithms
                    if let algSeq = try? child.children().first(where: { $0.tag == 0x30 }),
                       let oidNode = try? algSeq.children().first(where: { $0.tag == 0x06 })
                    {
                        hashAlgOID = DG14Parser.decodeOID(oidNode.value)
                        hashAlgName = Self.hashAlgorithmNames[hashAlgOID] ?? hashAlgOID
                    }
                } else {
                    // Second SET = signerInfos
                    parseSignerInfos(child.value, sigAlgOID: &sigAlgOID,
                                     signedAttrs: &signedAttrs, signature: &signatureData)
                }

            case 0x30:
                // EncapsulatedContentInfo SEQUENCE
                let ecChildren = (try? child.children()) ?? []
                for ecChild in ecChildren {
                    if ecChild.tag == 0xA0 {
                        // Explicit [0] contains OCTET STRING with LDS Security Object
                        if let octetString = try? ASN1Parser.parseTLV(ecChild.value).first(where: { $0.tag == 0x04 }) {
                            encapContent = octetString.value
                            parseLDSSecurityObject(
                                octetString.value,
                                hashAlgOID: &hashAlgOID,
                                hashAlgName: &hashAlgName,
                                dgHashes: &dgHashes,
                                ldsVersion: &ldsVersion,
                                unicodeVersion: &unicodeVersion
                            )
                        }
                    }
                }

            case 0xA0:
                // [0] IMPLICIT = certificates
                // Extract first certificate (DER SEQUENCE)
                if let certSeq = try? ASN1Parser.parseTLV(child.value).first(where: { $0.tag == 0x30 }) {
                    // Re-encode the certificate with its TLV wrapper
                    dscData = ASN1Parser.encodeTLV(tag: 0x30, value: certSeq.value)
                }

            default:
                break
            }
        }

        return SODContent(
            hashAlgorithmOID: hashAlgOID,
            hashAlgorithm: hashAlgName,
            dataGroupHashes: dgHashes,
            ldsVersion: ldsVersion,
            unicodeVersion: unicodeVersion,
            documentSignerCertificate: dscData,
            signedAttributes: signedAttrs,
            signature: signatureData,
            signatureAlgorithmOID: sigAlgOID,
            encapsulatedContent: encapContent,
            rawCMSData: contentInfoData
        )
    }

    // MARK: - LDS Security Object

    /// Parse the LDS Security Object (inside the EncapsulatedContentInfo).
    ///
    /// ```asn1
    /// LDSSecurityObject ::= SEQUENCE {
    ///     version             LDSSecurityObjectVersion,   -- INTEGER (0 or 1)
    ///     hashAlgorithm       DigestAlgorithmIdentifier,
    ///     dataGroupHashValues SEQUENCE OF DataGroupHash,
    ///     ldsVersionInfo      LDSVersionInfo OPTIONAL     -- only if version = 1
    /// }
    ///
    /// DataGroupHash ::= SEQUENCE {
    ///     dataGroupNumber  DataGroupNumber,  -- INTEGER
    ///     dataGroupHashValue  OCTET STRING
    /// }
    /// ```
    private static func parseLDSSecurityObject(
        _ data: Data,
        hashAlgOID: inout String,
        hashAlgName: inout String,
        dgHashes: inout [DataGroupId: Data],
        ldsVersion: inout String?,
        unicodeVersion: inout String?
    ) {
        guard let nodes = try? ASN1Parser.parseTLV(data),
              let seqNode = nodes.first(where: { $0.tag == 0x30 }),
              let children = try? seqNode.children()
        else { return }

        for child in children {
            switch child.tag {
            case 0x02:
                // Version INTEGER — skip
                break

            case 0x30:
                // Could be hashAlgorithm or LDSVersionInfo or DataGroupHash
                let subChildren = (try? child.children()) ?? []
                if subChildren.count >= 1, subChildren[0].tag == 0x06 {
                    // AlgorithmIdentifier: OID + optional parameters (RFC 5754 §2: SHA-2
                    // identifiers SHOULD omit the NULL parameters). The LDSSecurityObject
                    // hashAlgorithm governs DG hashes (ICAO 9303-10 §4.6.2.2).
                    let oid = DG14Parser.decodeOID(subChildren[0].value)
                    if hashAlgOID.isEmpty || Self.hashAlgorithmNames[oid] != nil {
                        hashAlgOID = oid
                        hashAlgName = Self.hashAlgorithmNames[oid] ?? oid
                    }
                } else if subChildren.count == 2,
                          subChildren[0].tag == 0x16 || subChildren[0].tag == 0x04,
                          subChildren[1].tag == 0x16 || subChildren[1].tag == 0x04
                {
                    // LDSVersionInfo: two IA5String or OCTET STRING
                    ldsVersion = String(data: subChildren[0].value, encoding: .ascii)
                    unicodeVersion = String(data: subChildren[1].value, encoding: .ascii)
                }

            case 0x31:
                // SET — shouldn't appear inside LDS Security Object
                break

            default:
                // Check if this is the SEQUENCE OF DataGroupHash
                // Try parsing as sequence of SEQUENCE
                break
            }
        }

        // Find the SEQUENCE OF DataGroupHash
        for child in children where child.tag == 0x30 {
            let subChildren = (try? child.children()) ?? []
            // A DataGroupHash has INTEGER + OCTET STRING
            if subChildren.count == 2, subChildren[0].tag == 0x02, subChildren[1].tag == 0x04 {
                let dgNumber = DG14Parser.decodeInteger(subChildren[0].value)
                if let dgId = Self.dgTagMap[dgNumber] {
                    dgHashes[dgId] = subChildren[1].value
                }
            }
        }

        // If we didn't find individual DG hashes in top-level SEQUENCEs,
        // look for a SEQUENCE OF (container for DataGroupHash entries)
        if dgHashes.isEmpty {
            for child in children {
                if child.tag == 0x30, let dgChildren = try? child.children(),
                   dgChildren.allSatisfy({ $0.tag == 0x30 })
                {
                    // This is the SEQUENCE OF DataGroupHash
                    for dgHashNode in dgChildren {
                        let parts = (try? dgHashNode.children()) ?? []
                        if parts.count == 2, parts[0].tag == 0x02, parts[1].tag == 0x04 {
                            let dgNumber = DG14Parser.decodeInteger(parts[0].value)
                            if let dgId = Self.dgTagMap[dgNumber] {
                                dgHashes[dgId] = parts[1].value
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Signer Info

    /// Parse SignerInfos SET to extract signature algorithm and signature.
    private static func parseSignerInfos(
        _ data: Data,
        sigAlgOID: inout String?,
        signedAttrs: inout Data?,
        signature: inout Data?
    ) {
        guard let nodes = try? ASN1Parser.parseTLV(data) else { return }

        // First SEQUENCE in the SET is the SignerInfo
        guard let signerInfoSeq = nodes.first(where: { $0.tag == 0x30 }),
              let children = try? signerInfoSeq.children()
        else { return }

        for child in children {
            switch child.tag {
            case 0xA0:
                // [0] IMPLICIT = signedAttrs
                // Store the original DER encoding (re-tagged as SET 0x31 for CMS signature verification)
                // Per RFC 5652 Section 5.4: For verification, the IMPLICIT [0] tag must be
                // replaced with EXPLICIT SET (0x31) before computing the digest.
                signedAttrs = ASN1Parser.encodeTLV(tag: 0x31, value: child.value)

            case 0x30:
                // Could be issuerAndSerialNumber or digestAlgorithm or signatureAlgorithm
                let subChildren = (try? child.children()) ?? []
                if let oidNode = subChildren.first(where: { $0.tag == 0x06 }) {
                    let oid = DG14Parser.decodeOID(oidNode.value)
                    // The signature algorithm OID comes after the signed attrs
                    if signedAttrs != nil, sigAlgOID == nil {
                        sigAlgOID = oid
                    }
                }

            case 0x04:
                // OCTET STRING = signature value
                signature = child.value

            default:
                break
            }
        }
    }

    // MARK: - Passive Authentication (Hash Verification)

    /// Verify data group hashes against the hashes stored in SOD.
    ///
    /// - Important: This only verifies that computed DG hashes match the SOD-stored hashes.
    ///   It does NOT verify the SOD's CMS signature or the certificate trust chain.
    ///   Full passive authentication requires OpenSSL or equivalent for CMS verification.
    ///
    /// - Parameters:
    ///   - sodContent: Parsed SOD content with expected hashes.
    ///   - rawDataGroups: Raw data group bytes as read from the chip.
    /// - Returns: PassiveAuthenticationResult with per-DG hash verification results.
    static func verifyHashes(
        sodContent: SODContent,
        rawDataGroups: [DataGroupId: Data]
    ) -> PassiveAuthenticationResult {
        var results: [DataGroupId: Bool] = [:]

        // Validate hash algorithm is known before proceeding
        let knownAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-224"]
        guard knownAlgorithms.contains(sodContent.hashAlgorithm) else {
            return PassiveAuthenticationResult(
                dataGroupHashResults: [:],
                hasCertificate: sodContent.documentSignerCertificate != nil,
                cmsSignatureValid: nil,
                trustChainValid: nil,
                status: .unsupportedHashAlgorithm
            )
        }

        // For each DG hash in the SOD, compute the hash of the raw data and compare
        for (dgId, expectedHash) in sodContent.dataGroupHashes {
            guard let rawData = rawDataGroups[dgId] else {
                // DG not read — skip (don't mark as failed)
                continue
            }

            let computedHash: Data
            switch sodContent.hashAlgorithm {
            case "SHA-1":
                computedHash = HashUtils.sha1(rawData)
            case "SHA-256":
                computedHash = HashUtils.sha256(rawData)
            case "SHA-384":
                computedHash = HashUtils.sha384(rawData)
            case "SHA-512":
                computedHash = HashUtils.sha512(rawData)
            case "SHA-224":
                computedHash = HashUtils.sha224(rawData)
            default:
                // This shouldn't be reached due to the guard above
                continue
            }

            results[dgId] = (computedHash == expectedHash)
        }

        // ICAO 9303-11 §5.1: every data group read must be checked against the SOD.
        // A DG1–DG16 that was read but has no hash in the SOD cannot be authenticated.
        for (dgId, _) in rawDataGroups where dgId != .com && dgId != .sod {
            if sodContent.dataGroupHashes[dgId] == nil {
                results[dgId] = false
            }
        }

        let allValid = !results.isEmpty && results.values.allSatisfy(\.self)

        // Use signatureNotVerified when hashes pass — makes clear that CMS
        // signature verification was NOT performed
        let status: PassiveAuthStatus = if allValid {
            .signatureNotVerified
        } else {
            .hashMismatch
        }

        return PassiveAuthenticationResult(
            dataGroupHashResults: results,
            hasCertificate: sodContent.documentSignerCertificate != nil,
            cmsSignatureValid: nil,
            trustChainValid: nil,
            status: status
        )
    }

    /// Verify passive authentication using both DG hashes and CMS signature when available.
    static func verifyPassiveAuthentication(
        sodContent: SODContent,
        rawDataGroups: [DataGroupId: Data],
        trustAnchorsDER: [Data] = []
    ) -> PassiveAuthenticationResult {
        let hashResult = verifyHashes(sodContent: sodContent, rawDataGroups: rawDataGroups)

        guard hashResult.allHashesValid else {
            return hashResult
        }

        let cmsStatus = verifyCMSSignature(sodContent: sodContent)
        switch cmsStatus {
        case .unavailable:
            return hashResult
        case .verified:
            if trustAnchorsDER.isEmpty {
                return PassiveAuthenticationResult(
                    dataGroupHashResults: hashResult.dataGroupHashResults,
                    hasCertificate: hashResult.hasCertificate,
                    cmsSignatureValid: true,
                    trustChainValid: nil,
                    status: .signatureVerified
                )
            }

            let trustValid = verifyTrustChain(
                documentSignerCertificateDER: sodContent.documentSignerCertificate,
                trustAnchorsDER: trustAnchorsDER
            )
            return PassiveAuthenticationResult(
                dataGroupHashResults: hashResult.dataGroupHashResults,
                hasCertificate: hashResult.hasCertificate,
                cmsSignatureValid: true,
                trustChainValid: trustValid,
                status: trustValid ? .fullyVerified : .trustChainInvalid
            )
        case .invalid:
            return PassiveAuthenticationResult(
                dataGroupHashResults: hashResult.dataGroupHashResults,
                hasCertificate: hashResult.hasCertificate,
                cmsSignatureValid: false,
                trustChainValid: nil,
                status: .signatureInvalid
            )
        }
    }

    private enum CMSSignatureStatus {
        case unavailable
        case verified
        case invalid
    }

    private static func verifyCMSSignature(sodContent: SODContent) -> CMSSignatureStatus {
        guard let rawCMSData = sodContent.rawCMSData,
              sodContent.documentSignerCertificate != nil,
              sodContent.signature != nil
        else {
            return .unavailable
        }

        #if canImport(OpenSSL)
            guard let input = BIO_new(BIO_s_mem()), let output = BIO_new(BIO_s_mem()) else {
                return .invalid
            }
            defer {
                BIO_free(input)
                BIO_free(output)
            }

            let writeCount = rawCMSData.withUnsafeBytes { ptr in
                BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(rawCMSData.count))
            }
            guard writeCount == rawCMSData.count else {
                return .invalid
            }

            guard let cms = d2i_CMS_bio(input, nil) else {
                return .invalid
            }
            defer { CMS_ContentInfo_free(cms) }

            let flags = UInt32(CMS_NO_SIGNER_CERT_VERIFY)
            guard CMS_verify(cms, nil, nil, nil, output, flags) == 1 else {
                return .invalid
            }

            let length = Int(BIO_ctrl(output, BIO_CTRL_PENDING, 0, nil))
            var verifiedContent = Data(repeating: 0x00, count: length)
            _ = verifiedContent.withUnsafeMutableBytes { ptr in
                BIO_read(output, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(length))
            }

            if let encapsulatedContent = sodContent.encapsulatedContent,
               verifiedContent != encapsulatedContent
            {
                return .invalid
            }

            return .verified
        #else
            return .unavailable
        #endif
    }

    private static func verifyTrustChain(
        documentSignerCertificateDER: Data?,
        trustAnchorsDER: [Data]
    ) -> Bool {
        guard !trustAnchorsDER.isEmpty,
              let documentSignerCertificateDER,
              let signerCertificate = loadX509Certificate(documentSignerCertificateDER)
        else {
            return false
        }
        defer { X509_free(signerCertificate) }

        let anchorCertificates = trustAnchorsDER.compactMap(loadX509Certificate)
        guard !anchorCertificates.isEmpty,
              let store = X509_STORE_new(),
              let context = X509_STORE_CTX_new()
        else {
            anchorCertificates.forEach { X509_free($0) }
            return false
        }
        defer {
            X509_STORE_CTX_free(context)
            X509_STORE_free(store)
            anchorCertificates.forEach { X509_free($0) }
        }

        for certificate in anchorCertificates where X509_STORE_add_cert(store, certificate) != 1 {
            return false
        }

        guard X509_STORE_CTX_init(context, store, signerCertificate, nil) == 1 else {
            return false
        }

        return X509_verify_cert(context) == 1
    }

    private static func loadX509Certificate(_ der: Data) -> OpaquePointer? {
        guard let input = BIO_new(BIO_s_mem()) else {
            return nil
        }
        defer { BIO_free(input) }

        let writeCount = der.withUnsafeBytes { ptr in
            BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(der.count))
        }
        guard writeCount == der.count else {
            return nil
        }

        return d2i_X509_bio(input, nil)
    }
}
