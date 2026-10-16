import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

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
                    parseSignerInfos(
                        child.value,
                        sigAlgOID: &sigAlgOID,
                        signedAttrs: &signedAttrs,
                        signature: &signatureData
                    )
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

        // The certificates SET may hold several certificates in any order. The document
        // signer is the one the SignerInfo's SID names, not necessarily the first.
        if let signer = signerCertificateDER(cmsDER: contentInfoData) {
            dscData = signer
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
}
