import Foundation

@available(*, deprecated, renamed: "ActiveAuthenticationPublicKey")
public typealias ActiveAuthPublicKey = ActiveAuthenticationPublicKey

/// Parsed Active Authentication public key from DG15.
public enum ActiveAuthenticationPublicKey: Sendable, Equatable, Codable {
    /// RSA public key with modulus and exponent.
    case rsa(modulus: Data, exponent: Data)
    /// ECDSA public key with curve OID and uncompressed point.
    case ecdsa(curveOID: String, publicPoint: Data)
    /// Unknown key type — store raw SubjectPublicKeyInfo bytes.
    case unknown(Data)
}

/// Parser for DG15 (Active Authentication Public Key).
///
/// TLV wrapper tag: 0x6F
/// Contains a SubjectPublicKeyInfo ASN.1 structure:
///
/// ```asn1
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier,
///     subjectPublicKey  BIT STRING
/// }
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm  OBJECT IDENTIFIER,
///     parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
///
/// References:
/// - ICAO Doc 9303 Part 10, Section 4.7.15 (EF.DG15 — Active Authentication Public Key)
/// - ICAO Doc 9303 Part 11, Section 6.2 (AA public key: RSA or ECDSA)
/// - RFC 5280, Section 4.1 (SubjectPublicKeyInfo ASN.1 definition)
/// - RFC 3279 (RSA, DSA, ECDSA algorithm identifiers for SubjectPublicKeyInfo)
public enum DG15Parser {
    /// Known algorithm OIDs for public key types.
    public static let rsaOID = "1.2.840.113549.1.1.1" // rsaEncryption
    public static let ecPublicKeyOID = "1.2.840.10045.2.1" // id-ecPublicKey

    /// Parse DG15 raw data into an ActiveAuthenticationPublicKey.
    public static func parse(_ data: Data) throws -> ActiveAuthenticationPublicKey {
        // Parse outer TLV: tag 0x6F wrapping SubjectPublicKeyInfo
        let nodes = try ASN1Parser.parseTLV(data)

        // Find the content — may be wrapped in 0x6F tag or be a bare SEQUENCE
        let spkiData: Data = if let dgNode = nodes.first(where: { $0.tag == 0x6F }) {
            dgNode.value
        } else {
            data
        }

        // Parse to find the SubjectPublicKeyInfo SEQUENCE
        let spkiNodes = try ASN1Parser.parseTLV(spkiData)
        guard let spkiSeq = spkiNodes.first(where: { $0.tag == 0x30 }) else {
            return .unknown(data)
        }

        // Parse SubjectPublicKeyInfo SEQUENCE children: AlgorithmIdentifier + BIT STRING
        let spkiChildren = try spkiSeq.children()
        guard spkiChildren.count >= 2 else {
            return .unknown(data)
        }

        // First child: AlgorithmIdentifier SEQUENCE
        let algIdNode = spkiChildren[0]
        guard algIdNode.tag == 0x30 else {
            return .unknown(data)
        }
        let algIdChildren = try algIdNode.children()
        guard let oidNode = algIdChildren.first, oidNode.tag == 0x06 else {
            return .unknown(data)
        }
        let algorithmOID = DG14Parser.decodeOID(oidNode.value)

        // Second child: subjectPublicKey BIT STRING
        let bitStringNode = spkiChildren[1]
        guard bitStringNode.tag == 0x03, !bitStringNode.value.isEmpty else {
            return .unknown(data)
        }
        // BIT STRING: first byte is number of unused bits (usually 0)
        let unusedBits = bitStringNode.value[0]
        let publicKeyBits = Data(bitStringNode.value.dropFirst())

        switch algorithmOID {
        case Self.rsaOID:
            return try parseRSAPublicKey(publicKeyBits)

        case Self.ecPublicKeyOID:
            // EC parameters are in the AlgorithmIdentifier
            let curveOID: String = if algIdChildren.count > 1, algIdChildren[1].tag == 0x06 {
                DG14Parser.decodeOID(algIdChildren[1].value)
            } else {
                "unknown"
            }
            // For EC keys, the public key bits ARE the uncompressed point
            // If there are unused bits, we should handle it but usually it's 0
            _ = unusedBits
            return .ecdsa(curveOID: curveOID, publicPoint: publicKeyBits)

        default:
            return .unknown(data)
        }
    }

    /// Extract the DER SubjectPublicKeyInfo from DG15, unchanged.
    ///
    /// ECDSA keys may carry explicit ECParameters instead of a named-curve OID
    /// (BSI TR-03111, ICAO 9303-11 §6.1); passing the original SPKI to the verifier
    /// keeps those parameters intact.
    public static func subjectPublicKeyInfo(_ data: Data) -> Data? {
        guard let nodes = try? ASN1Parser.parseTLV(data) else { return nil }
        let spkiData = nodes.first(where: { $0.tag == 0x6F })?.value ?? data
        guard let spkiNodes = try? ASN1Parser.parseTLV(spkiData),
              let spkiSeq = spkiNodes.first(where: { $0.tag == 0x30 })
        else {
            return nil
        }
        return ASN1Parser.encodeTLV(tag: 0x30, value: spkiSeq.value)
    }

    /// Parse an RSA public key from the BIT STRING content.
    ///
    /// RSAPublicKey ::= SEQUENCE {
    ///     modulus  INTEGER,
    ///     publicExponent  INTEGER
    /// }
    public static func parseRSAPublicKey(_ data: Data) throws -> ActiveAuthenticationPublicKey {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let seqNode = nodes.first(where: { $0.tag == 0x30 }) else {
            return .unknown(data)
        }
        let children = try seqNode.children()
        guard children.count >= 2,
              children[0].tag == 0x02,
              children[1].tag == 0x02
        else {
            return .unknown(data)
        }

        var modulus = children[0].value
        var exponent = children[1].value

        // Strip leading zero byte from INTEGER encoding (sign byte)
        if modulus.count > 1, modulus[0] == 0x00 {
            modulus = Data(modulus.dropFirst())
        }
        if exponent.count > 1, exponent[0] == 0x00 {
            exponent = Data(exponent.dropFirst())
        }

        return .rsa(modulus: modulus, exponent: exponent)
    }
}
