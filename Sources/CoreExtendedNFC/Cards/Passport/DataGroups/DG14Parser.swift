import Foundation

/// Known ICAO 9303 OID values for security protocols.
///
/// References:
/// - ICAO Doc 9303 Part 11, Section 9.2 (SecurityInfo structures)
/// - BSI TR-03110 Part 3, Appendix A.1.1 (OID definitions for PACE, CA, TA)
/// - BSI TR-03110 Part 3, Table A.1 (id-PACE-*), Table A.4 (id-CA-*),
///   Table A.5 (id-PK-*), Table A.6 (id-TA-*)
/// - ICAO Doc 9303 Part 11, Section 6.2.5 (ActiveAuthenticationInfo with id-AA = 2.23.136.1.1.5)
public enum SecurityProtocol: String, Sendable, Hashable, Codable {
    // MARK: - PACE (Password Authenticated Connection Establishment)

    /// id-PACE-DH-GM-3DES-CBC-CBC
    case paceDHGM3DESCBCCBC = "0.4.0.127.0.7.2.2.4.1.1"
    /// id-PACE-DH-GM-AES-CBC-CMAC-128
    case paceDHGMAESCBCCMAC128 = "0.4.0.127.0.7.2.2.4.1.2"
    /// id-PACE-DH-GM-AES-CBC-CMAC-192
    case paceDHGMAESCBCCMAC192 = "0.4.0.127.0.7.2.2.4.1.3"
    /// id-PACE-DH-GM-AES-CBC-CMAC-256
    case paceDHGMAESCBCCMAC256 = "0.4.0.127.0.7.2.2.4.1.4"

    /// id-PACE-ECDH-GM-3DES-CBC-CBC
    case paceECDHGM3DESCBCCBC = "0.4.0.127.0.7.2.2.4.2.1"
    /// id-PACE-ECDH-GM-AES-CBC-CMAC-128
    case paceECDHGMAESCBCCMAC128 = "0.4.0.127.0.7.2.2.4.2.2"
    /// id-PACE-ECDH-GM-AES-CBC-CMAC-192
    case paceECDHGMAESCBCCMAC192 = "0.4.0.127.0.7.2.2.4.2.3"
    /// id-PACE-ECDH-GM-AES-CBC-CMAC-256
    case paceECDHGMAESCBCCMAC256 = "0.4.0.127.0.7.2.2.4.2.4"

    /// id-PACE-DH-IM-3DES-CBC-CBC
    case paceDHIM3DESCBCCBC = "0.4.0.127.0.7.2.2.4.3.1"
    /// id-PACE-DH-IM-AES-CBC-CMAC-128
    case paceDHIMAESCBCCMAC128 = "0.4.0.127.0.7.2.2.4.3.2"
    /// id-PACE-DH-IM-AES-CBC-CMAC-192
    case paceDHIMAESCBCCMAC192 = "0.4.0.127.0.7.2.2.4.3.3"
    /// id-PACE-DH-IM-AES-CBC-CMAC-256
    case paceDHIMAESCBCCMAC256 = "0.4.0.127.0.7.2.2.4.3.4"

    /// id-PACE-ECDH-IM-3DES-CBC-CBC
    case paceECDHIM3DESCBCCBC = "0.4.0.127.0.7.2.2.4.4.1"
    /// id-PACE-ECDH-IM-AES-CBC-CMAC-128
    case paceECDHIMAESCBCCMAC128 = "0.4.0.127.0.7.2.2.4.4.2"
    /// id-PACE-ECDH-IM-AES-CBC-CMAC-192
    case paceECDHIMAESCBCCMAC192 = "0.4.0.127.0.7.2.2.4.4.3"
    /// id-PACE-ECDH-IM-AES-CBC-CMAC-256
    case paceECDHIMAESCBCCMAC256 = "0.4.0.127.0.7.2.2.4.4.4"

    // MARK: - Chip Authentication (CA)

    /// id-CA-DH-3DES-CBC-CBC
    case caDH3DESCBCCBC = "0.4.0.127.0.7.2.2.3.1.1"
    /// id-CA-DH-AES-CBC-CMAC-128
    case caDHAESCBCCMAC128 = "0.4.0.127.0.7.2.2.3.1.2"
    /// id-CA-DH-AES-CBC-CMAC-192
    case caDHAESCBCCMAC192 = "0.4.0.127.0.7.2.2.3.1.3"
    /// id-CA-DH-AES-CBC-CMAC-256
    case caDHAESCBCCMAC256 = "0.4.0.127.0.7.2.2.3.1.4"

    /// id-CA-ECDH-3DES-CBC-CBC
    case caECDH3DESCBCCBC = "0.4.0.127.0.7.2.2.3.2.1"
    /// id-CA-ECDH-AES-CBC-CMAC-128
    case caECDHAESCBCCMAC128 = "0.4.0.127.0.7.2.2.3.2.2"
    /// id-CA-ECDH-AES-CBC-CMAC-192
    case caECDHAESCBCCMAC192 = "0.4.0.127.0.7.2.2.3.2.3"
    /// id-CA-ECDH-AES-CBC-CMAC-256
    case caECDHAESCBCCMAC256 = "0.4.0.127.0.7.2.2.3.2.4"

    // MARK: - Chip Authentication Public Key (id-PK)

    /// id-PK-DH — DH public key for Chip Authentication
    case pkDH = "0.4.0.127.0.7.2.2.1.1"
    /// id-PK-ECDH — ECDH public key for Chip Authentication
    case pkECDH = "0.4.0.127.0.7.2.2.1.2"

    // MARK: - Active Authentication (AA)

    /// id-AA — Active Authentication (the only valid AA OID per ICAO 9303)
    case aaRSA = "2.23.136.1.1.5"

    // MARK: - Terminal Authentication (TA)

    /// id-TA-RSA-v1-5-SHA-1
    case taRSAv15SHA1 = "0.4.0.127.0.7.2.2.2.1.1"
    /// id-TA-RSA-v1-5-SHA-256
    case taRSAv15SHA256 = "0.4.0.127.0.7.2.2.2.1.2"
    /// id-TA-RSA-PSS-SHA-1
    case taRSAPSSSHA1 = "0.4.0.127.0.7.2.2.2.1.3"
    /// id-TA-RSA-PSS-SHA-256
    case taRSAPSSSHA256 = "0.4.0.127.0.7.2.2.2.1.4"
    /// id-TA-ECDSA-SHA-1
    case taECDSASHA1 = "0.4.0.127.0.7.2.2.2.2.1"
    /// id-TA-ECDSA-SHA-224 (BSI TR-03110-3 Appendix A: id-TA-ECDSA 2)
    case taECDSASHA224 = "0.4.0.127.0.7.2.2.2.2.2"
    /// id-TA-ECDSA-SHA-256 (BSI TR-03110-3 Appendix A: id-TA-ECDSA 3)
    case taECDSASHA256 = "0.4.0.127.0.7.2.2.2.2.3"
    /// id-TA-ECDSA-SHA-384
    case taECDSASHA384 = "0.4.0.127.0.7.2.2.2.2.4"
    /// id-TA-ECDSA-SHA-512
    case taECDSASHA512 = "0.4.0.127.0.7.2.2.2.2.5"

    /// Whether this is a PACE protocol.
    public var isPACE: Bool {
        rawValue.hasPrefix("0.4.0.127.0.7.2.2.4")
    }

    /// Whether this is a Chip Authentication protocol (id-CA-*).
    public var isChipAuthentication: Bool {
        rawValue.hasPrefix("0.4.0.127.0.7.2.2.3")
    }

    /// Whether this is a Chip Authentication Public Key (id-PK-DH or id-PK-ECDH).
    public var isChipAuthenticationPublicKey: Bool {
        self == .pkDH || self == .pkECDH
    }

    /// Whether this is a Terminal Authentication protocol (id-TA-*).
    public var isTerminalAuthentication: Bool {
        rawValue.hasPrefix("0.4.0.127.0.7.2.2.2")
    }

    /// Whether this is Active Authentication (id-AA).
    public var isActiveAuthentication: Bool {
        self == .aaRSA
    }

    /// Whether this uses ECDH key agreement.
    public var isECDH: Bool {
        switch self {
        case .paceECDHGM3DESCBCCBC, .paceECDHGMAESCBCCMAC128,
             .paceECDHGMAESCBCCMAC192, .paceECDHGMAESCBCCMAC256,
             .paceECDHIM3DESCBCCBC, .paceECDHIMAESCBCCMAC128,
             .paceECDHIMAESCBCCMAC192, .paceECDHIMAESCBCCMAC256,
             .caECDH3DESCBCCBC, .caECDHAESCBCCMAC128,
             .caECDHAESCBCCMAC192, .caECDHAESCBCCMAC256:
            true
        default:
            false
        }
    }

    /// Whether this uses AES cipher.
    public var isAES: Bool {
        rawValue.hasSuffix(".2") || rawValue.hasSuffix(".3") || rawValue.hasSuffix(".4")
    }

    /// AES key length in bytes for this protocol (nil if not AES).
    public var aesKeyLength: Int? {
        guard isAES else { return nil }
        if rawValue.hasSuffix(".2") { return 16 }
        if rawValue.hasSuffix(".3") { return 24 }
        if rawValue.hasSuffix(".4") { return 32 }
        return nil
    }
}

/// Parsed PACE protocol info from DG14.
public struct PACEInfo: Sendable, Equatable, Codable {
    /// The PACE protocol OID.
    public let protocolOID: String
    /// Resolved protocol enum (nil if unknown OID).
    public let securityProtocol: SecurityProtocol?
    /// Protocol version (usually 2).
    public let version: Int
    /// Standard domain parameter ID (e.g., 0 = no std params, 8-15 = ECDH named curves).
    /// - 8: secp192r1
    /// - 9: BrainpoolP192r1
    /// - 10: secp224r1
    /// - 11: BrainpoolP224r1
    /// - 12: secp256r1 (P-256)
    /// - 13: BrainpoolP256r1
    /// - 14: BrainpoolP320r1
    /// - 15: secp384r1 (P-384)
    /// - 16: BrainpoolP384r1
    /// - 17: BrainpoolP512r1
    /// - 18: secp521r1 (P-521)
    public let parameterID: Int?
}

/// Parsed PACEDomainParameterInfo (ICAO 9303-11 §9.2, BSI TR-03110-3 A.1.1.1).
///
/// ```asn1
/// PACEDomainParameterInfo ::= SEQUENCE {
///     protocol        OBJECT IDENTIFIER (id-PACE-DH-GM | id-PACE-ECDH-GM |
///                                        id-PACE-DH-IM | id-PACE-ECDH-IM | id-PACE-ECDH-CAM),
///     domainParameter AlgorithmIdentifier,
///     parameterId     INTEGER OPTIONAL
/// }
/// ```
///
/// Explicit (proprietary) domain parameters. ``PACEHandler`` runs PACE only with
/// standardized domain parameters, so these are recorded but not used.
public struct PACEDomainParameterInfo: Sendable, Equatable, Codable {
    /// The key agreement / mapping OID (10 arcs, e.g. `0.4.0.127.0.7.2.2.4.2` = id-PACE-ECDH-GM).
    public let protocolOID: String
    /// DER encoding of the `domainParameter` AlgorithmIdentifier.
    public let domainParameter: Data
    /// Identifier that a PACEInfo with the same `parameterId` refers to.
    public let parameterID: Int?

    public init(protocolOID: String, domainParameter: Data, parameterID: Int?) {
        self.protocolOID = protocolOID
        self.domainParameter = domainParameter
        self.parameterID = parameterID
    }
}

/// Parsed Chip Authentication info from DG14.
public struct ChipAuthenticationInfo: Sendable, Equatable, Codable {
    /// The CA protocol OID.
    public let protocolOID: String
    /// Resolved protocol enum (nil if unknown OID).
    public let securityProtocol: SecurityProtocol?
    /// Protocol version (usually 1).
    public let version: Int
    /// Key ID (used to match with ChipAuthenticationPublicKeyInfo).
    public let keyID: Int?
}

/// Parsed Chip Authentication Public Key info from DG14.
public struct ChipAuthenticationPublicKeyInfo: Sendable, Equatable, Codable {
    /// The key agreement algorithm OID (e.g., id-ecPublicKey = "1.2.840.10045.2.1").
    public let protocolOID: String
    /// Raw SubjectPublicKeyInfo bytes.
    public let subjectPublicKey: Data
    /// Key ID (used to match with ChipAuthenticationInfo).
    public let keyID: Int?
}

/// Parsed Active Authentication info from DG14.
public struct ActiveAuthenticationInfo: Sendable, Equatable, Codable {
    /// The AA protocol OID.
    public let protocolOID: String
    /// Resolved protocol enum (nil if unknown OID).
    public let securityProtocol: SecurityProtocol?
    /// Protocol version.
    public let version: Int
    /// Signature algorithm OID.
    public let signatureAlgorithmOID: String?
}

/// Aggregated DG14 / EF.CardAccess security info.
public struct SecurityInfos: Sendable, Equatable, Codable {
    public let paceInfos: [PACEInfo]
    public let chipAuthInfos: [ChipAuthenticationInfo]
    public let chipAuthPublicKeyInfos: [ChipAuthenticationPublicKeyInfo]
    public let activeAuthInfos: [ActiveAuthenticationInfo]
    public let terminalAuthInfos: [TerminalAuthenticationInfo]
    /// PACEDomainParameterInfo entries (explicit PACE domain parameters).
    public let paceDomainParameterInfos: [PACEDomainParameterInfo]

    public init(
        paceInfos: [PACEInfo],
        chipAuthInfos: [ChipAuthenticationInfo],
        chipAuthPublicKeyInfos: [ChipAuthenticationPublicKeyInfo],
        activeAuthInfos: [ActiveAuthenticationInfo],
        terminalAuthInfos: [TerminalAuthenticationInfo] = [],
        paceDomainParameterInfos: [PACEDomainParameterInfo] = []
    ) {
        self.paceInfos = paceInfos
        self.chipAuthInfos = chipAuthInfos
        self.chipAuthPublicKeyInfos = chipAuthPublicKeyInfos
        self.activeAuthInfos = activeAuthInfos
        self.terminalAuthInfos = terminalAuthInfos
        self.paceDomainParameterInfos = paceDomainParameterInfos
    }

    private enum CodingKeys: String, CodingKey {
        case paceInfos, chipAuthInfos, chipAuthPublicKeyInfos, activeAuthInfos
        case terminalAuthInfos, paceDomainParameterInfos
    }

    /// Decodes models saved before `terminalAuthInfos` / `paceDomainParameterInfos` existed.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        paceInfos = try container.decode([PACEInfo].self, forKey: .paceInfos)
        chipAuthInfos = try container.decode([ChipAuthenticationInfo].self, forKey: .chipAuthInfos)
        chipAuthPublicKeyInfos = try container.decode(
            [ChipAuthenticationPublicKeyInfo].self,
            forKey: .chipAuthPublicKeyInfos
        )
        activeAuthInfos = try container.decode([ActiveAuthenticationInfo].self, forKey: .activeAuthInfos)
        terminalAuthInfos = try container.decodeIfPresent(
            [TerminalAuthenticationInfo].self,
            forKey: .terminalAuthInfos
        ) ?? []
        paceDomainParameterInfos = try container.decodeIfPresent(
            [PACEDomainParameterInfo].self,
            forKey: .paceDomainParameterInfos
        ) ?? []
    }

    /// Whether PACE is supported by this document.
    public var supportsPACE: Bool {
        !paceInfos.isEmpty
    }

    /// Whether Chip Authentication is supported.
    public var supportsChipAuthentication: Bool {
        !chipAuthInfos.isEmpty
    }

    /// Whether Active Authentication is supported.
    public var supportsActiveAuthentication: Bool {
        !activeAuthInfos.isEmpty
    }

    /// Whether Terminal Authentication info is present.
    public var hasTerminalAuthentication: Bool {
        !terminalAuthInfos.isEmpty
    }
}

/// Parsed Terminal Authentication info from DG14.
public struct TerminalAuthenticationInfo: Sendable, Equatable, Codable {
    /// The TA protocol OID.
    public let protocolOID: String
    /// Resolved protocol enum (nil if unknown OID).
    public let securityProtocol: SecurityProtocol?
    /// Protocol version.
    public let version: Int
}

/// Parser for DG14 (Security Info).
///
/// TLV wrapper tag: 0x6E
/// Contains a SET of SecurityInfo SEQUENCE structures, each with:
///   - OID (protocol identifier)
///   - version INTEGER
///   - optional parameters
///
/// References:
/// - ICAO Doc 9303 Part 10, Section 4.7.14 (EF.DG14 structure)
/// - ICAO Doc 9303 Part 11, Section 9.2 (SecurityInfo ASN.1 definitions)
/// - BSI TR-03110 Part 3, Section A.1 (SecurityInfo OID tree: 0.4.0.127.0.7.2.2.*)
/// - JMRTD source: DG14File.java (reference implementation for OID classification)
public enum DG14Parser {
    /// Parse DG14 raw data into SecurityInfos.
    public static func parse(_ data: Data) throws -> SecurityInfos {
        try parseSecurityInfos(data, wrapperTag: 0x6E)
    }

    public static func parseSecurityInfos(_ data: Data, wrapperTag: UInt?) throws -> SecurityInfos {
        let nodes = try ASN1Parser.parseTLV(data)
        var innerData: Data = if let wrapperTag,
                                 let wrappedNode = nodes.first(where: { $0.tag == wrapperTag })
        {
            wrappedNode.value
        } else {
            data
        }

        if let innerNodes = try? ASN1Parser.parseTLV(innerData),
           let setNode = innerNodes.first(where: { $0.tag == 0x31 })
        {
            innerData = setNode.value
        }

        let infoNodes = try ASN1Parser.parseTLV(innerData)

        var paceInfos: [PACEInfo] = []
        var chipAuthInfos: [ChipAuthenticationInfo] = []
        var chipAuthPublicKeyInfos: [ChipAuthenticationPublicKeyInfo] = []
        var activeAuthInfos: [ActiveAuthenticationInfo] = []
        var terminalAuthInfos: [TerminalAuthenticationInfo] = []
        var paceDomainParameterInfos: [PACEDomainParameterInfo] = []

        for node in infoNodes where node.tag == 0x30 {
            guard let children = try? node.children(), !children.isEmpty else { continue }

            // First element must be OID (tag 0x06)
            guard let oidNode = children.first, oidNode.tag == 0x06 else { continue }
            let oid = decodeOID(oidNode.value)

            let protocol_ = SecurityProtocol(rawValue: oid)

            if oid.hasPrefix("0.4.0.127.0.7.2.2.4.") {
                // PACE (ICAO 9303-11 §9.2). PACEInfo names a full protocol (11 arcs,
                // e.g. id-PACE-ECDH-GM-AES-CBC-CMAC-128) followed by INTEGER version;
                // PACEDomainParameterInfo names only the key agreement and mapping (10
                // arcs, e.g. id-PACE-ECDH-GM) followed by an AlgorithmIdentifier.
                let arcCount = oid.split(separator: ".").count
                let parameterID = children.count > 2 && children[2].tag == 0x02
                    ? decodeInteger(children[2].value) : nil
                if arcCount == 11, children.count > 1, children[1].tag == 0x02 {
                    paceInfos.append(PACEInfo(
                        protocolOID: oid,
                        securityProtocol: protocol_,
                        version: decodeInteger(children[1].value),
                        parameterID: parameterID
                    ))
                } else if arcCount == 10, children.count > 1, children[1].tag == 0x30 {
                    paceDomainParameterInfos.append(PACEDomainParameterInfo(
                        protocolOID: oid,
                        domainParameter: ASN1Parser.encodeTLV(tag: 0x30, value: children[1].value),
                        parameterID: parameterID
                    ))
                }
            } else if oid.hasPrefix("0.4.0.127.0.7.2.2.3") {
                // Chip Authentication (id-CA: 0.4.0.127.0.7.2.2.3.*)
                let version = children.count > 1 ? decodeInteger(children[1].value) : 1
                let keyID = children.count > 2 ? decodeInteger(children[2].value) : nil
                chipAuthInfos.append(ChipAuthenticationInfo(
                    protocolOID: oid,
                    securityProtocol: protocol_,
                    version: version,
                    keyID: keyID
                ))
            } else if oid == "0.4.0.127.0.7.2.2.1.1" || oid == "0.4.0.127.0.7.2.2.1.2" {
                // Chip Authentication Public Key Info (id-PK-DH / id-PK-ECDH)
                // Per ICAO 9303: ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
                //   protocol  OBJECT IDENTIFIER (id-PK-DH | id-PK-ECDH),
                //   chipAuthenticationPublicKey  SubjectPublicKeyInfo,
                //   keyID  INTEGER OPTIONAL
                // }
                // Store the full SubjectPublicKeyInfo DER (tag+length+value), not just .value
                let subjectPublicKeyDER: Data = if children.count > 1, children[1].tag == 0x30 {
                    ASN1Parser.encodeTLV(tag: 0x30, value: children[1].value)
                } else {
                    Data()
                }
                let keyID = children.count > 2 ? decodeInteger(children[2].value) : nil
                chipAuthPublicKeyInfos.append(ChipAuthenticationPublicKeyInfo(
                    protocolOID: oid,
                    subjectPublicKey: subjectPublicKeyDER,
                    keyID: keyID
                ))
            } else if oid == "2.23.136.1.1.5" {
                // Active Authentication (id-AA) — ONLY this exact OID
                let version = children.count > 1 ? decodeInteger(children[1].value) : 1
                let sigAlgOID = children.count > 2 && children[2].tag == 0x06
                    ? decodeOID(children[2].value) : nil
                activeAuthInfos.append(ActiveAuthenticationInfo(
                    protocolOID: oid,
                    securityProtocol: protocol_,
                    version: version,
                    signatureAlgorithmOID: sigAlgOID
                ))
            } else if oid.hasPrefix("0.4.0.127.0.7.2.2.2") {
                // Terminal Authentication (id-TA: 0.4.0.127.0.7.2.2.2.*)
                // These are NOT Active Authentication — do not mix them
                let version = children.count > 1 ? decodeInteger(children[1].value) : 1
                terminalAuthInfos.append(TerminalAuthenticationInfo(
                    protocolOID: oid,
                    securityProtocol: protocol_,
                    version: version
                ))
            }
        }

        return SecurityInfos(
            paceInfos: paceInfos,
            chipAuthInfos: chipAuthInfos,
            chipAuthPublicKeyInfos: chipAuthPublicKeyInfos,
            activeAuthInfos: activeAuthInfos,
            terminalAuthInfos: terminalAuthInfos,
            paceDomainParameterInfos: paceDomainParameterInfos
        )
    }

    // MARK: - OID Decoding

    /// Decode a DER-encoded OID value into its dotted-decimal string representation.
    ///
    /// ASN.1 OID encoding:
    /// - Every subidentifier uses base-128 encoding with continuation bits (bit 7)
    /// - The first subidentifier encodes the first two arcs (X.690 §8.19.4):
    ///   value < 40 → 0.value, value < 80 → 1.(value − 40), otherwise 2.(value − 80)
    ///
    /// Returns an empty string for malformed encodings (truncated or oversized subidentifiers).
    public static func decodeOID(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }

        var subidentifiers: [UInt64] = []
        var value: UInt64 = 0
        var inProgress = false
        for byte in data {
            // Reject subidentifiers that would overflow 64 bits.
            guard value <= (UInt64.max >> 7) else { return "" }
            value = (value << 7) | UInt64(byte & 0x7F)
            inProgress = true
            if byte & 0x80 == 0 {
                subidentifiers.append(value)
                value = 0
                inProgress = false
            }
        }
        guard !inProgress, let firstSubidentifier = subidentifiers.first else { return "" }

        var components: [UInt64]
        switch firstSubidentifier {
        case 0 ..< 40:
            components = [0, firstSubidentifier]
        case 40 ..< 80:
            components = [1, firstSubidentifier - 40]
        default:
            components = [2, firstSubidentifier - 80]
        }
        components.append(contentsOf: subidentifiers.dropFirst())

        return components.map(String.init).joined(separator: ".")
    }

    /// Decode a DER-encoded INTEGER value.
    public static func decodeInteger(_ data: Data) -> Int {
        var result = 0
        for byte in data {
            result = (result << 8) | Int(byte)
        }
        return result
    }
}
