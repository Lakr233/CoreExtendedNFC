import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

/// PACE (Password Authenticated Connection Establishment) handler
/// per ICAO Doc 9303 Part 11 and BSI TR-03110.
///
/// PACE replaces BAC with a stronger authentication protocol using
/// elliptic curve Diffie-Hellman key agreement. It supports MRZ, CAN,
/// PIN, and PUK as password sources.
///
/// Generic Mapping (GM) protocol flow:
/// 1. MSE:Set AT — select PACE protocol and key reference
/// 2. General Authenticate step 1 — get encrypted nonce from chip
/// 3. Decrypt nonce using password-derived key
/// 4. General Authenticate step 2 — exchange ephemeral DH keys
/// 5. General Authenticate step 3 — exchange mapped DH keys
/// 6. General Authenticate step 4 — exchange authentication tokens
/// 7. Derive session keys → SecureMessagingTransport
///
/// References:
/// - ICAO Doc 9303 Part 11, Section 9.1 (PACE protocol overview)
/// - BSI TR-03110 Part 2, Section 3.4 (PACE Generic Mapping protocol steps)
/// - BSI TR-03110 Part 3, Table A.2 (Standardized Domain Parameters: parameter IDs 8–18)
/// - BSI TR-03110 Part 3, Appendix A.1.1.1 (PACE OID tree: 0.4.0.127.0.7.2.2.4.*)
/// - BSI TR-03110 Part 2, Section 3.4.3 (Key Derivation Function for PACE)
public enum PACEHandler {
    /// PACE key reference (password type).
    public enum KeyReference: UInt8, Sendable {
        /// MRZ-derived password.
        case mrz = 0x01
        /// Card Access Number (CAN) — 6-digit number on the card.
        case can = 0x02
        /// Personal Identification Number (PIN).
        case pin = 0x03
        /// Personal Unblocking Key (PUK).
        case puk = 0x04
    }

    /// Standard domain parameter IDs for ECDH.
    /// Reference: BSI TR-03110 Part 3, Table A.2
    public enum DomainParameterID: Int, Sendable {
        case secp192r1 = 8
        case brainpoolP192r1 = 9
        case secp224r1 = 10
        case brainpoolP224r1 = 11
        case secp256r1 = 12 // P-256 (most common)
        case brainpoolP256r1 = 13
        case brainpoolP320r1 = 14
        case secp384r1 = 15 // P-384
        case brainpoolP384r1 = 16
        case brainpoolP512r1 = 17
        case secp521r1 = 18 // P-521

        /// Whether this is a standard NIST curve supported by CryptoKit.
        public var isNISTCurve: Bool {
            switch self {
            case .secp256r1, .secp384r1, .secp521r1: true
            default: false
            }
        }
    }

    /// Attempt PACE authentication using MRZ-derived password.
    ///
    /// - Parameters:
    ///   - paceInfo: Parsed PACEInfo from DG14.
    ///   - mrzKey: The MRZ key string.
    ///   - transport: The underlying (unauthenticated) NFC tag transport.
    /// - Returns: A `SecureMessagingTransport` with PACE session keys.
    public static func performPACE(
        paceInfo: PACEInfo,
        mrzKey: String,
        transport: any NFCTagTransport
    ) async throws -> SecureMessagingTransport {
        try await performPACE(
            paceInfo: paceInfo,
            password: mrzKey,
            keyReference: .mrz,
            transport: transport
        )
    }

    /// Attempt PACE authentication using CAN (Card Access Number).
    ///
    /// - Parameters:
    ///   - paceInfo: Parsed PACEInfo from DG14.
    ///   - can: The 6-digit Card Access Number.
    ///   - transport: The underlying (unauthenticated) NFC tag transport.
    /// - Returns: A `SecureMessagingTransport` with PACE session keys.
    public static func performPACE(
        paceInfo: PACEInfo,
        can: String,
        transport: any NFCTagTransport
    ) async throws -> SecureMessagingTransport {
        try await performPACE(
            paceInfo: paceInfo,
            password: can,
            keyReference: .can,
            transport: transport
        )
    }

    /// Core PACE implementation.
    ///
    /// - Parameters:
    ///   - paceInfo: Parsed PACEInfo from DG14.
    ///   - password: The password (MRZ key or CAN).
    ///   - keyReference: Which key type to use.
    ///   - transport: The underlying NFC tag transport.
    /// - Returns: A `SecureMessagingTransport` with PACE session keys.
    public static func performPACE(
        paceInfo: PACEInfo,
        password: String,
        keyReference: KeyReference,
        transport: any NFCTagTransport
    ) async throws -> SecureMessagingTransport {
        guard let paceProtocol = paceInfo.securityProtocol else {
            throw NFCError.secureMessagingError("Unknown PACE protocol OID: \(paceInfo.protocolOID)")
        }

        // Determine SM encryption mode from protocol
        let smMode: SMEncryptionMode = if let keyLen = paceProtocol.aesKeyLength {
            switch keyLen {
            case 16: .aes128
            case 24: .aes192
            case 32: .aes256
            default: .aes128
            }
        } else {
            .tripleDES
        }

        // Derive K_π before touching the chip so invalid passwords fail without RF traffic.
        let passwordKey = try derivePasswordKey(
            password: password,
            keyReference: keyReference,
            mode: smMode
        )

        // Step 1: MSE:Set AT — select PACE protocol
        let oidData = ChipAuthenticationHandler.encodeOID(paceInfo.protocolOID)
        let mseAPDU = CommandAPDU.mseSetAT(oid: oidData, keyRef: keyReference.rawValue)
        let mseResponse = try await transport.sendAPDU(mseAPDU)

        guard mseResponse.isSuccess else {
            throw NFCError.secureMessagingError(
                "MSE:Set AT for PACE failed: SW=\(String(format: "%04X", mseResponse.statusWord))"
            )
        }

        // Step 2: General Authenticate — get encrypted nonce
        let step1Data = ASN1Parser.encodeTLV(tag: 0x7C, value: Data())
        let step1APDU = CommandAPDU.generalAuthenticate(data: step1Data)
        let step1Response = try await transport.sendAPDU(step1APDU)

        guard step1Response.isSuccess else {
            throw NFCError.secureMessagingError(
                "PACE step 1 (get nonce) failed: SW=\(String(format: "%04X", step1Response.statusWord))"
            )
        }

        // Parse encrypted nonce from response: 7C { 80 <nonce> }
        let encryptedNonce = try parseTag80FromDynamicAuth(step1Response.data)

        // Step 3: Decrypt nonce using password-derived key
        let decryptedNonce: Data
        switch smMode {
        case .tripleDES:
            decryptedNonce = try CryptoUtils.tripleDESDecrypt(key: passwordKey, message: encryptedNonce)
        case .aes128, .aes192, .aes256:
            let iv = Data(count: 16) // Zero IV for nonce decryption
            decryptedNonce = try CryptoUtils.aesDecrypt(key: passwordKey, message: encryptedNonce, iv: iv)
        }

        guard paceProtocol.isECDH else {
            throw NFCError.unsupportedOperation(
                "PACE currently supports ECDH key agreement only; protocol \(paceInfo.protocolOID) is not supported."
            )
        }

        guard paceProtocol.isGenericMapping else {
            throw NFCError.unsupportedOperation(
                "PACE currently supports Generic Mapping only; protocol \(paceInfo.protocolOID) is not supported."
            )
        }

        guard let parameterID = paceInfo.parameterID,
              let domainParameter = DomainParameterID(rawValue: parameterID),
              domainParameter.isNISTCurve
        else {
            throw NFCError.unsupportedOperation(
                "PACE currently supports standardized NIST curves only (parameter IDs 12, 15, 18)."
            )
        }

        #if canImport(OpenSSL)
            let curve = try OpenSSLPACECurve(parameterID: domainParameter)

            // Step 4: exchange mapping public keys over the standardized generator G.
            let mappingPrivateKey = try curve.generatePrivateScalar()
            let terminalMappingPublicKey = try curve.publicPoint(
                privateScalar: mappingPrivateKey,
                generator: nil
            )

            let step2Data = encodeDynamicAuthenticationData(tag: 0x81, value: terminalMappingPublicKey)
            let step2APDU = CommandAPDU.generalAuthenticate(data: step2Data)
            let step2Response = try await transport.sendAPDU(step2APDU)

            guard step2Response.isSuccess else {
                throw NFCError.secureMessagingError(
                    "PACE step 2 (map nonce) failed: SW=\(String(format: "%04X", step2Response.statusWord))"
                )
            }

            let chipMappingPublicKey = try parseTag82FromDynamicAuth(step2Response.data)
            // ICAO 9303-11 §4.4.3.3: the terminal must check that the chip's public key
            // differs from its own; a reflected key would let a party that does not know
            // the password complete the protocol.
            guard try !curve.isSamePoint(chipMappingPublicKey, terminalMappingPublicKey) else {
                throw NFCError.secureMessagingError("PACE: chip mapping public key reflects the terminal's key")
            }
            let mappingSharedPoint = try curve.sharedPoint(
                privateScalar: mappingPrivateKey,
                peerPublic: chipMappingPublicKey
            )
            let mappedGenerator = try curve.mappedGenerator(
                nonce: decryptedNonce,
                sharedPoint: mappingSharedPoint
            )

            // Step 5: exchange ephemeral public keys over the mapped generator G^.
            let ephemeralPrivateKey = try curve.generatePrivateScalar()
            let terminalEphemeralPublicKey = try curve.publicPoint(
                privateScalar: ephemeralPrivateKey,
                generator: mappedGenerator
            )

            let step3Data = encodeDynamicAuthenticationData(tag: 0x83, value: terminalEphemeralPublicKey)
            let step3APDU = CommandAPDU.generalAuthenticate(data: step3Data)
            let step3Response = try await transport.sendAPDU(step3APDU)

            guard step3Response.isSuccess else {
                throw NFCError.secureMessagingError(
                    "PACE step 3 (key agreement) failed: SW=\(String(format: "%04X", step3Response.statusWord))"
                )
            }

            let chipEphemeralPublicKey = try parseTag84FromDynamicAuth(step3Response.data)
            guard try !curve.isSamePoint(chipEphemeralPublicKey, terminalEphemeralPublicKey) else {
                throw NFCError.secureMessagingError("PACE: chip ephemeral public key reflects the terminal's key")
            }
            let sharedSecret = try curve.sharedSecretXCoordinate(
                privateScalar: ephemeralPrivateKey,
                peerPublic: chipEphemeralPublicKey
            )
            let sessionKeys = derivePACESessionKeys(sharedSecret: sharedSecret, mode: smMode)

            // Step 6: mutual authentication via token exchange.
            let terminalToken = try computeAuthToken(
                ksMac: sessionKeys.ksMac,
                publicKeyOther: chipEphemeralPublicKey,
                oid: oidData,
                mode: smMode
            )
            let step4Data = encodeDynamicAuthenticationData(tag: 0x85, value: terminalToken)
            let step4APDU = CommandAPDU.generalAuthenticate(data: step4Data, isLast: true)
            let step4Response = try await transport.sendAPDU(step4APDU)

            guard step4Response.isSuccess else {
                throw NFCError.secureMessagingError(
                    "PACE step 4 (mutual authentication) failed: SW=\(String(format: "%04X", step4Response.statusWord))"
                )
            }

            let chipToken = try parseTag86FromDynamicAuth(step4Response.data)
            let expectedChipToken = try computeAuthToken(
                ksMac: sessionKeys.ksMac,
                publicKeyOther: terminalEphemeralPublicKey,
                oid: oidData,
                mode: smMode
            )

            guard CryptoUtils.constantTimeEquals(chipToken, expectedChipToken) else {
                throw NFCError.secureMessagingError("PACE authentication token verification failed")
            }

            // PACE starts a fresh secure-messaging session with a zero SSC.
            return SecureMessagingTransport(
                transport: transport,
                ksEnc: sessionKeys.ksEnc,
                ksMac: sessionKeys.ksMac,
                ssc: Data(count: 8),
                mode: smMode
            )
        #else
            throw NFCError.unsupportedOperation(
                "PACE ECDH key agreement requires OpenSSL-backed elliptic-curve point operations."
            )
        #endif
    }

    // MARK: - Key Derivation

    /// Derive the password encryption key for PACE nonce decryption.
    ///
    /// - MRZ: `K_π = KDF_π(SHA-1(MRZ_information))` using the **full** 20-byte hash
    ///   (ICAO 9303-11 §9.7.3; only BAC truncates the hash to 16 bytes).
    /// - CAN/PIN/PUK: `K_π = KDF_π(password)` with the password encoded as ISO-8859-1.
    ///
    /// - Throws: `NFCError.secureMessagingError` when a CAN/PIN/PUK cannot be encoded as ISO-8859-1.
    public static func derivePasswordKey(
        password: String,
        keyReference: KeyReference,
        mode: SMEncryptionMode
    ) throws -> Data {
        let passwordData: Data
        if keyReference == .mrz {
            passwordData = HashUtils.sha1(Data(password.utf8))
        } else {
            // ICAO 9303 encodes CAN/PIN/PUK as ISO-8859-1 character data.
            guard let isoData = password.data(using: .isoLatin1, allowLossyConversion: false) else {
                throw NFCError.secureMessagingError(
                    "PACE password for \(keyReference) contains characters that cannot be represented in ISO-8859-1."
                )
            }
            passwordData = isoData
        }

        return KeyDerivation.deriveKey(
            keySeed: passwordData,
            counter: KeyDerivation.Mode.pace.rawValue,
            mode: mode
        )
    }

    /// Derive PACE session keys from the shared secret.
    ///
    /// KSenc = KDF(sharedSecret, 1)
    /// KSmac = KDF(sharedSecret, 2)
    public static func derivePACESessionKeys(
        sharedSecret: Data,
        mode: SMEncryptionMode
    ) -> (ksEnc: Data, ksMac: Data) {
        (
            ksEnc: KeyDerivation.deriveKey(keySeed: sharedSecret, counter: 1, mode: mode),
            ksMac: KeyDerivation.deriveKey(keySeed: sharedSecret, counter: 2, mode: mode)
        )
    }

    /// Compute PACE authentication token.
    ///
    /// `T = MAC(KSmac, 7F49 { 06 <OID> || 86 <publicKey_other> })`
    /// (ICAO 9303-11 §4.4.3.4, BSI TR-03110-3 A.2.4.2).
    ///
    /// - AES: AES-CMAC (RFC 4493) over the unpadded input — CMAC pads internally —
    ///   truncated to 8 bytes.
    /// - 3DES: ISO/IEC 9797-1 MAC algorithm 3 over the Method 2 padded input.
    public static func computeAuthToken(
        ksMac: Data,
        publicKeyOther: Data,
        oid: Data,
        mode: SMEncryptionMode
    ) throws -> Data {
        var authInput = Data()
        authInput.append(contentsOf: ASN1Parser.encodeTLV(tag: 0x06, value: oid))
        authInput.append(contentsOf: ASN1Parser.encodeTLV(tag: 0x86, value: publicKeyOther))
        let wrappedInput = ASN1Parser.encodeTLV(tag: 0x7F49, value: authInput)

        switch mode {
        case .tripleDES:
            let padded = ISO9797Padding.pad(wrappedInput, blockSize: mode.blockSize)
            return try ISO9797MAC.mac(key: ksMac, message: padded)
        case .aes128, .aes192, .aes256:
            let fullMAC = try AESCMAC.mac(key: ksMac, message: wrappedInput)
            return Data(fullMAC.prefix(8))
        }
    }

    public static func encodeDynamicAuthenticationData(tag: UInt8, value: Data) -> Data {
        ASN1Parser.encodeTLV(tag: 0x7C, value: ASN1Parser.encodeTLV(tag: UInt(tag), value: value))
    }

    // MARK: - Response Parsing

    /// Parse tag 0x80 from a Dynamic Authentication Data (7C) response.
    public static func parseTag80FromDynamicAuth(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
            throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in response")
        }
        let children = try ASN1Parser.parseTLV(wrapper.value)
        guard let nonceNode = children.first(where: { $0.tag == 0x80 }) else {
            throw NFCError.secureMessagingError("PACE: Missing tag 0x80 in response")
        }
        return nonceNode.value
    }

    /// Parse tag 0x81 (map nonce public key) from Dynamic Authentication Data.
    public static func parseTag81FromDynamicAuth(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
            throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in response")
        }
        let children = try ASN1Parser.parseTLV(wrapper.value)
        guard let keyNode = children.first(where: { $0.tag == 0x81 }) else {
            throw NFCError.secureMessagingError("PACE: Missing tag 0x81 in response")
        }
        return keyNode.value
    }

    /// Parse tag 0x82 (chip mapping public key) from Dynamic Authentication Data.
    public static func parseTag82FromDynamicAuth(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
            throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in response")
        }
        let children = try ASN1Parser.parseTLV(wrapper.value)
        guard let keyNode = children.first(where: { $0.tag == 0x82 }) else {
            throw NFCError.secureMessagingError("PACE: Missing tag 0x82 in response")
        }
        return keyNode.value
    }

    /// Parse tag 0x84 (chip ephemeral public key) from Dynamic Authentication Data.
    public static func parseTag84FromDynamicAuth(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
            throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in response")
        }
        let children = try ASN1Parser.parseTLV(wrapper.value)
        guard let keyNode = children.first(where: { $0.tag == 0x84 }) else {
            throw NFCError.secureMessagingError("PACE: Missing tag 0x84 in response")
        }
        return keyNode.value
    }

    /// Parse tag 0x86 (authentication token) from Dynamic Authentication Data.
    public static func parseTag86FromDynamicAuth(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)
        guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
            throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in response")
        }
        let children = try ASN1Parser.parseTLV(wrapper.value)
        guard let tokenNode = children.first(where: { $0.tag == 0x86 }) else {
            throw NFCError.secureMessagingError("PACE: Missing tag 0x86 in response")
        }
        return tokenNode.value
    }
}

public extension SecurityProtocol {
    var isGenericMapping: Bool {
        switch self {
        case .paceDHGM3DESCBCCBC, .paceDHGMAESCBCCMAC128,
             .paceDHGMAESCBCCMAC192, .paceDHGMAESCBCCMAC256,
             .paceECDHGM3DESCBCCBC, .paceECDHGMAESCBCCMAC128,
             .paceECDHGMAESCBCCMAC192, .paceECDHGMAESCBCCMAC256:
            true
        default:
            false
        }
    }
}
