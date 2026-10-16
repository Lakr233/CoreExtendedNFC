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

        /// Whether this is one of the NIST curves PACE supports (P-256, P-384, P-521).
        public var isNISTCurve: Bool {
            switch self {
            case .secp256r1, .secp384r1, .secp521r1: true
            default: false
            }
        }

        /// Whether this is one of the Brainpool curves PACE supports (RFC 5639,
        /// brainpoolP224r1 to brainpoolP512r1).
        public var isBrainpoolCurve: Bool {
            switch self {
            case .brainpoolP224r1, .brainpoolP256r1, .brainpoolP320r1,
                 .brainpoolP384r1, .brainpoolP512r1:
                true
            default:
                false
            }
        }

        /// Whether ``PACEHandler`` can run ECDH Generic Mapping on this curve.
        ///
        /// Standardized parameter IDs 11–18 are supported. The 192-bit curves (IDs 8
        /// and 9) and secp224r1 (ID 10) are not; a chip that only offers them falls
        /// back to BAC.
        public var isSupportedForPACE: Bool {
            isNISTCurve || isBrainpoolCurve
        }
    }

    // MARK: - Parameter Selection

    /// Why ``performPACE(paceInfo:password:keyReference:transport:mappingPrivateKey:ephemeralPrivateKey:)``
    /// cannot run with `paceInfo`, or `nil` when it can.
    ///
    /// PACE runs only for a known PACE protocol OID with ECDH key agreement, Generic
    /// Mapping and a standardized domain parameter ID whose curve
    /// ``DomainParameterID/isSupportedForPACE``.
    public static func unsupportedReason(for paceInfo: PACEInfo) -> String? {
        guard let paceProtocol = paceInfo.securityProtocol, paceProtocol.isPACE else {
            return "Unknown PACE protocol OID: \(paceInfo.protocolOID)."
        }
        guard paceProtocol.isECDH else {
            return "PACE currently supports ECDH key agreement only; protocol \(paceInfo.protocolOID) is not supported."
        }
        guard paceProtocol.isGenericMapping else {
            return "PACE currently supports Generic Mapping only; protocol \(paceInfo.protocolOID) is not supported."
        }
        guard let parameterID = paceInfo.parameterID,
              let domainParameter = DomainParameterID(rawValue: parameterID),
              domainParameter.isSupportedForPACE
        else {
            return "PACE currently supports standardized domain parameter IDs 11–18 (brainpoolP224r1 to "
                + "brainpoolP512r1, NIST P-256, P-384 and P-521); parameter ID "
                + "\(paceInfo.parameterID.map(String.init) ?? "none") is not supported."
        }
        return nil
    }

    /// Whether ``performPACE(paceInfo:password:keyReference:transport:mappingPrivateKey:ephemeralPrivateKey:)``
    /// supports `paceInfo` (see ``unsupportedReason(for:)``).
    public static func isSupported(_ paceInfo: PACEInfo) -> Bool {
        unsupportedReason(for: paceInfo) == nil
    }

    /// The PACE parameters to use from EF.CardAccess: the first PACEInfo this
    /// handler supports, or `nil` when none is supported.
    ///
    /// ICAO 9303-11 §4.4.4.1 lets the inspection system select any of the parameter
    /// sets the chip advertises, so an unsupported first entry (for example Integrated
    /// Mapping) does not rule PACE out.
    public static func selectPACEInfo(from securityInfos: SecurityInfos) -> PACEInfo? {
        securityInfos.paceInfos.first(where: isSupported)
    }

    /// Attempt PACE authentication using MRZ-derived password.
    ///
    /// - Parameters:
    ///   - paceInfo: PACEInfo parsed from EF.CardAccess.
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
    ///   - paceInfo: PACEInfo parsed from EF.CardAccess.
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
    /// Unsupported parameters (see ``unsupportedReason(for:)``) and invalid passwords
    /// are rejected before any APDU is sent, so the caller can fall back to BAC
    /// without PACE traffic on the chip.
    ///
    /// - Parameters:
    ///   - paceInfo: PACEInfo parsed from EF.CardAccess (ICAO 9303-11 §4.4.4.1,
    ///     §9.2.11); use ``selectPACEInfo(from:)`` to pick a supported entry.
    ///   - password: The password (MRZ key or CAN).
    ///   - keyReference: Which key type to use.
    ///   - transport: The underlying NFC tag transport.
    ///   - mappingPrivateKey: Terminal private key for the Generic Mapping step, as a
    ///     big-endian scalar in `[1, n-1]`. `nil` (the default) generates a random key.
    ///     Supply it only to reproduce published test vectors.
    ///   - ephemeralPrivateKey: Terminal ephemeral private key for key agreement, as a
    ///     big-endian scalar in `[1, n-1]`. `nil` (the default) generates a random key.
    /// - Returns: A `SecureMessagingTransport` with PACE session keys.
    /// - Throws: `NFCError.unsupportedOperation` for unsupported parameters,
    ///   `NFCError.invalidParameter` for an out-of-range supplied private key, and
    ///   `NFCError.secureMessagingError` when the chip rejects a step or a token fails.
    public static func performPACE(
        paceInfo: PACEInfo,
        password: String,
        keyReference: KeyReference,
        transport: any NFCTagTransport,
        mappingPrivateKey: Data? = nil,
        ephemeralPrivateKey: Data? = nil
    ) async throws -> SecureMessagingTransport {
        // Check the parameters before touching the chip so unsupported cards fall back
        // to BAC without a half-run PACE.
        if let reason = unsupportedReason(for: paceInfo) {
            throw NFCError.unsupportedOperation(reason)
        }
        guard let paceProtocol = paceInfo.securityProtocol,
              let parameterID = paceInfo.parameterID,
              let domainParameter = DomainParameterID(rawValue: parameterID)
        else {
            throw NFCError.unsupportedOperation("PACE parameters are incomplete: \(paceInfo.protocolOID)")
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
        let oidData = ChipAuthenticationHandler.encodeOID(paceInfo.protocolOID)

        #if canImport(OpenSSL)
            let curve = try OpenSSLPACECurve(parameterID: domainParameter)
            for suppliedKey in [mappingPrivateKey, ephemeralPrivateKey].compactMap(\.self) {
                guard try curve.isValidPrivateScalar(suppliedKey) else {
                    throw NFCError.invalidParameter("PACE private key must be a scalar in [1, n-1] of the curve order n")
                }
            }

            // Step 1: MSE:Set AT — select the PACE protocol, the password and the domain
            // parameters. Tag 84 carries the standardized domain parameter ID; ICAO
            // 9303-11 §4.4.4.1 requires it whenever the chip offers more than one set.
            let mseAPDU = CommandAPDU.mseSetAT(
                oid: oidData,
                keyRef: keyReference.rawValue,
                privateKeyRef: UInt8(domainParameter.rawValue)
            )
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
            try validateEncryptedNonce(encryptedNonce, mode: smMode)

            // Step 3: Decrypt nonce using password-derived key
            let decryptedNonce: Data
            switch smMode {
            case .tripleDES:
                decryptedNonce = try CryptoUtils.tripleDESDecrypt(key: passwordKey, message: encryptedNonce)
            case .aes128, .aes192, .aes256:
                let iv = Data(count: 16) // Zero IV for nonce decryption
                decryptedNonce = try CryptoUtils.aesDecrypt(key: passwordKey, message: encryptedNonce, iv: iv)
            }
            // Generic Mapping computes G^ = s·G + H. With s ≡ 0 (mod n) the mapped
            // generator is H, which the chip derives without knowing the password, so
            // the password would not be bound into the session keys.
            guard try !curve.isZeroModuloOrder(decryptedNonce) else {
                throw NFCError.secureMessagingError(
                    "PACE: chip nonce s is 0 modulo the group order, so the password would not be bound"
                )
            }

            // Step 4: exchange mapping public keys over the standardized generator G.
            let mappingPrivateKey = try mappingPrivateKey ?? curve.generatePrivateScalar()
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
            let ephemeralPrivateKey = try ephemeralPrivateKey ?? curve.generatePrivateScalar()
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
            _ = (passwordKey, oidData, domainParameter, mappingPrivateKey, ephemeralPrivateKey)
            throw NFCError.unsupportedOperation(
                "PACE ECDH key agreement requires OpenSSL-backed elliptic-curve point operations."
            )
        #endif
    }

    // MARK: - Nonce Checks

    /// Check the shape of the encrypted nonce `z` the chip sends in PACE step 1.
    ///
    /// ICAO 9303-11 §4.4.3.3: "The eMRTD chip SHALL randomly and uniformly select the
    /// nonce s as a binary bit string of length l, where l is a multiple of the block
    /// size in bits of the respective block cipher E() chosen by the eMRTD chip", and
    /// "The nonce s SHALL be encrypted in CBC mode […] using the key Kπ = KDFπ(π) […]
    /// and IV set to the all-0 string." `z` therefore has the length of `s`: a non-zero
    /// whole number of cipher blocks (16 bytes for AES, 8 for 3DES). An empty `z`
    /// decrypts to an empty `s`, which maps to G^ = H and does not bind the password.
    ///
    /// No minimum beyond one block is enforced: the specification sets none, and the
    /// Appendix G.1 worked example uses a 16-byte nonce on a 256-bit curve.
    ///
    /// - Throws: `NFCError.secureMessagingError` for an empty or misaligned nonce.
    public static func validateEncryptedNonce(_ encryptedNonce: Data, mode: SMEncryptionMode) throws {
        let blockSize = mode.blockSize
        guard !encryptedNonce.isEmpty, encryptedNonce.count % blockSize == 0 else {
            throw NFCError.secureMessagingError(
                "PACE: encrypted nonce of \(encryptedNonce.count) bytes is not a non-empty "
                    + "multiple of the \(blockSize)-byte cipher block (ICAO 9303-11 §4.4.3.3)"
            )
        }
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
