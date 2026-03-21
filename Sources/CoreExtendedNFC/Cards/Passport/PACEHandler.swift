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
        let passwordKey = derivePasswordKey(
            password: password,
            keyReference: keyReference,
            mode: smMode
        )

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

            guard chipToken == expectedChipToken else {
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
    /// For MRZ: K_π = KDF(SHA-1(MRZ_information), 3)
    /// For CAN/PIN/PUK: K_π = KDF(password bytes, 3)
    static func derivePasswordKey(
        password: String,
        keyReference: KeyReference,
        mode: SMEncryptionMode
    ) -> Data {
        let passwordData: Data
        if keyReference == .mrz {
            // For MRZ, use the existing Kseed derivation
            passwordData = KeyDerivation.generateKseed(mrzKey: password)
        } else {
            // ICAO 9303 encodes CAN/PIN/PUK as ISO-8859-1 character data.
            guard let isoData = password.data(using: .isoLatin1, allowLossyConversion: false) else {
                preconditionFailure(
                    "PACE password for \(keyReference) contains characters that cannot be represented in ISO-8859-1."
                )
            }
            passwordData = isoData
        }

        return deriveKey(
            keySeed: passwordData,
            counter: 3,
            mode: mode
        )
    }

    /// Derive PACE session keys from the shared secret.
    ///
    /// KSenc = KDF(sharedSecret, 1)
    /// KSmac = KDF(sharedSecret, 2)
    static func derivePACESessionKeys(
        sharedSecret: Data,
        mode: SMEncryptionMode
    ) -> (ksEnc: Data, ksMac: Data) {
        (
            ksEnc: deriveKey(keySeed: sharedSecret, counter: 1, mode: mode),
            ksMac: deriveKey(keySeed: sharedSecret, counter: 2, mode: mode)
        )
    }

    /// Compute PACE authentication token.
    ///
    /// T = MAC(KSmac, publicKey_other)
    static func computeAuthToken(
        ksMac: Data,
        publicKeyOther: Data,
        oid: Data,
        mode: SMEncryptionMode
    ) throws -> Data {
        // Build the authentication input:
        // 7F49 { 06 <OID> || 86 <publicKey> }
        var authInput = Data()
        authInput.append(contentsOf: ASN1Parser.encodeTLV(tag: 0x06, value: oid))
        authInput.append(contentsOf: ASN1Parser.encodeTLV(tag: 0x86, value: publicKeyOther))
        let wrappedInput = ASN1Parser.encodeTLV(tag: 0x7F49, value: authInput)

        // Pad and MAC
        let blockSize = mode.blockSize
        let padded = ISO9797Padding.pad(wrappedInput, blockSize: blockSize)

        switch mode {
        case .tripleDES:
            return try ISO9797MAC.mac(key: ksMac, message: padded)
        case .aes128, .aes192, .aes256:
            let fullMAC = try AESCMAC.mac(key: ksMac, message: padded)
            return Data(fullMAC.prefix(8))
        }
    }

    private static func deriveKey(
        keySeed: Data,
        counter: UInt8,
        mode: SMEncryptionMode
    ) -> Data {
        var input = keySeed
        input.append(contentsOf: [0x00, 0x00, 0x00, counter])

        switch mode {
        case .tripleDES:
            let hash = HashUtils.sha1(input)
            let ka = KeyDerivation.adjustParity(Data(hash[0 ..< 8]))
            let kb = KeyDerivation.adjustParity(Data(hash[8 ..< 16]))
            return ka + kb
        case .aes128:
            return Data(HashUtils.sha1(input).prefix(16))
        case .aes192:
            return Data(HashUtils.sha256(input).prefix(24))
        case .aes256:
            return Data(HashUtils.sha256(input).prefix(32))
        }
    }

    private static func encodeDynamicAuthenticationData(tag: UInt8, value: Data) -> Data {
        ASN1Parser.encodeTLV(tag: 0x7C, value: ASN1Parser.encodeTLV(tag: UInt(tag), value: value))
    }

    // MARK: - Response Parsing

    /// Parse tag 0x80 from a Dynamic Authentication Data (7C) response.
    private static func parseTag80FromDynamicAuth(_ data: Data) throws -> Data {
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
    static func parseTag81FromDynamicAuth(_ data: Data) throws -> Data {
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
    static func parseTag82FromDynamicAuth(_ data: Data) throws -> Data {
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
    static func parseTag84FromDynamicAuth(_ data: Data) throws -> Data {
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
    static func parseTag86FromDynamicAuth(_ data: Data) throws -> Data {
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

private extension SecurityProtocol {
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

#if canImport(OpenSSL)
    final class OpenSSLPACECurve {
        private let group: OpaquePointer
        private let order: OpaquePointer
        private let ctx: OpaquePointer
        private let coordinateLength: Int
        private let scalarLength: Int

        init(parameterID: PACEHandler.DomainParameterID) throws {
            guard let group = EC_GROUP_new_by_curve_name(parameterID.opensslNID) else {
                throw NFCError.cryptoError("PACE: failed to create elliptic-curve group")
            }
            guard let order = BN_new() else {
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to allocate OpenSSL bignum for curve order")
            }
            guard let ctx = BN_CTX_new() else {
                BN_free(order)
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to allocate OpenSSL bignum context")
            }
            guard EC_GROUP_get_order(group, order, ctx) == 1 else {
                BN_free(order)
                BN_CTX_free(ctx)
                EC_GROUP_free(group)
                throw NFCError.cryptoError("PACE: failed to query curve order")
            }

            self.group = group
            self.order = order
            self.ctx = ctx
            coordinateLength = (Int(EC_GROUP_get_degree(group)) + 7) / 8
            scalarLength = (Int(BN_num_bits(order)) + 7) / 8
        }

        deinit {
            BN_free(order)
            BN_CTX_free(ctx)
            EC_GROUP_free(group)
        }

        func generatePrivateScalar() throws -> Data {
            while true {
                var random = Data(count: scalarLength)
                let status = random.withUnsafeMutableBytes { bytes in
                    SecRandomCopyBytes(kSecRandomDefault, scalarLength, bytes.baseAddress!)
                }
                guard status == errSecSuccess else {
                    throw NFCError.cryptoError("PACE: failed to generate random scalar")
                }

                let scalar = try makeScalar(random)
                defer { BN_free(scalar) }
                if BN_num_bits(scalar) > 0, BN_cmp(scalar, order) < 0 {
                    return random
                }
            }
        }

        func publicPoint(privateScalar: Data, generator: Data?) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate public point")
            }
            defer { EC_POINT_free(result) }

            if let generator {
                let mappedGenerator = try makePoint(generator)
                defer { EC_POINT_free(mappedGenerator) }

                guard EC_POINT_mul(group, result, nil, mappedGenerator, scalar, ctx) == 1 else {
                    throw NFCError.cryptoError("PACE: failed to compute public point")
                }
            } else {
                guard EC_POINT_mul(group, result, scalar, nil, nil, ctx) == 1 else {
                    throw NFCError.cryptoError("PACE: failed to compute mapping public point")
                }
            }

            return try exportPoint(result)
        }

        func sharedPoint(privateScalar: Data, peerPublic: Data) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            let peerPoint = try makePoint(peerPublic)
            defer { EC_POINT_free(peerPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate shared point")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nil, peerPoint, scalar, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute shared point")
            }

            return try exportPoint(result)
        }

        func mappedGenerator(nonce: Data, sharedPoint: Data) throws -> Data {
            let nonceScalar = try makeReducedScalar(nonce)
            defer { BN_free(nonceScalar) }

            let hPoint = try makePoint(sharedPoint)
            defer { EC_POINT_free(hPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate mapped generator")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nonceScalar, nil, nil, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute nonce contribution for mapped generator")
            }
            guard EC_POINT_add(group, result, result, hPoint, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute mapped generator")
            }

            return try exportPoint(result)
        }

        func sharedSecretXCoordinate(privateScalar: Data, peerPublic: Data) throws -> Data {
            let scalar = try makeScalar(privateScalar)
            defer { BN_free(scalar) }

            let peerPoint = try makePoint(peerPublic)
            defer { EC_POINT_free(peerPoint) }

            guard let result = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate shared-secret point")
            }
            defer { EC_POINT_free(result) }

            guard EC_POINT_mul(group, result, nil, peerPoint, scalar, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to compute shared secret")
            }

            return try exportXCoordinate(result)
        }

        private func makeScalar(_ data: Data) throws -> OpaquePointer {
            let scalar = data.withUnsafeBytes { bytes in
                BN_bin2bn(
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(data.count),
                    nil
                )
            }
            guard let scalar else {
                throw NFCError.cryptoError("PACE: failed to decode scalar value")
            }
            return scalar
        }

        private func makeReducedScalar(_ data: Data) throws -> OpaquePointer {
            let input = try makeScalar(data)
            guard let reduced = BN_new() else {
                BN_free(input)
                throw NFCError.cryptoError("PACE: failed to allocate reduced scalar")
            }
            guard BN_div(nil, reduced, input, order, ctx) == 1 else {
                BN_free(reduced)
                BN_free(input)
                throw NFCError.cryptoError("PACE: failed to reduce nonce modulo curve order")
            }
            BN_free(input)
            return reduced
        }

        private func makePoint(_ data: Data) throws -> OpaquePointer {
            guard let point = EC_POINT_new(group) else {
                throw NFCError.cryptoError("PACE: failed to allocate EC point")
            }

            let loaded = data.withUnsafeBytes { bytes in
                EC_POINT_oct2point(
                    group,
                    point,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    data.count,
                    ctx
                )
            }
            guard loaded == 1,
                  EC_POINT_is_at_infinity(group, point) == 0,
                  EC_POINT_is_on_curve(group, point, ctx) == 1
            else {
                EC_POINT_free(point)
                throw NFCError.cryptoError("PACE: invalid elliptic-curve point")
            }
            return point
        }

        private func exportPoint(_ point: OpaquePointer) throws -> Data {
            let form = POINT_CONVERSION_UNCOMPRESSED
            let length = EC_POINT_point2oct(group, point, form, nil, 0, ctx)
            guard length > 0 else {
                throw NFCError.cryptoError("PACE: failed to export EC point")
            }

            var output = Data(count: length)
            let written = output.withUnsafeMutableBytes { bytes in
                EC_POINT_point2oct(
                    group,
                    point,
                    form,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    length,
                    ctx
                )
            }
            guard written == length else {
                throw NFCError.cryptoError("PACE: failed to encode EC point")
            }
            return output
        }

        private func exportXCoordinate(_ point: OpaquePointer) throws -> Data {
            guard let x = BN_new(), let y = BN_new() else {
                throw NFCError.cryptoError("PACE: failed to allocate affine coordinates")
            }
            defer {
                BN_free(x)
                BN_free(y)
            }

            guard EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 1 else {
                throw NFCError.cryptoError("PACE: failed to read shared-secret coordinates")
            }

            var output = Data(count: coordinateLength)
            let written = output.withUnsafeMutableBytes { bytes in
                BN_bn2binpad(
                    x,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(coordinateLength)
                )
            }
            guard written == coordinateLength else {
                throw NFCError.cryptoError("PACE: failed to encode shared-secret x-coordinate")
            }
            return output
        }
    }

    private extension PACEHandler.DomainParameterID {
        var opensslNID: Int32 {
            switch self {
            case .secp256r1:
                Int32(NID_X9_62_prime256v1)
            case .secp384r1:
                Int32(NID_secp384r1)
            case .secp521r1:
                Int32(NID_secp521r1)
            default:
                Int32(NID_undef)
            }
        }
    }
#endif
