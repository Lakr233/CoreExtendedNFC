// Active Authentication test suite.
//
// ## References
// - ICAO Doc 9303 Part 11, Section 9.2: Active Authentication protocol
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - ICAO Doc 9303 Part 11, Section 9.2: INTERNAL AUTHENTICATE (INS=0x88)
// - ICAO Doc 9303 Part 11: RSA AA uses ISO 9796-2 message recovery
// - ICAO Doc 9303 Part 11: ECDSA AA uses plain (r||s) signature format
// - BSI TR-03110 Part 3: ecdsa-plain-signatures OID 0.4.0.127.0.7.1.1.4.1.*
// - RFC 5480: EC SubjectPublicKeyInfo structure
//   https://www.rfc-editor.org/rfc/rfc5480
// - DG15: SubjectPublicKeyInfo (SPKI) per RFC 5280 Section 4.1.2.7
//   - RSA: OID 1.2.840.113549.1.1.1 (rsaEncryption)
//   - EC: OID 1.2.840.10045.2.1 (id-ecPublicKey)
//   - BrainpoolP256r1: OID 1.3.36.3.3.2.8.1.1.7
@testable import CoreExtendedNFC
import CryptoKit
import Foundation
#if canImport(OpenSSL)
    import OpenSSL
#endif
import Testing

struct ActiveAuthenticationTests {
    // MARK: - AA Status Semantics

    @Test
    func `ActiveAuthenticationStatus has correct status values`() {
        #expect(ActiveAuthenticationStatus.notImplemented.rawValue == "notImplemented")
        #expect(ActiveAuthenticationStatus.verified.rawValue == "verified")
        #expect(ActiveAuthenticationStatus.failed.rawValue == "failed")
        #expect(ActiveAuthenticationStatus.commandFailed.rawValue == "commandFailed")
        #expect(ActiveAuthenticationStatus.unsupportedKeyType.rawValue == "unsupportedKeyType")
    }

    @Test
    func `ActiveAuthenticationResult with notImplemented status`() {
        let result = ActiveAuthenticationResult(
            success: false,
            details: "RSA AA requires message recovery",
            status: .notImplemented
        )
        #expect(!result.success)
        #expect(result.status == .notImplemented)
    }

    @Test
    func `ActiveAuthenticationResult default status is .verified`() {
        let result = ActiveAuthenticationResult(success: true, details: "OK")
        #expect(result.status == .verified)
    }

    // MARK: - ECDSA Plain Signature → DER Conversion Helper

    @Test
    func `Plain ECDSA signature (r||s) structure for P-256`() {
        // A plain ECDSA signature for P-256 is 64 bytes: r (32) || s (32)
        let r = Data(repeating: 0xAA, count: 32)
        let s = Data(repeating: 0xBB, count: 32)
        let plainSig = r + s

        #expect(plainSig.count == 64)
        #expect(plainSig.count % 2 == 0, "Plain signature must be even length (r||s)")

        let componentSize = plainSig.count / 2
        let rComponent = Data(plainSig[0 ..< componentSize])
        let sComponent = Data(plainSig[componentSize ..< plainSig.count])

        #expect(rComponent == r)
        #expect(sComponent == s)
    }

    @Test
    func `Plain ECDSA signature for P-384 is 96 bytes`() {
        let plainSig = Data(repeating: 0xCC, count: 96)
        let componentSize = plainSig.count / 2
        #expect(componentSize == 48, "P-384 r and s components should be 48 bytes each")
    }

    // MARK: - DG15 RSA Key Export for SecKeyCreateWithData

    @Test
    func `RSA public key modulus and exponent from DG15 can form valid DER`() throws {
        // Build a DG15 with known RSA key
        let rsaOID = ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.1.1")
        let algIdContent = ASN1Parser.encodeTLV(tag: 0x06, value: rsaOID) +
            ASN1Parser.encodeTLV(tag: 0x05, value: Data())
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value: algIdContent)

        // 1024-bit RSA key
        var modulus = Data(repeating: 0xAB, count: 128)
        modulus[0] = 0x80 // Set high bit to test leading zero handling
        let modulusWithSign = Data([0x00]) + modulus
        let exponent = Data([0x01, 0x00, 0x01])

        let rsaKeyContent = ASN1Parser.encodeTLV(tag: 0x02, value: modulusWithSign) +
            ASN1Parser.encodeTLV(tag: 0x02, value: exponent)
        let rsaKey = ASN1Parser.encodeTLV(tag: 0x30, value: rsaKeyContent)

        var bitStringValue = Data([0x00])
        bitStringValue.append(rsaKey)
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: bitStringValue)

        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algId + bitString)
        let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: spki)

        let result = try DG15Parser.parse(dg15Data)

        if case let .rsa(mod, exp) = result {
            // Leading zero should be stripped
            #expect(mod.count == 128, "Leading zero byte should be stripped from modulus")
            #expect(exp == Data([0x01, 0x00, 0x01]))

            // Build the RSAPublicKey DER that SecKeyCreateWithData expects
            var encodedMod = mod
            if encodedMod[0] & 0x80 != 0 {
                encodedMod.insert(0x00, at: 0)
            }
            let modTLV = ASN1Parser.encodeTLV(tag: 0x02, value: encodedMod)
            let expTLV = ASN1Parser.encodeTLV(tag: 0x02, value: exp)
            let rsaDER = ASN1Parser.encodeTLV(tag: 0x30, value: modTLV + expTLV)

            #expect(rsaDER[0] == 0x30, "RSA key DER should start with SEQUENCE tag")
            #expect(rsaDER.count > 130, "RSA key DER should be at least modulus + overhead")
        } else {
            Issue.record("Expected RSA key")
        }
    }

    // MARK: - DG15 ECDSA Key Export

    @Test
    func `ECDSA public key from DG15 with brainpool curve returns unknown curveOID format`() throws {
        let ecOID = ChipAuthenticationHandler.encodeOID("1.2.840.10045.2.1")
        // BrainpoolP256r1 OID: 1.3.36.3.3.2.8.1.1.7
        let curveOID = ChipAuthenticationHandler.encodeOID("1.3.36.3.3.2.8.1.1.7")

        let algIdContent = ASN1Parser.encodeTLV(tag: 0x06, value: ecOID) +
            ASN1Parser.encodeTLV(tag: 0x06, value: curveOID)
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value: algIdContent)

        var ecPoint = Data([0x04])
        ecPoint.append(Data(repeating: 0xAA, count: 32))
        ecPoint.append(Data(repeating: 0xBB, count: 32))

        var bitStringValue = Data([0x00])
        bitStringValue.append(ecPoint)
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: bitStringValue)

        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algId + bitString)
        let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: spki)

        let result = try DG15Parser.parse(dg15Data)

        if case let .ecdsa(curve, point) = result {
            #expect(curve == "1.3.36.3.3.2.8.1.1.7")
            #expect(point.count == 65)
            #expect(point[0] == 0x04, "EC point should start with 0x04 (uncompressed)")
        } else {
            Issue.record("Expected ECDSA key")
        }
    }

    @Test
    func `ECDSA Active Authentication verifier succeeds for P-256 SHA-256`() throws {
        let privateKey = P256.Signing.PrivateKey()
        let challenge = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let derSignature = try privateKey.signature(for: challenge).derRepresentation
        let plainSignature = try derSignatureToPlain(derSignature, componentLength: 32)

        let securityInfos = SecurityInfos(
            paceInfos: [],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: [ActiveAuthenticationInfo(
                protocolOID: SecurityProtocol.aaRSA.rawValue,
                securityProtocol: .aaRSA,
                version: 1,
                signatureAlgorithmOID: "0.4.0.127.0.7.1.1.4.1.3"
            )]
        )

        let result = ActiveAuthenticationVerifier.verify(
            challenge: challenge,
            signature: plainSignature,
            publicKey: .ecdsa(
                curveOID: "1.2.840.10045.3.1.7",
                publicPoint: privateKey.publicKey.x963Representation
            ),
            securityInfos: securityInfos
        )

        #expect(result.success)
        #expect(result.status == .verified)
    }

    @Test
    func `ECDSA Active Authentication falls back to the curve OID when the DG15 SPKI is not DER`() throws {
        let privateKey = P256.Signing.PrivateKey()
        let challenge = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let derSignature = try privateKey.signature(for: challenge).derRepresentation
        let plainSignature = try derSignatureToPlain(derSignature, componentLength: 32)

        let securityInfos = SecurityInfos(
            paceInfos: [],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: [ActiveAuthenticationInfo(
                protocolOID: SecurityProtocol.aaRSA.rawValue,
                securityProtocol: .aaRSA,
                version: 1,
                signatureAlgorithmOID: "0.4.0.127.0.7.1.1.4.1.3"
            )]
        )

        // BER indefinite-length SEQUENCE: valid BER, rejected by OpenSSL's DER decoder.
        let berSPKI = Data([0x30, 0x80, 0x00, 0x00])
        let result = ActiveAuthenticationVerifier.verify(
            challenge: challenge,
            signature: plainSignature,
            publicKey: .ecdsa(
                curveOID: "1.2.840.10045.3.1.7",
                publicPoint: privateKey.publicKey.x963Representation
            ),
            subjectPublicKeyInfo: berSPKI,
            securityInfos: securityInfos
        )

        #expect(result.status == .verified)
        #expect(result.success)
    }

    @Test
    func `ECDSA Active Authentication verifier fails for wrong challenge`() throws {
        let privateKey = P256.Signing.PrivateKey()
        let challenge = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let derSignature = try privateKey.signature(for: challenge).derRepresentation
        let plainSignature = try derSignatureToPlain(derSignature, componentLength: 32)

        let securityInfos = SecurityInfos(
            paceInfos: [],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: [ActiveAuthenticationInfo(
                protocolOID: SecurityProtocol.aaRSA.rawValue,
                securityProtocol: .aaRSA,
                version: 1,
                signatureAlgorithmOID: "0.4.0.127.0.7.1.1.4.1.3"
            )]
        )

        let result = ActiveAuthenticationVerifier.verify(
            challenge: Data([0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE]),
            signature: plainSignature,
            publicKey: .ecdsa(
                curveOID: "1.2.840.10045.3.1.7",
                publicPoint: privateKey.publicKey.x963Representation
            ),
            securityInfos: securityInfos
        )

        #expect(!result.success)
        #expect(result.status == .failed)
    }

    @Test
    func `ECDSA Active Authentication rejects r and s longer than the curve order`() throws {
        let privateKey = P256.Signing.PrivateKey()
        let challenge = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let derSignature = try privateKey.signature(for: challenge).derRepresentation
        let plainSignature = try derSignatureToPlain(derSignature, componentLength: 32)
        // Same r and s, each left-padded to 33 bytes: numerically valid, wrong length.
        let padded = Data([0x00]) + plainSignature.prefix(32) + Data([0x00]) + plainSignature.suffix(32)

        let securityInfos = SecurityInfos(
            paceInfos: [],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: [ActiveAuthenticationInfo(
                protocolOID: SecurityProtocol.aaRSA.rawValue,
                securityProtocol: .aaRSA,
                version: 1,
                signatureAlgorithmOID: "0.4.0.127.0.7.1.1.4.1.3"
            )]
        )
        let publicKey = ActiveAuthenticationPublicKey.ecdsa(
            curveOID: "1.2.840.10045.3.1.7",
            publicPoint: privateKey.publicKey.x963Representation
        )

        let rejected = ActiveAuthenticationVerifier.verify(
            challenge: challenge,
            signature: padded,
            publicKey: publicKey,
            securityInfos: securityInfos
        )
        #expect(rejected.status == .failed)
        #expect(!rejected.success)

        let accepted = ActiveAuthenticationVerifier.verify(
            challenge: challenge,
            signature: plainSignature,
            publicKey: publicKey,
            securityInfos: securityInfos
        )
        #expect(accepted.status == .verified)
    }

    #if canImport(OpenSSL)
        /// ISO 9796-2 scheme 1 signature (SHA-256, trailer 34CC) over `challenge`.
        private func makeISO9796Signature(
            challenge: Data,
            privateKey: OpaquePointer,
            payloadByte: UInt8 = 0xA5
        ) throws -> Data {
            let keySize = Int(EVP_PKEY_get_size(privateKey))
            let digestLength = 32
            let payload = Data(repeating: payloadByte, count: keySize - 1 - digestLength - 2)
            var recovered = Data([0x6A])
            recovered.append(payload)
            recovered.append(HashUtils.sha256(payload + challenge))
            recovered.append(contentsOf: [0x34, 0xCC])
            return try rawRSASign(message: recovered, privateKey: privateKey)
        }

        @Test
        func `RSA Active Authentication rejects a signature shorter than the modulus`() throws {
            let privateKey = try makeRSATestKey(bits: 1024)
            defer { EVP_PKEY_free(privateKey) }
            let publicKey = try exportRSAPublicKey(privateKey)

            // Find a signature with a leading zero byte (about 1 in 256), then drop it:
            // the integer is unchanged, but ISO/IEC 9796-2 fixes the length to the
            // modulus length.
            var challenge = Data()
            var stripped: Data?
            for attempt in UInt32(0) ..< 8192 where stripped == nil {
                challenge = Data([0x11, 0x22, 0x33, 0x44]) + withUnsafeBytes(of: attempt.bigEndian) { Data($0) }
                let signature = try makeISO9796Signature(challenge: challenge, privateKey: privateKey)
                if signature.first == 0x00 { stripped = Data(signature.dropFirst()) }
                if attempt == 0 {
                    let full = ActiveAuthenticationVerifier.verify(
                        challenge: challenge, signature: signature, publicKey: publicKey, securityInfos: nil
                    )
                    #expect(full.status == .verified)
                }
            }
            let shortSignature = try #require(stripped)

            let result = ActiveAuthenticationVerifier.verify(
                challenge: challenge,
                signature: shortSignature,
                publicKey: publicKey,
                securityInfos: nil
            )
            #expect(result.status == .failed)
            #expect(!result.success)
        }

        @Test
        func `RSA Active Authentication rejects moduli shorter than 1024 bits`() throws {
            let challenge = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            let privateKey = try makeRSATestKey(bits: 768)
            defer { EVP_PKEY_free(privateKey) }

            let result = ActiveAuthenticationVerifier.verify(
                challenge: challenge,
                signature: try makeISO9796Signature(challenge: challenge, privateKey: privateKey),
                publicKey: try exportRSAPublicKey(privateKey),
                securityInfos: nil
            )
            #expect(result.status == .failed)
            #expect(result.details.contains("1024"))
        }

        @Test
        func `RSA Active Authentication verifier succeeds for ISO 9796-2 recovered message`() throws {
            let challenge = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            let privateKey = try makeRSATestKey(bits: 1024)
            defer { EVP_PKEY_free(privateKey) }

            let keySize = Int(EVP_PKEY_get_size(privateKey))
            let digestLength = 32
            let payloadLength = keySize - 1 - digestLength - 2
            let payload = Data(repeating: 0xA5, count: payloadLength)

            var hashInput = payload
            hashInput.append(challenge)
            let digest = HashUtils.sha256(hashInput)

            var recovered = Data([0x6A])
            recovered.append(payload)
            recovered.append(digest)
            recovered.append(0x34)
            recovered.append(0xCC)

            let signature = try rawRSASign(message: recovered, privateKey: privateKey)
            let publicKey = try exportRSAPublicKey(privateKey)

            let result = ActiveAuthenticationVerifier.verify(
                challenge: challenge,
                signature: signature,
                publicKey: publicKey,
                securityInfos: nil
            )

            #expect(result.success)
            #expect(result.status == .verified)
        }
    #endif

    private func derSignatureToPlain(_ der: Data, componentLength: Int) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(der)
        let sequence = try #require(nodes.first(where: { $0.tag == 0x30 }))
        let parts = try sequence.children()
        let r = try #require(parts.first(where: { $0.tag == 0x02 }))
        let s = try #require(parts.dropFirst().first(where: { $0.tag == 0x02 }))
        return normalizeInteger(r.value, to: componentLength) + normalizeInteger(s.value, to: componentLength)
    }

    private func normalizeInteger(_ value: Data, to length: Int) -> Data {
        var normalized = value
        while normalized.count > 1, normalized.first == 0x00 {
            normalized.removeFirst()
        }
        if normalized.count >= length {
            return Data(normalized.suffix(length))
        }
        return Data(repeating: 0x00, count: length - normalized.count) + normalized
    }

    #if canImport(OpenSSL)
        private func makeRSATestKey(bits: Int32) throws -> OpaquePointer {
            guard let keygenContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil) else {
                throw NFCError.cryptoError("Failed to allocate RSA keygen context")
            }
            defer { EVP_PKEY_CTX_free(keygenContext) }

            guard EVP_PKEY_keygen_init(keygenContext) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_keygen_init failed")
            }

            guard EVP_PKEY_CTX_set_rsa_keygen_bits(keygenContext, bits) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_set_rsa_keygen_bits failed")
            }

            var generatedKey: OpaquePointer?
            guard EVP_PKEY_keygen(keygenContext, &generatedKey) == 1, let generatedKey else {
                throw NFCError.cryptoError("EVP_PKEY_keygen failed")
            }

            return generatedKey
        }

        private func rawRSASign(message: Data, privateKey: OpaquePointer) throws -> Data {
            guard let context = EVP_PKEY_CTX_new(privateKey, nil) else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_new failed")
            }
            defer { EVP_PKEY_CTX_free(context) }

            guard EVP_PKEY_sign_init(context) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_sign_init failed")
            }

            guard EVP_PKEY_CTX_set_rsa_padding(context, RSA_NO_PADDING) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_set_rsa_padding failed")
            }

            var signatureLength = 0
            let lengthResult = message.withUnsafeBytes { msgPtr in
                EVP_PKEY_sign(
                    context,
                    nil,
                    &signatureLength,
                    msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    message.count
                )
            }
            guard lengthResult == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_sign length query failed")
            }

            var signature = Data(repeating: 0x00, count: signatureLength)
            let signResult = message.withUnsafeBytes { msgPtr in
                signature.withUnsafeMutableBytes { sigPtr in
                    EVP_PKEY_sign(
                        context,
                        sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &signatureLength,
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count
                    )
                }
            }
            guard signResult == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_sign failed")
            }

            if signature.count != signatureLength {
                signature.removeSubrange(signatureLength...)
            }
            return signature
        }

        private func exportRSAPublicKey(_ privateKey: OpaquePointer) throws -> ActiveAuthenticationPublicKey {
            guard let output = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("Failed to allocate OpenSSL public key export state")
            }
            defer { BIO_free(output) }

            guard i2d_PUBKEY_bio(output, privateKey) == 1 else {
                throw NFCError.cryptoError("i2d_PUBKEY_bio failed")
            }

            let length = Int(BIO_ctrl(output, BIO_CTRL_PENDING, 0, nil))
            var der = Data(repeating: 0x00, count: length)
            _ = der.withUnsafeMutableBytes { ptr in
                BIO_read(output, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(length))
            }

            let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: der)
            return try DG15Parser.parse(dg15Data)
        }
    #endif
}
