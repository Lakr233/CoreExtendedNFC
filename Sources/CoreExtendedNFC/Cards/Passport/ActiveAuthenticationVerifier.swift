import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

enum ActiveAuthenticationVerifier {
    private struct HashDescriptor {
        let algorithmName: String
        let digestLength: Int
        let compute: @Sendable (Data) -> Data
    }

    private static let ecPublicKeyOID = "1.2.840.10045.2.1"

    static func verify(
        challenge: Data,
        signature: Data,
        publicKey: ActiveAuthPublicKey,
        subjectPublicKeyInfo: Data? = nil,
        securityInfos: SecurityInfos?
    ) -> ActiveAuthenticationResult {
        switch publicKey {
        case let .rsa(modulus, exponent):
            verifyRSA(
                challenge: challenge,
                signature: signature,
                modulus: modulus,
                exponent: exponent
            )

        case let .ecdsa(curveOID, publicPoint):
            verifyECDSA(
                challenge: challenge,
                signature: signature,
                curveOID: curveOID,
                publicPoint: publicPoint,
                subjectPublicKeyInfo: subjectPublicKeyInfo,
                securityInfos: securityInfos
            )

        case .unknown:
            ActiveAuthenticationResult(
                success: false,
                details: "Unknown public key type — cannot verify Active Authentication",
                status: .unsupportedKeyType
            )
        }
    }

    private static func verifyRSA(
        challenge: Data,
        signature: Data,
        modulus: Data,
        exponent: Data
    ) -> ActiveAuthenticationResult {
        #if canImport(OpenSSL)
            do {
                let publicKey = try readRSAPublicKey(modulus: modulus, exponent: exponent)
                defer { EVP_PKEY_free(publicKey) }

                let recovered = try rsaPublicRecover(signature: signature, publicKey: publicKey)
                guard let (descriptor, payload, digest) = parseRecoveredRSASignature(recovered) else {
                    return ActiveAuthenticationResult(
                        success: false,
                        details: "RSA Active Authentication signature format is invalid",
                        status: .failed
                    )
                }

                var fullMessage = payload
                fullMessage.append(challenge)
                let expectedDigest = descriptor.compute(fullMessage)

                guard CryptoUtils.constantTimeEquals(expectedDigest, digest) else {
                    return ActiveAuthenticationResult(
                        success: false,
                        details: "RSA Active Authentication digest mismatch",
                        status: .failed
                    )
                }

                return ActiveAuthenticationResult(
                    success: true,
                    details: "RSA Active Authentication verified using ISO 9796-2 message recovery",
                    status: .verified
                )
            } catch {
                return ActiveAuthenticationResult(
                    success: false,
                    details: "RSA Active Authentication failed: \(error)",
                    status: .failed
                )
            }
        #else
            return ActiveAuthenticationResult(
                success: false,
                details: "RSA Active Authentication requires OpenSSL integration",
                status: .notImplemented
            )
        #endif
    }

    private static func verifyECDSA(
        challenge: Data,
        signature: Data,
        curveOID: String,
        publicPoint: Data,
        subjectPublicKeyInfo: Data?,
        securityInfos: SecurityInfos?
    ) -> ActiveAuthenticationResult {
        guard let signatureOID = securityInfos?.activeAuthInfos.first?.signatureAlgorithmOID,
              let descriptor = hashDescriptorForECDSA(signatureOID)
        else {
            return ActiveAuthenticationResult(
                success: false,
                details: "ECDSA Active Authentication requires DG14 signatureAlgorithmOID",
                status: .notImplemented
            )
        }

        #if canImport(OpenSSL)
            // Prefer the DG15 SubjectPublicKeyInfo as stored: it may use explicit
            // ECParameters, which cannot be rebuilt from a curve OID. When OpenSSL rejects
            // the stored encoding (e.g. non-DER BER from the chip), rebuild a named-curve
            // key from the parsed curve OID and point instead.
            let loadedKey: OpaquePointer? = subjectPublicKeyInfo.flatMap {
                try? readPublicKey(subjectPublicKeyInfoDER: $0)
            } ?? (try? readECPublicKey(curveOID: curveOID, publicPoint: publicPoint))
            guard let publicKey = loadedKey, EVP_PKEY_get_base_id(publicKey) == EVP_PKEY_EC else {
                if let loadedKey { EVP_PKEY_free(loadedKey) }
                return ActiveAuthenticationResult(
                    success: false,
                    details: "ECDSA Active Authentication public key could not be loaded (curve \(curveOID))",
                    status: .unsupportedKeyType
                )
            }
            defer { EVP_PKEY_free(publicKey) }

            do {
                let derSignature = try convertPlainECDSASignatureToDER(signature)
                let verified = verifySignature(
                    data: challenge,
                    signature: derSignature,
                    publicKey: publicKey,
                    digestName: descriptor.algorithmName
                )

                return ActiveAuthenticationResult(
                    success: verified,
                    details: verified
                        ? "ECDSA Active Authentication signature verified"
                        : "ECDSA Active Authentication signature verification failed",
                    status: verified ? .verified : .failed
                )
            } catch {
                return ActiveAuthenticationResult(
                    success: false,
                    details: "ECDSA Active Authentication failed: \(error)",
                    status: .failed
                )
            }
        #else
            return ActiveAuthenticationResult(
                success: false,
                details: "ECDSA Active Authentication requires OpenSSL integration",
                status: .notImplemented
            )
        #endif
    }

    private static func hashDescriptorForECDSA(_ oid: String) -> HashDescriptor? {
        switch oid {
        case "0.4.0.127.0.7.1.1.4.1.1":
            HashDescriptor(algorithmName: "sha1", digestLength: 20, compute: HashUtils.sha1)
        case "0.4.0.127.0.7.1.1.4.1.2":
            HashDescriptor(algorithmName: "sha224", digestLength: 28, compute: HashUtils.sha224)
        case "0.4.0.127.0.7.1.1.4.1.3":
            HashDescriptor(algorithmName: "sha256", digestLength: 32, compute: HashUtils.sha256)
        case "0.4.0.127.0.7.1.1.4.1.4":
            HashDescriptor(algorithmName: "sha384", digestLength: 48, compute: HashUtils.sha384)
        case "0.4.0.127.0.7.1.1.4.1.5":
            HashDescriptor(algorithmName: "sha512", digestLength: 64, compute: HashUtils.sha512)
        default:
            nil
        }
    }

    private static func hashDescriptorForRSATrailer(_ trailer: UInt8) -> HashDescriptor? {
        switch trailer {
        case 0xBC, 0x33:
            HashDescriptor(algorithmName: "sha1", digestLength: 20, compute: HashUtils.sha1)
        case 0x34:
            HashDescriptor(algorithmName: "sha256", digestLength: 32, compute: HashUtils.sha256)
        case 0x35:
            HashDescriptor(algorithmName: "sha512", digestLength: 64, compute: HashUtils.sha512)
        case 0x36:
            HashDescriptor(algorithmName: "sha384", digestLength: 48, compute: HashUtils.sha384)
        case 0x38:
            HashDescriptor(algorithmName: "sha224", digestLength: 28, compute: HashUtils.sha224)
        default:
            nil
        }
    }

    private static func parseRecoveredRSASignature(_ recovered: Data) -> (HashDescriptor, Data, Data)? {
        guard recovered.count >= 3 else {
            return nil
        }

        var body = recovered
        let lastByte = body.removeLast()

        let trailerByte: UInt8
        if lastByte == 0xBC {
            trailerByte = lastByte
        } else if lastByte == 0xCC, let hashIdentifier = body.popLast() {
            trailerByte = hashIdentifier
        } else {
            return nil
        }

        guard let descriptor = hashDescriptorForRSATrailer(trailerByte),
              body.count >= 1 + descriptor.digestLength,
              body.first == 0x6A
        else {
            return nil
        }

        let payloadRange = 1 ..< (body.count - descriptor.digestLength)
        let payload = Data(body[payloadRange])
        let digest = Data(body.suffix(descriptor.digestLength))
        return (descriptor, payload, digest)
    }

    #if canImport(OpenSSL)
        private static func readRSAPublicKey(modulus: Data, exponent: Data) throws -> OpaquePointer {
            let spki = makeRSASubjectPublicKeyInfo(modulus: modulus, exponent: exponent)

            guard let input = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("BIO_new failed")
            }
            defer { BIO_free(input) }

            _ = spki.withUnsafeBytes { ptr in
                BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(spki.count))
            }

            guard let key = d2i_PUBKEY_bio(input, nil) else {
                throw NFCError.cryptoError("d2i_PUBKEY_bio failed")
            }

            return key
        }

        private static func rsaPublicRecover(signature: Data, publicKey: OpaquePointer) throws -> Data {
            guard let context = EVP_PKEY_CTX_new(publicKey, nil) else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_new failed")
            }
            defer { EVP_PKEY_CTX_free(context) }

            guard EVP_PKEY_verify_recover_init(context) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_verify_recover_init failed")
            }

            guard EVP_PKEY_CTX_set_rsa_padding(context, RSA_NO_PADDING) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_set_rsa_padding failed")
            }

            var recoveredLength = 0
            let lengthResult = signature.withUnsafeBytes { sigPtr in
                EVP_PKEY_verify_recover(
                    context,
                    nil,
                    &recoveredLength,
                    sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signature.count
                )
            }
            guard lengthResult == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_verify_recover length query failed")
            }

            var recovered = Data(repeating: 0x00, count: recoveredLength)
            let recoverResult = signature.withUnsafeBytes { sigPtr in
                recovered.withUnsafeMutableBytes { outPtr in
                    EVP_PKEY_verify_recover(
                        context,
                        outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &recoveredLength,
                        sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        signature.count
                    )
                }
            }
            guard recoverResult == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_verify_recover failed")
            }

            if recovered.count != recoveredLength {
                recovered.removeSubrange(recoveredLength...)
            }
            return recovered
        }

        private static func makeRSASubjectPublicKeyInfo(modulus: Data, exponent: Data) -> Data {
            let rsaEncryptionOID = ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.1.1"))
            let nullParameters = ASN1Parser.encodeTLV(tag: 0x05, value: Data())
            let algorithmIdentifier = ASN1Parser.encodeTLV(tag: 0x30, value: rsaEncryptionOID + nullParameters)

            let rsaPublicKey = ASN1Parser.encodeTLV(
                tag: 0x30,
                value: encodeASN1Integer(modulus) + encodeASN1Integer(exponent)
            )

            var bitString = Data([0x00])
            bitString.append(rsaPublicKey)
            let subjectPublicKey = ASN1Parser.encodeTLV(tag: 0x03, value: bitString)

            return ASN1Parser.encodeTLV(tag: 0x30, value: algorithmIdentifier + subjectPublicKey)
        }

        private static func encodeASN1Integer(_ value: Data) -> Data {
            var normalized = value.drop(while: { $0 == 0x00 })
            if normalized.isEmpty {
                normalized = Data([0x00])[...]
            }

            var integerBytes = Data(normalized)
            if let first = integerBytes.first, first & 0x80 != 0 {
                integerBytes.insert(0x00, at: 0)
            }

            return ASN1Parser.encodeTLV(tag: 0x02, value: integerBytes)
        }

        private static func readECPublicKey(curveOID: String, publicPoint: Data) throws -> OpaquePointer {
            let algorithmOID = ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(ecPublicKeyOID))
            let curveOIDData = ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(curveOID))
            let algorithmIdentifier = ASN1Parser.encodeTLV(tag: 0x30, value: algorithmOID + curveOIDData)

            var bitStringValue = Data([0x00])
            bitStringValue.append(publicPoint)
            let subjectPublicKey = ASN1Parser.encodeTLV(tag: 0x03, value: bitStringValue)
            let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algorithmIdentifier + subjectPublicKey)
            return try readPublicKey(subjectPublicKeyInfoDER: spki)
        }

        /// Load a DER SubjectPublicKeyInfo (named or explicit parameters) into an EVP_PKEY.
        private static func readPublicKey(subjectPublicKeyInfoDER spki: Data) throws -> OpaquePointer {
            guard let input = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("BIO_new failed")
            }
            defer { BIO_free(input) }

            _ = spki.withUnsafeBytes { ptr in
                BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(spki.count))
            }

            guard let key = d2i_PUBKEY_bio(input, nil) else {
                throw NFCError.cryptoError("d2i_PUBKEY_bio failed")
            }

            return key
        }

        private static func convertPlainECDSASignatureToDER(_ signature: Data) throws -> Data {
            guard signature.count >= 2, signature.count.isMultiple(of: 2) else {
                throw NFCError.cryptoError("ECDSA signature must be plain r||s")
            }

            guard let ecdsaSignature = ECDSA_SIG_new() else {
                throw NFCError.cryptoError("ECDSA_SIG_new failed")
            }
            defer { ECDSA_SIG_free(ecdsaSignature) }

            let componentLength = signature.count / 2
            let rData = Data(signature.prefix(componentLength))
            let sData = Data(signature.suffix(componentLength))

            guard let r = rData.withUnsafeBytes({ ptr in
                BN_bin2bn(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(componentLength), nil)
            }), let s = sData.withUnsafeBytes({ ptr in
                BN_bin2bn(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(componentLength), nil)
            }) else {
                throw NFCError.cryptoError("BN_bin2bn failed for ECDSA signature")
            }

            guard ECDSA_SIG_set0(ecdsaSignature, r, s) == 1 else {
                BN_free(r)
                BN_free(s)
                throw NFCError.cryptoError("ECDSA_SIG_set0 failed")
            }

            let derLength = i2d_ECDSA_SIG(ecdsaSignature, nil)
            guard derLength > 0 else {
                throw NFCError.cryptoError("i2d_ECDSA_SIG length calculation failed")
            }

            var der = Data(repeating: 0x00, count: Int(derLength))
            let written = der.withUnsafeMutableBytes { ptr -> Int32 in
                var cursor = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return i2d_ECDSA_SIG(ecdsaSignature, &cursor)
            }

            guard written == derLength else {
                throw NFCError.cryptoError("i2d_ECDSA_SIG encoding failed")
            }

            return der
        }

        private static func verifySignature(
            data: Data,
            signature: Data,
            publicKey: OpaquePointer,
            digestName: String
        ) -> Bool {
            guard let ctx = EVP_MD_CTX_new() else {
                return false
            }
            defer { EVP_MD_CTX_free(ctx) }

            var keyContext: OpaquePointer?
            let digest = digestName.withCString { name in
                EVP_get_digestbyname(name)
            }
            guard let digest else {
                return false
            }

            guard EVP_DigestVerifyInit(ctx, &keyContext, digest, nil, publicKey) == 1 else {
                return false
            }

            let updateResult = data.withUnsafeBytes { ptr in
                EVP_DigestUpdate(ctx, ptr.baseAddress, data.count)
            }
            guard updateResult == 1 else {
                return false
            }

            let finalResult = signature.withUnsafeBytes { ptr in
                EVP_DigestVerifyFinal(
                    ctx,
                    ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signature.count
                )
            }

            return finalResult == 1
        }
    #endif
}
