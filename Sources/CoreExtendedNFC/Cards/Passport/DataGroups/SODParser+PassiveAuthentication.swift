import Foundation

#if canImport(OpenSSL)
    import OpenSSL
#endif

public extension SODParser {
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

        // Use signatureNotVerified when hashes pass — makes clear that CMS
        // signature verification was NOT performed. When nothing was compared (only
        // COM/SOD read, or every covered data group absent) there is no mismatch to
        // report either: the result stays neutral and its hash results stay empty.
        let status: PassiveAuthenticationStatus = if results.values.allSatisfy(\.self) {
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
        case let .verified(signerCertificateDER):
            if trustAnchorsDER.isEmpty {
                return PassiveAuthenticationResult(
                    dataGroupHashResults: hashResult.dataGroupHashResults,
                    hasCertificate: hashResult.hasCertificate,
                    cmsSignatureValid: true,
                    trustChainValid: nil,
                    status: .signatureVerified
                )
            }

            // Validate the certificate whose key actually verified the signature: a SOD
            // carrying a genuine DSC next to a self-signed signer must not pass.
            let trustValid = verifyTrustChain(
                documentSignerCertificateDER: signerCertificateDER,
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

    enum CMSSignatureStatus: Sendable, Equatable {
        case unavailable
        /// Verified with the key of this certificate (DER), the one the SignerInfo names.
        case verified(signerCertificateDER: Data)
        case invalid
    }

    static func verifyCMSSignature(sodContent: SODContent) -> CMSSignatureStatus {
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

            // ICAO 9303-10 §4.6.2: the SOD carries exactly one SignerInfo (the DSC's).
            guard let signerInfos = CMS_get0_SignerInfos(cms), OPENSSL_sk_num(signerInfos) == 1 else {
                return .invalid
            }

            // The signer certificate is checked against the CSCA anchors separately, on
            // the exact certificate CMS_verify used (see verifyPassiveAuthentication).
            let flags = UInt32(CMS_NO_SIGNER_CERT_VERIFY)
            guard CMS_verify(cms, nil, nil, nil, output, flags) == 1 else {
                return .invalid
            }

            guard let signers = CMS_get0_signers(cms) else {
                return .invalid
            }
            defer { OPENSSL_sk_free(signers) }
            guard OPENSSL_sk_num(signers) == 1,
                  let signerPointer = OPENSSL_sk_value(signers, 0),
                  let signerCertificateDER = encodeX509Certificate(OpaquePointer(signerPointer))
            else {
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

            return .verified(signerCertificateDER: signerCertificateDER)
        #else
            return .unavailable
        #endif
    }

    /// DER of the embedded certificate that the (single) SignerInfo's SID identifies.
    ///
    /// Returns `nil` when the CMS cannot be decoded, does not have exactly one
    /// SignerInfo, or embeds no certificate matching it.
    static func signerCertificateDER(cmsDER: Data) -> Data? {
        #if canImport(OpenSSL)
            guard let input = BIO_new(BIO_s_mem()) else { return nil }
            defer { BIO_free(input) }
            let writeCount = cmsDER.withUnsafeBytes { ptr in
                BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(cmsDER.count))
            }
            guard writeCount == cmsDER.count, let cms = d2i_CMS_bio(input, nil) else { return nil }
            defer { CMS_ContentInfo_free(cms) }

            guard let signerInfos = CMS_get0_SignerInfos(cms),
                  OPENSSL_sk_num(signerInfos) == 1,
                  let signerInfoPointer = OPENSSL_sk_value(signerInfos, 0),
                  let certificates = CMS_get1_certs(cms)
            else {
                return nil
            }
            let signerInfo = OpaquePointer(signerInfoPointer)
            defer {
                for index in 0 ..< OPENSSL_sk_num(certificates) {
                    if let certificate = OPENSSL_sk_value(certificates, index) {
                        X509_free(OpaquePointer(certificate))
                    }
                }
                OPENSSL_sk_free(certificates)
            }

            for index in 0 ..< OPENSSL_sk_num(certificates) {
                guard let certificatePointer = OPENSSL_sk_value(certificates, index) else { continue }
                let certificate = OpaquePointer(certificatePointer)
                if CMS_SignerInfo_cert_cmp(signerInfo, certificate) == 0 {
                    return encodeX509Certificate(certificate)
                }
            }
            return nil
        #else
            return nil
        #endif
    }

    private static func encodeX509Certificate(_ certificate: OpaquePointer) -> Data? {
        let length = i2d_X509(certificate, nil)
        guard length > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(length))
        let written = bytes.withUnsafeMutableBufferPointer { buffer -> Int32 in
            var cursor = buffer.baseAddress
            return i2d_X509(certificate, &cursor)
        }
        guard written == length else { return nil }
        return Data(bytes)
    }

    static func verifyTrustChain(
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
