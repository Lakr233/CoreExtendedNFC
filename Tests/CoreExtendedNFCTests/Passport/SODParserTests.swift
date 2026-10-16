// SOD (Security Object Document) parser test suite.
//
// ## References
// - ICAO Doc 9303 Part 11, Section 9.3: Passive Authentication and SOD structure
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - ICAO Doc 9303 Part 11: LDS Security Object OID = 2.23.136.1.1.1 (id-icao-lds-SOD)
// - RFC 5652 (CMS): SignedData structure, signedAttrs re-tagging from [0] to SET (0x31)
//   https://www.rfc-editor.org/rfc/rfc5652
// - RFC 5652 Section 5.4: For hash computation, signedAttrs must be re-encoded as SET (0x31)
// - Hash OIDs (NIST): SHA-1=1.3.14.3.2.26, SHA-224=2.16.840.1.101.3.4.2.4,
//   SHA-256=2.16.840.1.101.3.4.2.1, SHA-384=2.16.840.1.101.3.4.2.2,
//   SHA-512=2.16.840.1.101.3.4.2.3
//   https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
// - JMRTD SODFile.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/lds/SODFile.java
@testable import CoreExtendedNFC
import Foundation
#if canImport(OpenSSL)
    import OpenSSL
#endif
import Testing

struct SODParserTests {
    // MARK: - Hash Algorithm Handling

    @Test
    func `Unknown hash algorithm returns .unsupportedHashAlgorithm instead of silent fallback`() {
        let rawDG1 = Data(repeating: 0x42, count: 100)

        let sodContent = SODContent(
            hashAlgorithmOID: "1.2.3.4.5.6.7",
            hashAlgorithm: "UNKNOWN-HASH",
            dataGroupHashes: [.dg1: Data(repeating: 0xFF, count: 32)],
            ldsVersion: nil,
            unicodeVersion: nil,
            documentSignerCertificate: nil,
            signedAttributes: nil,
            signature: nil,
            signatureAlgorithmOID: nil,
            encapsulatedContent: nil
        )

        let result = SODParser.verifyHashes(
            sodContent: sodContent,
            rawDataGroups: [.dg1: rawDG1]
        )

        // Should NOT silently fallback to SHA-256
        #expect(result.status == .unsupportedHashAlgorithm)
        #expect(result.dataGroupHashResults.isEmpty,
                "No hash results should be produced for unknown algorithm")
    }

    @Test
    func `SHA-224 hash algorithm (if present in SOD)`() throws {
        // SOD with SHA-224 OID
        let sha224OID = ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.4")
        let signedDataOID = ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.7.2")

        let digestAlgSeq = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: sha224OID))
        let digestAlgsSet = ASN1Parser.encodeTLV(tag: 0x31, value: digestAlgSeq)

        let version = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x00]))
        let hashAlg = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: sha224OID))

        let dg1Hash = Data(repeating: 0xAA, count: 28) // SHA-224 = 28 bytes
        let dgHashSeq = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01])) +
                ASN1Parser.encodeTLV(tag: 0x04, value: dg1Hash))

        let ldsSecObj = ASN1Parser.encodeTLV(tag: 0x30, value: version + hashAlg + dgHashSeq)
        let ldsOctetString = ASN1Parser.encodeTLV(tag: 0x04, value: ldsSecObj)

        let ldsSecObjOID = ChipAuthenticationHandler.encodeOID("2.23.136.1.1.1")
        let encapContent = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ldsSecObjOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value: ldsOctetString))

        let signerInfosSet = ASN1Parser.encodeTLV(tag: 0x31, value: Data())

        let signedDataVersion = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x03]))
        let signedData = ASN1Parser.encodeTLV(tag: 0x30, value:
            signedDataVersion + digestAlgsSet + encapContent + signerInfosSet)

        let contentInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: signedDataOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value: signedData))

        let sodData = ASN1Parser.encodeTLV(tag: 0x77, value: contentInfo)

        let result = try SODParser.parse(sodData)
        #expect(result.hashAlgorithm == "SHA-224")
        #expect(result.hashAlgorithmOID == "2.16.840.1.101.3.4.2.4")
    }

    // MARK: - Passive Auth Semantics

    @Test
    func `No data group compared is not reported as a hash mismatch`() {
        let sodContent = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            // SHA-256("\x61\x00")
            dataGroupHashes: [.dg1: vectorHex("FFE9AAEAA2A2D5048174DF0B80599EF0197EC024C4B051BC9860CFF58EF7F9F3")],
            ldsVersion: nil,
            unicodeVersion: nil,
            documentSignerCertificate: nil,
            signedAttributes: nil,
            signature: nil,
            signatureAlgorithmOID: nil,
            encapsulatedContent: nil
        )

        // Only COM and the SOD itself were read: nothing the SOD covers was compared.
        let result = SODParser.verifyHashes(
            sodContent: sodContent,
            rawDataGroups: [.com: Data([0x60, 0x00]), .sod: Data([0x77, 0x00])]
        )

        #expect(result.dataGroupHashResults.isEmpty)
        #expect(result.failedDataGroups.isEmpty)
        #expect(result.status != .hashMismatch)
        #expect(result.status == .signatureNotVerified)
        #expect(!result.allHashesValid)
    }

    @Test
    func `Hash comparison success reports signatureNotVerified, not full verification`() {
        let rawDG1 = Data(repeating: 0x42, count: 100)
        let expectedHash = HashUtils.sha256(rawDG1)

        let sodContent = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            dataGroupHashes: [.dg1: expectedHash],
            ldsVersion: nil,
            unicodeVersion: nil,
            documentSignerCertificate: nil,
            signedAttributes: nil,
            signature: nil,
            signatureAlgorithmOID: nil,
            encapsulatedContent: nil
        )

        let result = SODParser.verifyHashes(
            sodContent: sodContent,
            rawDataGroups: [.dg1: rawDG1]
        )

        #expect(result.allHashesValid)
        // The key assertion: must NOT claim full verification
        #expect(result.status == .signatureNotVerified,
                "Hash-only comparison should report .signatureNotVerified, not full PA complete")
    }

    @Test
    func `Missing DG data is skipped, not failed`() {
        let sodContent = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            dataGroupHashes: [
                .dg1: Data(repeating: 0xAA, count: 32),
                .dg2: Data(repeating: 0xBB, count: 32),
            ],
            ldsVersion: nil,
            unicodeVersion: nil,
            documentSignerCertificate: nil,
            signedAttributes: nil,
            signature: nil,
            signatureAlgorithmOID: nil,
            encapsulatedContent: nil
        )

        // Only provide DG1, not DG2
        let rawDG1 = Data(repeating: 0x42, count: 100)
        let result = SODParser.verifyHashes(
            sodContent: sodContent,
            rawDataGroups: [.dg1: rawDG1]
        )

        // DG1 should fail (hash doesn't match), DG2 should be skipped
        #expect(result.dataGroupHashResults.count == 1)
        #expect(result.dataGroupHashResults[.dg2] == nil, "Unread DG should not appear in results")
    }

    // MARK: - SignedAttrs DER Storage

    @Test
    func `signedAttrs stored as re-tagged SET (0x31) DER for CMS verification`() throws {
        // Build a minimal SignerInfo with signedAttrs [0] IMPLICIT
        let signedDataOID = ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.7.2")
        let sha256OID = ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.1")

        let digestAlgsSet = ASN1Parser.encodeTLV(tag: 0x31, value:
            ASN1Parser.encodeTLV(tag: 0x30, value:
                ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID)))

        // Minimal encapContentInfo
        let ldsSecObjOID = ChipAuthenticationHandler.encodeOID("2.23.136.1.1.1")
        let ldsSecObj = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x00])))
        let encapContent = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ldsSecObjOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value:
                    ASN1Parser.encodeTLV(tag: 0x04, value: ldsSecObj)))

        // SignerInfo with signedAttrs
        let signedAttrsContent = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let signedAttrsNode = ASN1Parser.encodeTLV(tag: 0xA0, value: signedAttrsContent)
        let sigAlg = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID))
        let signature = ASN1Parser.encodeTLV(tag: 0x04, value: Data(repeating: 0xAB, count: 32))
        let signerInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01])) +
                signedAttrsNode + sigAlg + signature)
        let signerInfosSet = ASN1Parser.encodeTLV(tag: 0x31, value: signerInfo)

        let signedDataVersion = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x03]))
        let signedData = ASN1Parser.encodeTLV(tag: 0x30, value:
            signedDataVersion + digestAlgsSet + encapContent + signerInfosSet)
        let contentInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: signedDataOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value: signedData))
        let sodData = ASN1Parser.encodeTLV(tag: 0x77, value: contentInfo)

        let result = try SODParser.parse(sodData)

        // signedAttrs should be stored as SET (0x31) DER, not raw value
        if let attrs = result.signedAttributes {
            #expect(attrs[0] == 0x31,
                    "signedAttrs should start with SET tag 0x31 for CMS verification, got \(String(format: "0x%02X", attrs[0]))")
        }
    }

    // MARK: - LDSSecurityObject structure (ICAO 9303-10 §4.6.2.2)

    /// EF.SOD around `ldsSecurityObject` with SignedData digestAlgorithms SHA-256 and no signer.
    private func makeUnsignedSOD(
        ldsSecurityObject: Data,
        eContentTypeOID: String = "2.23.136.1.1.1"
    ) -> Data {
        let sha256OID = ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.1")
        let digestAlgorithms = ASN1Parser.encodeTLV(tag: 0x31, value:
            ASN1Parser.encodeTLV(tag: 0x30, value: ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID)))
        let encapContent = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(eContentTypeOID))
                + ASN1Parser.encodeTLV(tag: 0xA0, value: ASN1Parser.encodeTLV(tag: 0x04, value: ldsSecurityObject)))
        let signedData = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x03]))
                + digestAlgorithms + encapContent + ASN1Parser.encodeTLV(tag: 0x31, value: Data()))
        let contentInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(SODParser.signedDataOID))
                + ASN1Parser.encodeTLV(tag: 0xA0, value: signedData))
        return ASN1Parser.encodeTLV(tag: 0x77, value: contentInfo)
    }

    private func makeLDSSecurityObject(
        version: UInt8,
        hashOID: String = "2.16.840.1.101.3.4.2.1",
        ldsVersionInfo: Data? = nil
    ) -> Data {
        let hashAlgorithm = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(hashOID)))
        let dgHash = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01]))
                + ASN1Parser.encodeTLV(tag: 0x04, value: Data(repeating: 0xAB, count: 32)))
        let dgHashes = ASN1Parser.encodeTLV(tag: 0x30, value: dgHash)
        return ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([version])) + hashAlgorithm + dgHashes + (ldsVersionInfo ?? Data()))
    }

    @Test
    func `LDSVersionInfo encoded as PrintableString is parsed`() throws {
        let versionInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x13, value: Data("0108".utf8))
                + ASN1Parser.encodeTLV(tag: 0x13, value: Data("040000".utf8)))
        let sod = try SODParser.parse(makeUnsignedSOD(
            ldsSecurityObject: makeLDSSecurityObject(version: 1, ldsVersionInfo: versionInfo)
        ))
        #expect(sod.ldsVersion == "0108")
        #expect(sod.unicodeVersion == "040000")
        #expect(sod.dataGroupHashes[.dg1] == Data(repeating: 0xAB, count: 32))
    }

    @Test
    func `LDSSecurityObject versions other than v0 and v1 are rejected`() {
        #expect(throws: NFCError.self) {
            _ = try SODParser.parse(makeUnsignedSOD(ldsSecurityObject: makeLDSSecurityObject(version: 2)))
        }
        let versionInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x13, value: Data("0108".utf8))
                + ASN1Parser.encodeTLV(tag: 0x13, value: Data("040000".utf8)))
        #expect(throws: NFCError.self) {
            _ = try SODParser.parse(makeUnsignedSOD(
                ldsSecurityObject: makeLDSSecurityObject(version: 0, ldsVersionInfo: versionInfo)
            ))
        }
        #expect(throws: Never.self) {
            _ = try SODParser.parse(makeUnsignedSOD(ldsSecurityObject: makeLDSSecurityObject(version: 0)))
        }
    }

    @Test
    func `Unknown LDSSecurityObject hash OID is unsupported, not replaced by digestAlgorithms`() throws {
        let sod = try SODParser.parse(makeUnsignedSOD(
            ldsSecurityObject: makeLDSSecurityObject(version: 0, hashOID: "1.2.3.4.5")
        ))
        #expect(sod.hashAlgorithmOID == "1.2.3.4.5")

        let result = SODParser.verifyHashes(sodContent: sod, rawDataGroups: [.dg1: Data("dg1".utf8)])
        #expect(result.status == .unsupportedHashAlgorithm)
    }

    @Test
    func `EF.SOD whose eContentType is not the LDS security object is rejected`() {
        #expect(throws: NFCError.self) {
            _ = try SODParser.parse(makeUnsignedSOD(
                ldsSecurityObject: makeLDSSecurityObject(version: 0),
                eContentTypeOID: "1.2.840.113549.1.7.1"
            ))
        }
    }

    #if canImport(OpenSSL)
        // MARK: - CMS content type and DSC key usage

        /// Replace the first DER encoding of `from` (the eContentType, which precedes the
        /// signed attributes) with `to`. eContentType is outside the signature.
        private func replacingFirstOID(in data: Data, from: String, to: String) throws -> Data {
            let fromDER = ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(from))
            let toDER = ASN1Parser.encodeTLV(tag: 0x06, value: ChipAuthenticationHandler.encodeOID(to))
            #expect(fromDER.count == toDER.count)
            let range = try #require(data.range(of: fromDER))
            var patched = data
            patched.replaceSubrange(range, with: toDER)
            return patched
        }

        @Test
        func `CMS whose eContentType is not the LDS security object fails the signature check`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            let (sodData, _) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1])
            let parsed = try SODParser.parse(sodData)
            let cmsData = try #require(parsed.rawCMSData)
            let patchedCMS = try replacingFirstOID(in: cmsData, from: "2.23.136.1.1.1", to: "2.23.136.1.1.2")

            #expect(throws: NFCError.self) {
                _ = try SODParser.parse(ASN1Parser.encodeTLV(tag: 0x77, value: patchedCMS))
            }
            let patched = SODContent(
                hashAlgorithmOID: parsed.hashAlgorithmOID,
                hashAlgorithm: parsed.hashAlgorithm,
                dataGroupHashes: parsed.dataGroupHashes,
                ldsVersion: parsed.ldsVersion,
                unicodeVersion: parsed.unicodeVersion,
                documentSignerCertificate: parsed.documentSignerCertificate,
                signedAttributes: parsed.signedAttributes,
                signature: parsed.signature,
                signatureAlgorithmOID: parsed.signatureAlgorithmOID,
                encapsulatedContent: parsed.encapsulatedContent,
                rawCMSData: patchedCMS
            )
            #expect(SODParser.verifyCMSSignature(sodContent: patched) == .invalid)
        }

        @Test
        func `CMS whose signed contentType attribute differs from eContentType is invalid`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            // Signed as 2.23.136.1.1.2 (contentType attribute = .2), then eContentType
            // rewritten to the LDS security object OID.
            let (signedData, _) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1], eContentTypeOID: "2.23.136.1.1.2")
            let sodData = try replacingFirstOID(in: signedData, from: "2.23.136.1.1.2", to: "2.23.136.1.1.1")

            let sodContent = try SODParser.parse(sodData)
            let result = SODParser.verifyPassiveAuthentication(sodContent: sodContent, rawDataGroups: [.dg1: rawDG1])

            #expect(result.allHashesValid)
            #expect(result.cmsSignatureValid == false)
            #expect(result.status == .signatureInvalid)
        }

        @Test
        func `DSC whose keyUsage omits digitalSignature fails trust validation`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            for (keyUsage, expected) in [
                ("critical,digitalSignature", PassiveAuthenticationStatus.fullyVerified),
                ("critical,nonRepudiation", PassiveAuthenticationStatus.trustChainInvalid),
            ] {
                let (sodData, signerDER) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1], keyUsage: keyUsage)
                let result = SODParser.verifyPassiveAuthentication(
                    sodContent: try SODParser.parse(sodData),
                    rawDataGroups: [.dg1: rawDG1],
                    trustAnchorsDER: [signerDER]
                )
                #expect(result.cmsSignatureValid == true, "\(keyUsage)")
                #expect(result.status == expected, "\(keyUsage)")
            }
        }

        @Test
        func `CMS-backed SOD verifies embedded signature and hashes`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            let (sodData, _) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1])

            let sodContent = try SODParser.parse(sodData)
            let result = SODParser.verifyPassiveAuthentication(
                sodContent: sodContent,
                rawDataGroups: [.dg1: rawDG1]
            )

            #expect(result.allHashesValid)
            #expect(result.cmsSignatureValid == true)
            #expect(result.status == .signatureVerified)
        }

        @Test
        func `CMS-backed SOD reports signatureInvalid when CMS bytes are tampered`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            let (sodData, _) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1])
            let parsed = try SODParser.parse(sodData)
            let cmsData = try #require(parsed.rawCMSData)

            var tamperedCMS = cmsData
            tamperedCMS[tamperedCMS.count - 1] ^= 0x01

            let tampered = SODContent(
                hashAlgorithmOID: parsed.hashAlgorithmOID,
                hashAlgorithm: parsed.hashAlgorithm,
                dataGroupHashes: parsed.dataGroupHashes,
                ldsVersion: parsed.ldsVersion,
                unicodeVersion: parsed.unicodeVersion,
                documentSignerCertificate: parsed.documentSignerCertificate,
                signedAttributes: parsed.signedAttributes,
                signature: parsed.signature,
                signatureAlgorithmOID: parsed.signatureAlgorithmOID,
                encapsulatedContent: parsed.encapsulatedContent,
                rawCMSData: tamperedCMS
            )

            let result = SODParser.verifyPassiveAuthentication(
                sodContent: tampered,
                rawDataGroups: [.dg1: rawDG1]
            )

            #expect(result.allHashesValid)
            #expect(result.cmsSignatureValid == false)
            #expect(result.status == .signatureInvalid)
        }

        @Test
        func `SOD fully verifies when DSC is trusted by provided anchors`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            let (sodData, signerDER) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1], returnSignerDER: true)

            let sodContent = try SODParser.parse(sodData)
            let result = SODParser.verifyPassiveAuthentication(
                sodContent: sodContent,
                rawDataGroups: [.dg1: rawDG1],
                trustAnchorsDER: [signerDER]
            )

            #expect(result.allHashesValid)
            #expect(result.cmsSignatureValid == true)
            #expect(result.trustChainValid == true)
            #expect(result.status == .fullyVerified)
        }

        @Test
        func `SOD trust chain reports invalid for unrelated anchors`() throws {
            let rawDG1 = Data("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<".utf8)
            let (sodData, _) = try makeSignedSOD(rawDataGroups: [.dg1: rawDG1], returnSignerDER: true)
            let (otherCertificate, _) = try makeSelfSignedCertificate()
            let otherDER = try exportCertificateDER(otherCertificate)
            X509_free(otherCertificate)

            let sodContent = try SODParser.parse(sodData)
            let result = SODParser.verifyPassiveAuthentication(
                sodContent: sodContent,
                rawDataGroups: [.dg1: rawDG1],
                trustAnchorsDER: [otherDER]
            )

            #expect(result.allHashesValid)
            #expect(result.cmsSignatureValid == true)
            #expect(result.trustChainValid == false)
            #expect(result.status == .trustChainInvalid)
        }

        private func makeSignedSOD(
            rawDataGroups: [DataGroupId: Data],
            returnSignerDER _: Bool = false,
            eContentTypeOID: String = "2.23.136.1.1.1",
            keyUsage: String? = nil
        ) throws -> (Data, Data) {
            let ldsSecurityObject = buildLDSSecurityObject(rawDataGroups: rawDataGroups)
            let (certificate, privateKey) = try makeSelfSignedCertificate(keyUsage: keyUsage)
            let signerDER = try exportCertificateDER(certificate)
            defer {
                X509_free(certificate)
                EVP_PKEY_free(privateKey)
            }

            guard let input = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("BIO_new failed")
            }
            defer { BIO_free(input) }

            let writeCount = ldsSecurityObject.withUnsafeBytes { ptr in
                BIO_write(input, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(ldsSecurityObject.count))
            }
            guard writeCount == ldsSecurityObject.count else {
                throw NFCError.cryptoError("BIO_write failed for LDS Security Object")
            }

            let flags = UInt32(CMS_BINARY | CMS_PARTIAL)
            guard let cms = CMS_sign(certificate, privateKey, nil, input, flags) else {
                throw NFCError.cryptoError("CMS_sign failed")
            }
            defer { CMS_ContentInfo_free(cms) }

            let oid = eContentTypeOID.withCString { OBJ_txt2obj($0, 1) }
            guard let oid else {
                throw NFCError.cryptoError("OBJ_txt2obj failed")
            }
            defer { ASN1_OBJECT_free(oid) }

            guard CMS_set1_eContentType(cms, oid) == 1 else {
                throw NFCError.cryptoError("CMS_set1_eContentType failed")
            }

            guard CMS_final(cms, input, nil, UInt32(CMS_BINARY)) == 1 else {
                throw NFCError.cryptoError("CMS_final failed")
            }

            guard let output = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("BIO_new failed for output")
            }
            defer { BIO_free(output) }

            guard i2d_CMS_bio(output, cms) == 1 else {
                throw NFCError.cryptoError("i2d_CMS_bio failed")
            }

            let length = Int(BIO_ctrl(output, BIO_CTRL_PENDING, 0, nil))
            var cmsDER = Data(repeating: 0x00, count: length)
            _ = cmsDER.withUnsafeMutableBytes { ptr in
                BIO_read(output, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(length))
            }

            return (ASN1Parser.encodeTLV(tag: 0x77, value: cmsDER), signerDER)
        }

        private func buildLDSSecurityObject(rawDataGroups: [DataGroupId: Data]) -> Data {
            let sha256OID = ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.1")
            let version = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x00]))
            let hashAlgorithm = ASN1Parser.encodeTLV(tag: 0x30, value:
                ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID))

            let dgHashes = rawDataGroups.keys.sorted(by: { $0.rawValue < $1.rawValue }).reduce(into: Data()) { result, dgId in
                guard let rawData = rawDataGroups[dgId] else { return }
                guard let dgNumber = dataGroupNumber(for: dgId) else { return }
                let dgHash = ASN1Parser.encodeTLV(tag: 0x30, value:
                    ASN1Parser.encodeTLV(tag: 0x02, value: Data([dgNumber])) +
                        ASN1Parser.encodeTLV(tag: 0x04, value: HashUtils.sha256(rawData)))
                result.append(dgHash)
            }

            return ASN1Parser.encodeTLV(tag: 0x30, value: version + hashAlgorithm + dgHashes)
        }

        private func dataGroupNumber(for dgId: DataGroupId) -> UInt8? {
            switch dgId {
            case .dg1: 1
            case .dg2: 2
            case .dg3: 3
            case .dg4: 4
            case .dg5: 5
            case .dg6: 6
            case .dg7: 7
            case .dg8: 8
            case .dg9: 9
            case .dg10: 10
            case .dg11: 11
            case .dg12: 12
            case .dg13: 13
            case .dg14: 14
            case .dg15: 15
            case .dg16: 16
            case .com, .sod: nil
            }
        }

        private func makeSelfSignedCertificate(keyUsage: String? = nil) throws -> (OpaquePointer, OpaquePointer) {
            guard let keygenContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil) else {
                throw NFCError.cryptoError("Failed to allocate RSA keygen context")
            }
            defer { EVP_PKEY_CTX_free(keygenContext) }

            guard EVP_PKEY_keygen_init(keygenContext) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_keygen_init failed")
            }

            guard EVP_PKEY_CTX_set_rsa_keygen_bits(keygenContext, 1024) == 1 else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_set_rsa_keygen_bits failed")
            }

            var generatedKey: OpaquePointer?
            guard EVP_PKEY_keygen(keygenContext, &generatedKey) == 1, let privateKey = generatedKey else {
                throw NFCError.cryptoError("EVP_PKEY_keygen failed")
            }

            guard let certificate = X509_new() else {
                EVP_PKEY_free(privateKey)
                throw NFCError.cryptoError("Failed to allocate X509/EVP state")
            }

            guard X509_set_version(certificate, 2) == 1,
                  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1,
                  X509_gmtime_adj(X509_getm_notBefore(certificate), 0) != nil,
                  X509_gmtime_adj(X509_getm_notAfter(certificate), 60 * 60 * 24) != nil,
                  X509_set_pubkey(certificate, privateKey) == 1
            else {
                EVP_PKEY_free(privateKey)
                X509_free(certificate)
                throw NFCError.cryptoError("Failed to initialize certificate fields")
            }

            guard let subject = X509_get_subject_name(certificate) else {
                EVP_PKEY_free(privateKey)
                X509_free(certificate)
                throw NFCError.cryptoError("X509_get_subject_name failed")
            }

            let commonName = Array("CoreExtendedNFC Test DSC".utf8)
            let addNameResult = commonName.withUnsafeBufferPointer { ptr in
                X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, ptr.baseAddress, Int32(commonName.count), -1, 0)
            }
            if let keyUsage {
                guard let extensionValue = keyUsage.withCString({ X509V3_EXT_conf_nid(nil, nil, NID_key_usage, $0) }) else {
                    EVP_PKEY_free(privateKey)
                    X509_free(certificate)
                    throw NFCError.cryptoError("X509V3_EXT_conf_nid failed")
                }
                defer { X509_EXTENSION_free(extensionValue) }
                guard X509_add_ext(certificate, extensionValue, -1) == 1 else {
                    EVP_PKEY_free(privateKey)
                    X509_free(certificate)
                    throw NFCError.cryptoError("X509_add_ext failed")
                }
            }

            guard addNameResult == 1,
                  X509_set_issuer_name(certificate, subject) == 1,
                  X509_sign(certificate, privateKey, EVP_sha256()) > 0
            else {
                EVP_PKEY_free(privateKey)
                X509_free(certificate)
                throw NFCError.cryptoError("Failed to self-sign certificate")
            }

            return (certificate, privateKey)
        }

        private func exportCertificateDER(_ certificate: OpaquePointer) throws -> Data {
            guard let output = BIO_new(BIO_s_mem()) else {
                throw NFCError.cryptoError("BIO_new failed for certificate export")
            }
            defer { BIO_free(output) }

            guard i2d_X509_bio(output, certificate) == 1 else {
                throw NFCError.cryptoError("i2d_X509_bio failed")
            }

            let length = Int(BIO_ctrl(output, BIO_CTRL_PENDING, 0, nil))
            var der = Data(repeating: 0x00, count: length)
            _ = der.withUnsafeMutableBytes { ptr in
                BIO_read(output, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(length))
            }
            return der
        }
    #endif
}
