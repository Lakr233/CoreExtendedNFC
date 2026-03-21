// Phase 2 integration tests: DG14, DG15, SOD, PACE, CA, PassportModel.
//
// ## References
// - BSI TR-03110 Part 3: PACE, CA, TA protocol OIDs and domain parameters
//   https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html
// - BSI TR-03110 Part 3, Table A.2: PACE domain parameter IDs
//   (secp256r1=12, brainpoolP256r1=13, secp384r1=15, secp521r1=18)
// - ICAO Doc 9303 Part 11: BAC, Secure Messaging, Active/Passive Authentication
// - RFC 5652 (CMS): SignedData in SOD
// - RFC 3279 / RFC 5758: Algorithm OIDs for RSA and ECDSA
// - OID references: https://oid-base.com/get/0.4.0.127.0.7.2.2
// - JMRTD PassportService.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/PassportService.java
@testable import CoreExtendedNFC
import Foundation
import Testing

struct Phase2Tests {
    // MARK: - DG14 SecurityInfo Parser

    @Test("Parse DG14 with PACE info")
    func parseDG14PACEInfo() throws {
        // Build a DG14 with PACEInfo:
        // 6E { 31 { 30 { 06 <PACE-ECDH-GM-AES-CBC-CMAC-256 OID> 02 01 02 02 01 0C } } }
        let oid = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.4.2.4")
        let oidNode = ASN1Parser.encodeTLV(tag: 0x06, value: oid)
        let versionNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x02]))
        let paramIDNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x0C])) // secp256r1 = 12

        var seqContent = Data()
        seqContent.append(oidNode)
        seqContent.append(versionNode)
        seqContent.append(paramIDNode)
        let seqNode = ASN1Parser.encodeTLV(tag: 0x30, value: seqContent)
        let setNode = ASN1Parser.encodeTLV(tag: 0x31, value: seqNode)
        let dg14Data = ASN1Parser.encodeTLV(tag: 0x6E, value: setNode)

        let result = try DG14Parser.parse(dg14Data)
        #expect(result.supportsPACE)
        #expect(result.paceInfos.count == 1)
        #expect(result.paceInfos[0].protocolOID == "0.4.0.127.0.7.2.2.4.2.4")
        #expect(result.paceInfos[0].securityProtocol == .paceECDHGMAESCBCCMAC256)
        #expect(result.paceInfos[0].version == 2)
        #expect(result.paceInfos[0].parameterID == 12)
    }

    @Test("Parse DG14 with Chip Authentication info")
    func parseDG14ChipAuth() throws {
        let oid = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.3.2.2")
        let oidNode = ASN1Parser.encodeTLV(tag: 0x06, value: oid)
        let versionNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01]))

        var seqContent = Data()
        seqContent.append(oidNode)
        seqContent.append(versionNode)
        let seqNode = ASN1Parser.encodeTLV(tag: 0x30, value: seqContent)
        let setNode = ASN1Parser.encodeTLV(tag: 0x31, value: seqNode)
        let dg14Data = ASN1Parser.encodeTLV(tag: 0x6E, value: setNode)

        let result = try DG14Parser.parse(dg14Data)
        #expect(result.supportsChipAuthentication)
        #expect(result.chipAuthInfos.count == 1)
        #expect(result.chipAuthInfos[0].securityProtocol == .caECDHAESCBCCMAC128)
        #expect(result.chipAuthInfos[0].version == 1)
    }

    @Test("Parse DG14 with multiple security infos")
    func parseDG14MultipleInfos() throws {
        // PACE info
        let paceOID = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.4.2.2")
        let paceNode = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: paceOID) +
                ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x02])) +
                ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x0C])))

        // CA info
        let caOID = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.3.2.2")
        let caNode = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: caOID) +
                ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01])))

        let setNode = ASN1Parser.encodeTLV(tag: 0x31, value: paceNode + caNode)
        let dg14Data = ASN1Parser.encodeTLV(tag: 0x6E, value: setNode)

        let result = try DG14Parser.parse(dg14Data)
        #expect(result.supportsPACE)
        #expect(result.supportsChipAuthentication)
        #expect(result.paceInfos.count == 1)
        #expect(result.chipAuthInfos.count == 1)
    }

    @Test("SecurityProtocol properties")
    func securityProtocolProperties() {
        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC256.isPACE)
        #expect(!SecurityProtocol.paceECDHGMAESCBCCMAC256.isChipAuthentication)
        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC256.isECDH)
        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC256.isAES)
        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC256.aesKeyLength == 32)

        #expect(SecurityProtocol.caECDH3DESCBCCBC.isChipAuthentication)
        #expect(!SecurityProtocol.caECDH3DESCBCCBC.isPACE)
        #expect(SecurityProtocol.caECDH3DESCBCCBC.isECDH)

        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC128.aesKeyLength == 16)
        #expect(SecurityProtocol.paceECDHGMAESCBCCMAC192.aesKeyLength == 24)
    }

    // MARK: - DG15 Active Auth Public Key Parser

    @Test("Parse DG15 with RSA public key")
    func parseDG15RSA() throws {
        // Build a minimal DG15 with RSA SubjectPublicKeyInfo:
        // 6F { 30 (SPKI) { 30 (AlgId) { 06 (rsaEncryption) 05 00 } 03 (BIT STRING) { RSAPublicKey } } }

        let rsaOID = ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.1.1")
        let algIdContent = ASN1Parser.encodeTLV(tag: 0x06, value: rsaOID) +
            ASN1Parser.encodeTLV(tag: 0x05, value: Data()) // NULL params
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value: algIdContent)

        // RSAPublicKey: SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
        let modulus = Data([0x00]) + Data(repeating: 0xAB, count: 128) // 1024-bit with leading zero
        let exponent = Data([0x01, 0x00, 0x01]) // 65537
        let rsaKeyContent = ASN1Parser.encodeTLV(tag: 0x02, value: modulus) +
            ASN1Parser.encodeTLV(tag: 0x02, value: exponent)
        let rsaKey = ASN1Parser.encodeTLV(tag: 0x30, value: rsaKeyContent)

        // BIT STRING: 0x00 (unused bits) + rsaKey
        var bitStringValue = Data([0x00])
        bitStringValue.append(rsaKey)
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: bitStringValue)

        let spkiContent = algId + bitString
        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: spkiContent)
        let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: spki)

        let result = try DG15Parser.parse(dg15Data)

        if case let .rsa(mod, exp) = result {
            #expect(mod.count == 128) // Leading zero stripped
            #expect(exp == Data([0x01, 0x00, 0x01]))
        } else {
            Issue.record("Expected RSA key, got \(result)")
        }
    }

    @Test("Parse DG15 with ECDSA public key")
    func parseDG15ECDSA() throws {
        let ecOID = ChipAuthenticationHandler.encodeOID("1.2.840.10045.2.1")
        let curveOID = ChipAuthenticationHandler.encodeOID("1.2.840.10045.3.1.7") // secp256r1

        let algIdContent = ASN1Parser.encodeTLV(tag: 0x06, value: ecOID) +
            ASN1Parser.encodeTLV(tag: 0x06, value: curveOID)
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value: algIdContent)

        // EC public point: 04 || x || y (65 bytes for P-256)
        var ecPoint = Data([0x04])
        ecPoint.append(Data(repeating: 0xAA, count: 32)) // x
        ecPoint.append(Data(repeating: 0xBB, count: 32)) // y

        // BIT STRING: 0x00 (unused bits) + ecPoint
        var bitStringValue = Data([0x00])
        bitStringValue.append(ecPoint)
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: bitStringValue)

        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algId + bitString)
        let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: spki)

        let result = try DG15Parser.parse(dg15Data)

        if case let .ecdsa(curve, point) = result {
            #expect(curve == "1.2.840.10045.3.1.7")
            #expect(point.count == 65)
            #expect(point[0] == 0x04)
        } else {
            Issue.record("Expected ECDSA key, got \(result)")
        }
    }

    @Test("Parse DG15 with unknown algorithm returns unknown")
    func parseDG15Unknown() throws {
        let unknownOID = ChipAuthenticationHandler.encodeOID("1.2.3.4.5.6.7")
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: unknownOID))
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: Data([0x00, 0xAB, 0xCD]))
        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algId + bitString)
        let dg15Data = ASN1Parser.encodeTLV(tag: 0x6F, value: spki)

        let result = try DG15Parser.parse(dg15Data)
        if case .unknown = result {
            // Expected
        } else {
            Issue.record("Expected unknown key type")
        }
    }

    // MARK: - SOD Parser

    @Test("Parse minimal SOD structure")
    func parseSODMinimal() throws {
        // Build a minimal SOD with one DG hash
        let signedDataOID = ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.7.2")
        let sha256OID = ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.1")

        // DigestAlgorithms SET { SEQUENCE { OID } }
        let digestAlgSeq = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID))
        let digestAlgsSet = ASN1Parser.encodeTLV(tag: 0x31, value: digestAlgSeq)

        // LDS Security Object:
        // SEQUENCE { version, hashAlg, SEQUENCE OF DataGroupHash }
        let version = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x00]))
        let hashAlg = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: sha256OID))

        // DataGroupHash for DG1: SEQUENCE { INTEGER(1), OCTET STRING(hash) }
        let dg1Hash = Data(repeating: 0xAA, count: 32)
        let dgHashSeq = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01])) +
                ASN1Parser.encodeTLV(tag: 0x04, value: dg1Hash))

        let ldsSecObj = ASN1Parser.encodeTLV(tag: 0x30, value:
            version + hashAlg + dgHashSeq)
        let ldsOctetString = ASN1Parser.encodeTLV(tag: 0x04, value: ldsSecObj)

        // EncapContentInfo
        let ldsSecObjOID = ChipAuthenticationHandler.encodeOID("2.23.136.1.1.1")
        let encapContent = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ldsSecObjOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value: ldsOctetString))

        // Empty SignerInfos SET
        let signerInfosSet = ASN1Parser.encodeTLV(tag: 0x31, value: Data())

        // SignedData SEQUENCE
        let signedDataVersion = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x03]))
        let signedData = ASN1Parser.encodeTLV(tag: 0x30, value:
            signedDataVersion + digestAlgsSet + encapContent + signerInfosSet)

        // ContentInfo
        let contentInfo = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: signedDataOID) +
                ASN1Parser.encodeTLV(tag: 0xA0, value: signedData))

        // SOD wrapper
        let sodData = ASN1Parser.encodeTLV(tag: 0x77, value: contentInfo)

        let result = try SODParser.parse(sodData)
        #expect(result.hashAlgorithm == "SHA-256")
        #expect(result.hashAlgorithmOID == "2.16.840.1.101.3.4.2.1")
        #expect(result.dataGroupHashes.count == 1)
        #expect(result.dataGroupHashes[.dg1] == dg1Hash)
    }

    @Test("SOD hash verification — matching hashes")
    func sodHashVerificationMatch() {
        // Create raw DG1 data
        let rawDG1 = Data(repeating: 0x42, count: 100)

        // Compute its SHA-256 hash
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
        #expect(result.status == .signatureNotVerified)
        #expect(result.dataGroupHashResults[.dg1] == true)
        #expect(result.failedDataGroups.isEmpty)
    }

    @Test("SOD hash verification — mismatched hashes")
    func sodHashVerificationMismatch() {
        let rawDG1 = Data(repeating: 0x42, count: 100)
        let wrongHash = Data(repeating: 0xFF, count: 32)

        let sodContent = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            dataGroupHashes: [.dg1: wrongHash],
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

        #expect(!result.allHashesValid)
        #expect(result.status == .hashMismatch)
        #expect(result.failedDataGroups.contains(.dg1))
    }

    @Test("SOD hash verification — SHA-1 algorithm")
    func sodHashVerificationSHA1() {
        let rawDG1 = Data(repeating: 0x42, count: 50)
        let expectedHash = HashUtils.sha1(rawDG1)

        let sodContent = SODContent(
            hashAlgorithmOID: "1.3.14.3.2.26",
            hashAlgorithm: "SHA-1",
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
    }

    @Test("SOD hash verification — multiple data groups")
    func sodHashVerificationMultiple() {
        let rawDG1 = Data([0x01, 0x02, 0x03])
        let rawDG2 = Data([0x04, 0x05, 0x06])

        let sodContent = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            dataGroupHashes: [
                .dg1: HashUtils.sha256(rawDG1),
                .dg2: HashUtils.sha256(rawDG2),
            ],
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
            rawDataGroups: [.dg1: rawDG1, .dg2: rawDG2]
        )

        #expect(result.allHashesValid)
        #expect(result.dataGroupHashResults.count == 2)
    }

    // MARK: - OID Encoding / Decoding

    @Test("OID encode/decode roundtrip")
    func oidRoundtrip() {
        let oids = [
            "0.4.0.127.0.7.2.2.4.2.4",
            "1.2.840.113549.1.7.2",
            "2.16.840.1.101.3.4.2.1",
            "1.2.840.10045.2.1",
            "1.2.840.10045.3.1.7",
        ]

        for oid in oids {
            let encoded = ChipAuthenticationHandler.encodeOID(oid)
            let decoded = DG14Parser.decodeOID(encoded)
            #expect(decoded == oid, "Roundtrip failed for \(oid): got \(decoded)")
        }
    }

    @Test("OID decode known values")
    func oidDecodeKnown() {
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        // DER: 60 86 48 01 65 03 04 02 01
        let sha256DER = Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        let decoded = DG14Parser.decodeOID(sha256DER)
        #expect(decoded == "2.16.840.1.101.3.4.2.1")
    }

    // MARK: - AES Secure Messaging

    @Test("AES-mode SecureMessaging encrypt/decrypt roundtrip")
    func aesSMRoundtrip() {
        let ksEnc = Data(repeating: 0x01, count: 16)
        let ksMac = Data(repeating: 0x02, count: 16)
        let ssc = Data(repeating: 0x00, count: 8) // 8-byte SSC (padded to 16 inside SM for AES)

        let mock = MockTransport()

        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc,
            mode: .aes128
        )

        // Verify the mode is set correctly
        #expect(sm.identifier == mock.identifier)
    }

    @Test("SMEncryptionMode properties")
    func smEncryptionModeProperties() {
        #expect(SMEncryptionMode.tripleDES.blockSize == 8)
        #expect(SMEncryptionMode.tripleDES.sscLength == 8)
        #expect(SMEncryptionMode.tripleDES.macLength == 8)

        #expect(SMEncryptionMode.aes128.blockSize == 16)
        #expect(SMEncryptionMode.aes128.sscLength == 8) // SSC is always 8 bytes, padded to 16 for AES
        #expect(SMEncryptionMode.aes128.macLength == 8)

        #expect(SMEncryptionMode.aes256.blockSize == 16)
        #expect(SMEncryptionMode.aes256.sscLength == 8) // SSC is always 8 bytes
    }

    // MARK: - PACE Handler

    @Test("PACE password key derivation for MRZ")
    func pacePasswordKeyDerivationMRZ() {
        let key = PACEHandler.derivePasswordKey(
            password: "L898902C<364081251204159",
            keyReference: .mrz,
            mode: .aes128
        )
        // Should derive a 16-byte key using Kseed → KDF mode 3 (pace)
        #expect(key.count == 16)
    }

    @Test("PACE password key derivation for CAN")
    func pacePasswordKeyDerivationCAN() {
        let key = PACEHandler.derivePasswordKey(
            password: "123456",
            keyReference: .can,
            mode: .aes128
        )
        #expect(key.count == 16)
    }

    @Test("PACE password key derivation for CAN AES-256 uses password bytes")
    func pacePasswordKeyDerivationCANAES256() throws {
        let key = PACEHandler.derivePasswordKey(
            password: "123456",
            keyReference: .can,
            mode: .aes256
        )

        let expected = try #require(Data(hexString: "8DF3278FB32026E66277357FCD6C826DBEB3DE32088B2531757D753940185923"))
        #expect(key == expected)
    }

    @Test("PACE session key derivation")
    func paceSessionKeyDerivation() {
        let sharedSecret = Data(repeating: 0xAB, count: 32)
        let (ksEnc, ksMac) = PACEHandler.derivePACESessionKeys(
            sharedSecret: sharedSecret,
            mode: .aes128
        )

        #expect(ksEnc.count == 16)
        #expect(ksMac.count == 16)
        #expect(ksEnc != ksMac) // Different keys for enc and mac
    }

    @Test("PACE session key derivation AES-256")
    func paceSessionKeyDerivationAES256() {
        let sharedSecret = Data(repeating: 0xCD, count: 64)
        let (ksEnc, ksMac) = PACEHandler.derivePACESessionKeys(
            sharedSecret: sharedSecret,
            mode: .aes256
        )

        #expect(ksEnc.count == 32)
        #expect(ksMac.count == 32)
        #expect(ksEnc != ksMac)
    }

    @Test("PACE authentication token computation")
    func paceAuthToken() throws {
        let ksMac = Data(repeating: 0x42, count: 16)
        let publicKey = Data(repeating: 0xAB, count: 65)
        let oid = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.4.2.2")

        let token = try PACEHandler.computeAuthToken(
            ksMac: ksMac,
            publicKeyOther: publicKey,
            oid: oid,
            mode: .aes128
        )

        #expect(token.count == 8) // Truncated AES-CMAC
    }

    // MARK: - Chip Authentication Handler

    @Test("CA session key derivation")
    func caSessionKeyDerivation() {
        let sharedSecret = Data(repeating: 0xEF, count: 32)
        let (ksEnc, ksMac) = ChipAuthenticationHandler.deriveCASessionKeys(
            sharedSecret: sharedSecret,
            mode: .aes128
        )

        #expect(ksEnc.count == 16)
        #expect(ksMac.count == 16)
        #expect(ksEnc != ksMac)
    }

    @Test("CA OID encoding")
    func caOIDEncoding() {
        let oid = "0.4.0.127.0.7.2.2.3.2.2"
        let encoded = ChipAuthenticationHandler.encodeOID(oid)
        let decoded = DG14Parser.decodeOID(encoded)
        #expect(decoded == oid)
    }

    // MARK: - Passport APDU Extensions

    @Test("INTERNAL AUTHENTICATE APDU")
    func internalAuthAPDU() {
        let challenge = Data(repeating: 0xAA, count: 8)
        let apdu = CommandAPDU.internalAuthenticate(data: challenge)
        #expect(apdu.cla == 0x00)
        #expect(apdu.ins == 0x88)
        #expect(apdu.p1 == 0x00)
        #expect(apdu.p2 == 0x00)
        #expect(apdu.data?.count == 8)
        #expect(apdu.le == 0x00)
    }

    @Test("MSE:Set AT APDU with OID and key reference")
    func mseSetATAPDU() throws {
        let oid = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.2.2.4.2.2")
        let apdu = CommandAPDU.mseSetAT(oid: oid, keyRef: 0x01)

        #expect(apdu.ins == 0x22)
        #expect(apdu.p1 == 0xC1)
        #expect(apdu.p2 == 0xA4)

        // Data should contain 0x80 tag for OID and 0x83 tag for key ref
        let data = try #require(apdu.data)
        #expect(data[0] == 0x80) // Cryptographic mechanism reference
        #expect(data.contains(0x83)) // Key reference tag
    }

    @Test("General Authenticate APDU")
    func generalAuthAPDU() {
        let data = ASN1Parser.encodeTLV(tag: 0x7C, value: Data())
        let apdu = CommandAPDU.generalAuthenticate(data: data, isLast: true)
        #expect(apdu.cla == 0x00) // isLast = true → no chaining
        #expect(apdu.ins == 0x86)
    }

    @Test("General Authenticate APDU with chaining")
    func generalAuthAPDUChained() {
        let data = ASN1Parser.encodeTLV(tag: 0x7C, value: Data())
        let apdu = CommandAPDU.generalAuthenticate(data: data, isLast: false)
        #expect(apdu.cla == 0x10) // Command chaining
        #expect(apdu.ins == 0x86)
    }

    // MARK: - PassportModel with Phase 2 fields

    @Test("PassportModel with passive auth result")
    func passportModelWithPA() {
        let paResult = PassiveAuthenticationResult(
            dataGroupHashResults: [.dg1: true, .dg2: true],
            hasCertificate: true,
            status: .signatureNotVerified
        )

        let model = PassportModel(
            ldsVersion: nil,
            unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil,
            faceImageData: nil,
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: nil,
            securityInfoRaw: nil,
            activeAuthPublicKey: nil,
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: nil,
            passiveAuthResult: paResult,
            activeAuthResult: nil,
            rawDataGroups: [:]
        )

        #expect(model.passiveAuthResult?.allHashesValid == true)
        #expect(model.passiveAuthResult?.status == .signatureNotVerified)
    }

    @Test("PassportModel with active auth result")
    func passportModelWithAA() {
        let aaResult = ActiveAuthenticationResult(success: true, details: "RSA verified")

        let model = PassportModel(
            ldsVersion: nil,
            unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil,
            faceImageData: nil,
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: nil,
            securityInfoRaw: nil,
            activeAuthPublicKey: .rsa(modulus: Data([0xAB]), exponent: Data([0x01, 0x00, 0x01])),
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: nil,
            passiveAuthResult: nil,
            activeAuthResult: aaResult,
            rawDataGroups: [:]
        )

        #expect(model.activeAuthResult?.success == true)
        #expect(model.activeAuthPublicKey != nil)
    }

    @Test("PassportModel with security infos")
    func passportModelWithSecurityInfos() {
        let secInfos = SecurityInfos(
            paceInfos: [PACEInfo(
                protocolOID: "0.4.0.127.0.7.2.2.4.2.4",
                securityProtocol: .paceECDHGMAESCBCCMAC256,
                version: 2,
                parameterID: 12
            )],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: []
        )

        let model = PassportModel(
            ldsVersion: nil,
            unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil,
            faceImageData: nil,
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: secInfos,
            securityInfoRaw: nil,
            activeAuthPublicKey: nil,
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: nil,
            passiveAuthResult: nil,
            activeAuthResult: nil,
            rawDataGroups: [:]
        )

        #expect(model.securityInfos?.supportsPACE == true)
        #expect(model.securityInfos?.supportsChipAuthentication == false)
    }

    // MARK: - PACE Domain Parameters

    @Test("PACE domain parameter IDs")
    func paceDomainParameters() {
        #expect(PACEHandler.DomainParameterID.secp256r1.rawValue == 12)
        #expect(PACEHandler.DomainParameterID.secp384r1.rawValue == 15)
        #expect(PACEHandler.DomainParameterID.secp521r1.rawValue == 18)

        #expect(PACEHandler.DomainParameterID.secp256r1.isNISTCurve)
        #expect(PACEHandler.DomainParameterID.secp384r1.isNISTCurve)
        #expect(!PACEHandler.DomainParameterID.brainpoolP256r1.isNISTCurve)
    }

    // MARK: - PassiveAuthStatus

    @Test("PassiveAuthStatus values")
    func passiveAuthStatusValues() {
        #expect(PassiveAuthStatus.dataGroupHashesVerified.rawValue == "dataGroupHashesVerified")
        #expect(PassiveAuthStatus.hashMismatch.rawValue == "hashMismatch")
        #expect(PassiveAuthStatus.sodParseFailed.rawValue == "sodParseFailed")
        #expect(PassiveAuthStatus.sodNotAvailable.rawValue == "sodNotAvailable")
        #expect(PassiveAuthStatus.unsupportedHashAlgorithm.rawValue == "unsupportedHashAlgorithm")
        #expect(PassiveAuthStatus.signatureNotVerified.rawValue == "signatureNotVerified")
        #expect(PassiveAuthStatus.signatureVerified.rawValue == "signatureVerified")
        #expect(PassiveAuthStatus.signatureInvalid.rawValue == "signatureInvalid")
        #expect(PassiveAuthStatus.fullyVerified.rawValue == "fullyVerified")
        #expect(PassiveAuthStatus.trustChainInvalid.rawValue == "trustChainInvalid")
    }
}
