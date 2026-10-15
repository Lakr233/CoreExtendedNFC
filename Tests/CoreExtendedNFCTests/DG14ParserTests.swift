// DG14 SecurityInfo parser test suite.
//
// ## References
// - BSI TR-03110 Part 3, Appendix A.6: SecurityInfo OID assignments
//   https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html
// - BSI TR-03110 Part 3, Section A.6.1: PACEInfo (0.4.0.127.0.7.2.2.4.*)
// - BSI TR-03110 Part 3, Section A.6.2: ChipAuthenticationInfo (0.4.0.127.0.7.2.2.3.*)
// - BSI TR-03110 Part 3, Section A.6.3: ChipAuthenticationPublicKeyInfo (id-PK: 0.4.0.127.0.7.2.2.1.*)
// - BSI TR-03110 Part 3, Section A.6.4: TerminalAuthenticationInfo (id-TA: 0.4.0.127.0.7.2.2.2.*)
// - ICAO Doc 9303 Part 11, Section 9.2: Active Authentication OID 2.23.136.1.1.5 (id-AA)
// - OID Registry: https://oid-base.com/get/0.4.0.127.0.7.2.2
// - Bouncy Castle EACObjectIdentifiers javadoc:
//   https://downloads.bouncycastle.org/java/docs/bcutil-jdk15to18-javadoc/org/bouncycastle/asn1/eac/EACObjectIdentifiers.html
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DG14ParserTests {
    // MARK: - Helper: Build a SecurityInfo SEQUENCE node

    /// Build a DG14 containing one or more SecurityInfo SEQUENCE nodes.
    private func buildDG14(sequences: [Data]) -> Data {
        var setContent = Data()
        for seq in sequences {
            setContent.append(seq)
        }
        let setNode = ASN1Parser.encodeTLV(tag: 0x31, value: setContent)
        return ASN1Parser.encodeTLV(tag: 0x6E, value: setNode)
    }

    /// Build a SEQUENCE { OID, version [, optional] } node.
    private func buildInfoSequence(oid: String, version: Int, optional: Data? = nil) -> Data {
        let oidEncoded = ChipAuthenticationHandler.encodeOID(oid)
        var content = ASN1Parser.encodeTLV(tag: 0x06, value: oidEncoded)
        content.append(ASN1Parser.encodeTLV(tag: 0x02, value: encodeIntegerValue(version)))
        if let opt = optional {
            content.append(opt)
        }
        return ASN1Parser.encodeTLV(tag: 0x30, value: content)
    }

    /// Build a ChipAuthenticationPublicKeyInfo SEQUENCE with id-PK-ECDH OID.
    private func buildCAPubKeySequence(oid: String, keyID: Int? = nil) -> Data {
        let oidEncoded = ChipAuthenticationHandler.encodeOID(oid)
        var content = ASN1Parser.encodeTLV(tag: 0x06, value: oidEncoded)

        // SubjectPublicKeyInfo SEQUENCE (minimal: AlgId + BIT STRING)
        let ecOID = ChipAuthenticationHandler.encodeOID("1.2.840.10045.2.1")
        let curveOID = ChipAuthenticationHandler.encodeOID("1.2.840.10045.3.1.7")
        let algId = ASN1Parser.encodeTLV(tag: 0x30, value:
            ASN1Parser.encodeTLV(tag: 0x06, value: ecOID) +
                ASN1Parser.encodeTLV(tag: 0x06, value: curveOID))
        let ecPoint = Data([0x04]) + Data(repeating: 0xAA, count: 32) + Data(repeating: 0xBB, count: 32)
        let bitString = ASN1Parser.encodeTLV(tag: 0x03, value: Data([0x00]) + ecPoint)
        let spki = ASN1Parser.encodeTLV(tag: 0x30, value: algId + bitString)
        content.append(spki)

        if let kid = keyID {
            content.append(ASN1Parser.encodeTLV(tag: 0x02, value: encodeIntegerValue(kid)))
        }
        return ASN1Parser.encodeTLV(tag: 0x30, value: content)
    }

    private func encodeIntegerValue(_ value: Int) -> Data {
        if value <= 0x7F {
            return Data([UInt8(value)])
        } else if value <= 0x7FFF {
            return Data([UInt8(value >> 8), UInt8(value & 0xFF)])
        }
        return Data([UInt8(value >> 16), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
    }

    // MARK: - id-PK-DH / id-PK-ECDH Classification

    @Test
    func `id-PK-ECDH (0.4.0.127.0.7.2.2.1.2) classified as ChipAuthenticationPublicKeyInfo`() throws {
        let dg14 = buildDG14(sequences: [
            buildCAPubKeySequence(oid: "0.4.0.127.0.7.2.2.1.2"),
        ])
        let result = try DG14Parser.parse(dg14)
        #expect(result.chipAuthPublicKeyInfos.count == 1)
        #expect(result.chipAuthPublicKeyInfos[0].protocolOID == "0.4.0.127.0.7.2.2.1.2")
        #expect(!result.chipAuthPublicKeyInfos[0].subjectPublicKey.isEmpty)
        // Should NOT appear in any other bucket
        #expect(result.activeAuthInfos.isEmpty)
        #expect(result.chipAuthInfos.isEmpty)
        #expect(result.terminalAuthInfos.isEmpty)
    }

    @Test
    func `id-PK-DH (0.4.0.127.0.7.2.2.1.1) classified as ChipAuthenticationPublicKeyInfo`() throws {
        let dg14 = buildDG14(sequences: [
            buildCAPubKeySequence(oid: "0.4.0.127.0.7.2.2.1.1"),
        ])
        let result = try DG14Parser.parse(dg14)
        #expect(result.chipAuthPublicKeyInfos.count == 1)
        #expect(result.chipAuthPublicKeyInfos[0].protocolOID == "0.4.0.127.0.7.2.2.1.1")
    }

    @Test
    func `id-PK-ECDH with keyID is preserved`() throws {
        let dg14 = buildDG14(sequences: [
            buildCAPubKeySequence(oid: "0.4.0.127.0.7.2.2.1.2", keyID: 1),
        ])
        let result = try DG14Parser.parse(dg14)
        #expect(result.chipAuthPublicKeyInfos.count == 1)
        #expect(result.chipAuthPublicKeyInfos[0].keyID == 1)
    }

    @Test
    func `SubjectPublicKeyInfo stored as full DER (starts with 0x30)`() throws {
        let dg14 = buildDG14(sequences: [
            buildCAPubKeySequence(oid: "0.4.0.127.0.7.2.2.1.2"),
        ])
        let result = try DG14Parser.parse(dg14)
        let spki = result.chipAuthPublicKeyInfos[0].subjectPublicKey
        // Full DER should start with SEQUENCE tag 0x30
        #expect(!spki.isEmpty)
        #expect(spki[0] == 0x30, "SubjectPublicKeyInfo should start with SEQUENCE tag 0x30, got \(String(format: "0x%02X", spki[0]))")
    }

    // MARK: - Terminal Authentication NOT classified as Active Authentication

    @Test
    func `TA OIDs (0.4.0.127.0.7.2.2.2.*) classified as Terminal Authentication, NOT AA`() throws {
        let taOIDs = [
            "0.4.0.127.0.7.2.2.2.1.1", // id-TA-RSA-v1-5-SHA-1
            "0.4.0.127.0.7.2.2.2.1.2", // id-TA-RSA-v1-5-SHA-256
            "0.4.0.127.0.7.2.2.2.2.1", // id-TA-ECDSA-SHA-1
            "0.4.0.127.0.7.2.2.2.2.2", // id-TA-ECDSA-SHA-224
            "0.4.0.127.0.7.2.2.2.2.3", // id-TA-ECDSA-SHA-256
            "0.4.0.127.0.7.2.2.2.2.4", // id-TA-ECDSA-SHA-384
            "0.4.0.127.0.7.2.2.2.2.5", // id-TA-ECDSA-SHA-512
        ]

        for taOID in taOIDs {
            let dg14 = buildDG14(sequences: [
                buildInfoSequence(oid: taOID, version: 1),
            ])
            let result = try DG14Parser.parse(dg14)
            #expect(result.activeAuthInfos.isEmpty,
                    "TA OID \(taOID) should NOT be classified as Active Authentication")
            #expect(result.terminalAuthInfos.count == 1,
                    "TA OID \(taOID) should be classified as Terminal Authentication")
        }
    }

    // MARK: - Active Authentication — only id-AA (2.23.136.1.1.5)

    @Test
    func `Only id-AA (2.23.136.1.1.5) classified as Active Authentication`() throws {
        let dg14 = buildDG14(sequences: [
            buildInfoSequence(oid: "2.23.136.1.1.5", version: 1),
        ])
        let result = try DG14Parser.parse(dg14)
        #expect(result.activeAuthInfos.count == 1)
        #expect(result.activeAuthInfos[0].protocolOID == "2.23.136.1.1.5")
        #expect(result.activeAuthInfos[0].securityProtocol == .aaRSA)
    }

    @Test
    func `AA with signature algorithm OID`() throws {
        // id-AA with ecdsa-plain-SHA256 signature algorithm
        let sigAlgOID = ChipAuthenticationHandler.encodeOID("0.4.0.127.0.7.1.1.4.1.3")
        let oidEncoded = ChipAuthenticationHandler.encodeOID("2.23.136.1.1.5")
        var content = ASN1Parser.encodeTLV(tag: 0x06, value: oidEncoded)
        content.append(ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x01])))
        content.append(ASN1Parser.encodeTLV(tag: 0x06, value: sigAlgOID))
        let seq = ASN1Parser.encodeTLV(tag: 0x30, value: content)

        let dg14 = buildDG14(sequences: [seq])
        let result = try DG14Parser.parse(dg14)
        #expect(result.activeAuthInfos.count == 1)
        #expect(result.activeAuthInfos[0].signatureAlgorithmOID == "0.4.0.127.0.7.1.1.4.1.3")
    }

    // MARK: - Mixed DG14: PACE + CA + CA Public Key + AA + TA

    @Test
    func `Mixed DG14 with all SecurityInfo types correctly classified`() throws {
        let dg14 = buildDG14(sequences: [
            // PACE-ECDH-GM-AES-128
            buildInfoSequence(oid: "0.4.0.127.0.7.2.2.4.2.2", version: 2,
                              optional: ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x0D]))),
            // CA-ECDH-AES-128
            buildInfoSequence(oid: "0.4.0.127.0.7.2.2.3.2.2", version: 1),
            // id-PK-ECDH (CA public key)
            buildCAPubKeySequence(oid: "0.4.0.127.0.7.2.2.1.2"),
            // id-AA
            buildInfoSequence(oid: "2.23.136.1.1.5", version: 1),
            // id-TA-ECDSA-SHA-256
            buildInfoSequence(oid: "0.4.0.127.0.7.2.2.2.2.2", version: 1),
        ])

        let result = try DG14Parser.parse(dg14)

        // PACE
        #expect(result.paceInfos.count == 1)
        #expect(result.paceInfos[0].securityProtocol == .paceECDHGMAESCBCCMAC128)
        #expect(result.paceInfos[0].parameterID == 13) // BrainpoolP256r1

        // CA
        #expect(result.chipAuthInfos.count == 1)
        #expect(result.chipAuthInfos[0].securityProtocol == .caECDHAESCBCCMAC128)

        // CA Public Key
        #expect(result.chipAuthPublicKeyInfos.count == 1)
        #expect(result.chipAuthPublicKeyInfos[0].protocolOID == "0.4.0.127.0.7.2.2.1.2")

        // AA
        #expect(result.activeAuthInfos.count == 1)
        #expect(result.activeAuthInfos[0].protocolOID == "2.23.136.1.1.5")

        // TA
        #expect(result.terminalAuthInfos.count == 1)
        #expect(result.terminalAuthInfos[0].protocolOID == "0.4.0.127.0.7.2.2.2.2.2")
    }

    // MARK: - SecurityProtocol enum properties

    @Test
    func `SecurityProtocol id-PK properties`() {
        #expect(SecurityProtocol.pkDH.isChipAuthenticationPublicKey)
        #expect(SecurityProtocol.pkECDH.isChipAuthenticationPublicKey)
        #expect(!SecurityProtocol.pkDH.isPACE)
        #expect(!SecurityProtocol.pkDH.isChipAuthentication)
        #expect(!SecurityProtocol.pkDH.isActiveAuthentication)
    }

    @Test
    func `SecurityProtocol TA properties`() {
        #expect(SecurityProtocol.taRSAv15SHA1.isTerminalAuthentication)
        #expect(SecurityProtocol.taECDSASHA256.isTerminalAuthentication)
        #expect(!SecurityProtocol.taRSAv15SHA1.isActiveAuthentication)
        #expect(!SecurityProtocol.taECDSASHA256.isPACE)
    }

    @Test
    func `SecurityProtocol AA properties`() {
        #expect(SecurityProtocol.aaRSA.isActiveAuthentication)
        #expect(!SecurityProtocol.aaRSA.isTerminalAuthentication)
        #expect(!SecurityProtocol.aaRSA.isPACE)
        #expect(!SecurityProtocol.aaRSA.isChipAuthentication)
    }

    // MARK: - Edge Cases

    @Test
    func `Unknown OID is silently ignored (not classified into any bucket)`() throws {
        let dg14 = buildDG14(sequences: [
            buildInfoSequence(oid: "1.2.3.4.5.6.7.8.9", version: 1),
        ])
        let result = try DG14Parser.parse(dg14)
        #expect(result.paceInfos.isEmpty)
        #expect(result.chipAuthInfos.isEmpty)
        #expect(result.chipAuthPublicKeyInfos.isEmpty)
        #expect(result.activeAuthInfos.isEmpty)
        #expect(result.terminalAuthInfos.isEmpty)
    }

    @Test
    func `All 8 CA OIDs correctly classified`() throws {
        let caOIDs = [
            "0.4.0.127.0.7.2.2.3.1.1", // DH-3DES
            "0.4.0.127.0.7.2.2.3.1.2", // DH-AES-128
            "0.4.0.127.0.7.2.2.3.1.3", // DH-AES-192
            "0.4.0.127.0.7.2.2.3.1.4", // DH-AES-256
            "0.4.0.127.0.7.2.2.3.2.1", // ECDH-3DES
            "0.4.0.127.0.7.2.2.3.2.2", // ECDH-AES-128
            "0.4.0.127.0.7.2.2.3.2.3", // ECDH-AES-192
            "0.4.0.127.0.7.2.2.3.2.4", // ECDH-AES-256
        ]

        for caOID in caOIDs {
            let dg14 = buildDG14(sequences: [
                buildInfoSequence(oid: caOID, version: 1),
            ])
            let result = try DG14Parser.parse(dg14)
            #expect(result.chipAuthInfos.count == 1,
                    "CA OID \(caOID) should be classified as ChipAuthenticationInfo")
            #expect(result.activeAuthInfos.isEmpty,
                    "CA OID \(caOID) should NOT be classified as Active Authentication")
        }
    }
}
