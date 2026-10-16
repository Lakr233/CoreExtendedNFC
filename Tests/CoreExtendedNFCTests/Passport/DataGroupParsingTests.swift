// Data group parsing test suite (COM, DG1, DG2, MRZ, DataGroupId, PassportModel, APDU).
//
// ## References
// - ICAO Doc 9303 Part 10: LDS structure, data group file IDs and TLV tags
//   https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
// - ICAO Doc 9303 Part 10, Table 33: EF file identifiers (COM=011E, SOD=011D, DG1-16=0101-0110)
// - ICAO Doc 9303 Part 10, Section 4.7.2.1: EF.COM structure (tag 0x60)
//   - Tag 0x5F01: LDS version, Tag 0x5F36: Unicode version, Tag 0x5C: DG presence list
// - ICAO Doc 9303 Part 10, Section 4.7.2.2: DG1 structure (tag 0x61, inner 0x5F1F for MRZ)
// - ICAO Doc 9303 Part 10, Section 4.7.2.3: DG2 structure (tag 0x75, CBEFF biometric)
//   - ISO/IEC 19794-5 face image format, JPEG signature at FFD8FFE0
// - ICAO Doc 9303 Part 3: MRZ formats
//   https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
//   - TD1: 3×30=90 chars, TD2: 2×36=72 chars, TD3: 2×44=88 chars
//   - ICAO example: P<UTOERIKSSON<<ANNA<MARIA, doc L898902C<
// - ICAO Doc 9303 Part 10, Section 4.6.2: eMRTD AID = A0000002471001
// - ISO/IEC 7816-4: SELECT (A4), READ BINARY (B0), GET CHALLENGE (84),
//   MUTUAL AUTHENTICATE (82), INTERNAL AUTHENTICATE (88)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DataGroupParsingTests {
    // MARK: - COM (EF.COM)

    // ICAO 9303 Part 10, Section 4.7.2.1

    @Test
    func `Parse COM data group`() throws {
        // Construct COM TLV:
        // 60 <len>
        //   5F01 04 "0107"          (LDS version)
        //   5F36 06 "040000"        (Unicode version)
        //   5C 02 61 75             (DG list: DG1=0x61, DG2=0x75)
        var comData = Data()

        // LDS version
        let ldsVersion = Data("0107".utf8)
        var ldsNode = Data([0x5F, 0x01, UInt8(ldsVersion.count)])
        ldsNode.append(ldsVersion)

        // Unicode version
        let uniVersion = Data("040000".utf8)
        var uniNode = Data([0x5F, 0x36, UInt8(uniVersion.count)])
        uniNode.append(uniVersion)

        // DG list
        let dgList = Data([0x61, 0x75]) // DG1, DG2
        var dgNode = Data([0x5C, UInt8(dgList.count)])
        dgNode.append(dgList)

        // Assemble inner content
        var innerContent = Data()
        innerContent.append(ldsNode)
        innerContent.append(uniNode)
        innerContent.append(dgNode)

        // Wrap in 0x60 tag
        comData.append(0x60)
        comData.append(contentsOf: ASN1Parser.encodeLength(innerContent.count))
        comData.append(innerContent)

        let result = try DataGroupParser.parseCOM(comData)
        #expect(result.ldsVersion == "0107")
        #expect(result.unicodeVersion == "040000")
        #expect(result.dataGroups.count == 2)
        #expect(result.dataGroups.contains(.dg1))
        #expect(result.dataGroups.contains(.dg2))
    }

    // MARK: - DG1 (MRZ)

    @Test
    func `Parse DG1 with TD3 passport MRZ`() throws {
        // TD3 MRZ: 2 lines × 44 chars = 88 chars
        let mrzString = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
            "L898902C<3UTO6408125F1204159ZE184226B<<<<<10"

        let mrzData = Data(mrzString.utf8)

        // Build DG1 TLV: 61 <len> [5F1F <len> <MRZ>]
        var innerContent = Data([0x5F, 0x1F])
        innerContent.append(contentsOf: ASN1Parser.encodeLength(mrzData.count))
        innerContent.append(mrzData)

        var dg1Data = Data([0x61])
        dg1Data.append(contentsOf: ASN1Parser.encodeLength(innerContent.count))
        dg1Data.append(innerContent)

        let mrz = try DataGroupParser.parseDG1(dg1Data)
        #expect(mrz.format == .td3)
        #expect(mrz.documentCode == "P")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(mrz.documentNumber == "L898902C")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.dateOfBirth == "640812")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "120415")
    }

    @Test
    func `Parse DG1 with TD1 ID card MRZ`() throws {
        // TD1: 3 lines × 30 chars = 90 chars
        let mrzString = "I<UTOD231458907<<<<<<<<<<<<<<<" +
            "7408122F1204159UTO<<<<<<<<<<<6" +
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"

        let mrzData = Data(mrzString.utf8)
        var innerContent = Data([0x5F, 0x1F])
        innerContent.append(contentsOf: ASN1Parser.encodeLength(mrzData.count))
        innerContent.append(mrzData)

        var dg1Data = Data([0x61])
        dg1Data.append(contentsOf: ASN1Parser.encodeLength(innerContent.count))
        dg1Data.append(innerContent)

        let mrz = try DataGroupParser.parseDG1(dg1Data)
        #expect(mrz.format == .td1)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
    }

    @Test
    func `DG1 missing 0x61 wrapper throws error`() {
        // Wrong tag — 0x62 instead of 0x61
        let data = Data([0x62, 0x03, 0x5F, 0x1F, 0x00])
        #expect(throws: NFCError.self) {
            _ = try DataGroupParser.parseDG1(data)
        }
    }

    // MARK: - DG2 (Face Image)

    @Test
    func `Parse DG2 extracts JPEG image data`() throws {
        // Build a minimal DG2 with a JPEG signature embedded
        // 75 <len>
        //   7F61 <len>
        //     02 01 01                 (count = 1)
        //     7F60 <len>
        //       A1 02 00 00            (header)
        //       5F2E <len> [header bytes + FFD8 FFE0 ... image data]

        let jpegSignature = Data([0xFF, 0xD8, 0xFF, 0xE0])
        let imageContent = jpegSignature + Data(repeating: 0xAB, count: 20)

        // Prepend some ISO 19794-5 header bytes before JPEG
        let faceRecordHeader = Data(repeating: 0x00, count: 14) // dummy header
        var biometricContent = faceRecordHeader
        biometricContent.append(imageContent)

        // Tag 0x5F2E with biometric data
        var biometricNode = Data([0x5F, 0x2E])
        biometricNode.append(contentsOf: ASN1Parser.encodeLength(biometricContent.count))
        biometricNode.append(biometricContent)

        // Header template
        let headerNode = Data([0xA1, 0x02, 0x00, 0x00])

        // 7F60 template
        var template60Content = headerNode
        template60Content.append(biometricNode)
        var template60 = Data([0x7F, 0x60])
        template60.append(contentsOf: ASN1Parser.encodeLength(template60Content.count))
        template60.append(template60Content)

        // Count node
        let countNode = Data([0x02, 0x01, 0x01])

        // 7F61 group template
        var template61Content = countNode
        template61Content.append(template60)
        var template61 = Data([0x7F, 0x61])
        template61.append(contentsOf: ASN1Parser.encodeLength(template61Content.count))
        template61.append(template61Content)

        // 75 wrapper
        var dg2Data = Data([0x75])
        dg2Data.append(contentsOf: ASN1Parser.encodeLength(template61.count))
        dg2Data.append(template61)

        let result = try DataGroupParser.parseDG2(dg2Data)
        // Should find the JPEG starting at FFD8
        #expect(result[0] == 0xFF)
        #expect(result[1] == 0xD8)
        #expect(result.count == imageContent.count)
    }

    @Test
    func `DG2 missing 0x75 wrapper throws error`() {
        let data = Data([0x76, 0x00]) // Wrong tag
        #expect(throws: NFCError.self) {
            _ = try DataGroupParser.parseDG2(data)
        }
    }

    @Test
    func `Parse DG2 extracts JPEG2000 codestream from ISO 19794-5 face record`() throws {
        // Simulate a facial record beginning with the `FAC\0` header, followed by
        // an embedded JPEG2000 codestream (`FF4F FF51`).
        let faceRecordHeader = Data([
            0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00,
            0x00, 0x00, 0x50, 0x2E, 0x00, 0x01,
        ])
        let codestream = Data([0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F]) + Data(repeating: 0xAA, count: 16)
        let biometricContent = faceRecordHeader + codestream

        var biometricNode = Data([0x5F, 0x2E])
        biometricNode.append(contentsOf: ASN1Parser.encodeLength(biometricContent.count))
        biometricNode.append(biometricContent)

        let headerNode = Data([0xA1, 0x02, 0x00, 0x00])

        var template60Content = headerNode
        template60Content.append(biometricNode)
        var template60 = Data([0x7F, 0x60])
        template60.append(contentsOf: ASN1Parser.encodeLength(template60Content.count))
        template60.append(template60Content)

        let countNode = Data([0x02, 0x01, 0x01])

        var template61Content = countNode
        template61Content.append(template60)
        var template61 = Data([0x7F, 0x61])
        template61.append(contentsOf: ASN1Parser.encodeLength(template61Content.count))
        template61.append(template61Content)

        var dg2Data = Data([0x75])
        dg2Data.append(contentsOf: ASN1Parser.encodeLength(template61.count))
        dg2Data.append(template61)

        let result = try DataGroupParser.parseDG2(dg2Data)
        #expect(result.starts(with: [0xFF, 0x4F, 0xFF, 0x51]))
        #expect(result == codestream)
    }

    // MARK: - MRZ Parsing

    @Test
    func `MRZ TD3 format (passport)`() throws {
        let mrzString = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
            "L898902C<3UTO6408125F1204159ZE184226B<<<<<10"
        let mrz = try MRZData(mrzString: mrzString)

        #expect(mrz.format == .td3)
        #expect(mrz.documentCode == "P")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(mrz.documentNumber == "L898902C")
        #expect(mrz.dateOfBirth == "640812")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "120415")
        #expect(mrz.nationality == "UTO")
    }

    @Test
    func `MRZ TD1 format (ID card)`() throws {
        let mrzString = "I<UTOD231458907<<<<<<<<<<<<<<<" +
            "7408122F1204159UTO<<<<<<<<<<<6" +
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        let mrz = try MRZData(mrzString: mrzString)

        #expect(mrz.format == .td1)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.documentNumber == "D23145890")
        #expect(mrz.dateOfBirth == "740812")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "120415")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
    }

    @Test
    func `MRZ TD2 format (visa)`() throws {
        // TD2: 2 lines × 36 chars = 72 chars
        let mrzString = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
            "D231458907UTO7408122F1204159<<<<<<<6"
        let mrz = try MRZData(mrzString: mrzString)

        #expect(mrz.format == .td2)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(mrz.documentNumber == "D23145890")
    }

    @Test
    func `Invalid MRZ length throws error`() {
        #expect(throws: NFCError.self) {
            _ = try MRZData(mrzString: "TOOSHORT")
        }
    }

    // MARK: - DataGroupId

    @Test
    func `DataGroupId file IDs are correct`() {
        #expect(DataGroupId.com.fileID == Data([0x01, 0x1E]))
        #expect(DataGroupId.sod.fileID == Data([0x01, 0x1D]))
        #expect(DataGroupId.dg1.fileID == Data([0x01, 0x01]))
        #expect(DataGroupId.dg2.fileID == Data([0x01, 0x02]))
        #expect(DataGroupId.dg14.fileID == Data([0x01, 0x0E]))
        #expect(DataGroupId.dg15.fileID == Data([0x01, 0x0F]))
    }

    @Test
    func `DataGroupId TLV tags are correct`() {
        #expect(DataGroupId.com.tlvTag == 0x60)
        #expect(DataGroupId.sod.tlvTag == 0x77)
        #expect(DataGroupId.dg1.tlvTag == 0x61)
        #expect(DataGroupId.dg2.tlvTag == 0x75)
        #expect(DataGroupId.dg7.tlvTag == 0x67)
        #expect(DataGroupId.dg11.tlvTag == 0x6B)
        #expect(DataGroupId.dg12.tlvTag == 0x6C)
        #expect(DataGroupId.dg14.tlvTag == 0x6E)
        #expect(DataGroupId.dg15.tlvTag == 0x6F)
    }

    @Test
    func `All DataGroupId cases have names`() {
        for dgId in DataGroupId.allCases {
            #expect(!dgId.name.isEmpty, "\(dgId) should have a non-empty name")
        }
    }

    // MARK: - PassportModel

    @Test
    func `PassportModel stores raw data groups`() {
        let rawData = Data([0x01, 0x02, 0x03])
        let model = PassportModel(
            ldsVersion: "0107",
            unicodeVersion: "040000",
            availableDataGroups: [.dg1, .dg2],
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
            sodRaw: rawData,
            passiveAuthResult: nil,
            activeAuthResult: nil,
            rawDataGroups: [.sod: rawData]
        )

        #expect(model.ldsVersion == "0107")
        #expect(model.availableDataGroups.count == 2)
        #expect(model.sodRaw == rawData)
        #expect(model.rawDataGroups[.sod] == rawData)
    }

    // MARK: - Passport APDU Construction

    @Test
    func `SELECT eMRTD application APDU`() {
        let apdu = CommandAPDU.selectPassportApplication()
        #expect(apdu.cla == 0x00)
        #expect(apdu.ins == 0xA4)
        #expect(apdu.p1 == 0x04)
        #expect(apdu.p2 == 0x0C)
        #expect(apdu.data == Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]))
    }

    @Test
    func `SELECT EF APDU`() {
        let apdu = CommandAPDU.selectEF(id: DataGroupId.dg1.fileID)
        #expect(apdu.ins == 0xA4)
        #expect(apdu.p1 == 0x02)
        #expect(apdu.p2 == 0x0C)
        #expect(apdu.data == Data([0x01, 0x01]))
    }

    @Test
    func `GET CHALLENGE APDU`() {
        let apdu = CommandAPDU.getChallenge()
        #expect(apdu.cla == 0x00)
        #expect(apdu.ins == 0x84)
        #expect(apdu.le == 0x08)
    }

    @Test
    func `MUTUAL AUTHENTICATE APDU`() {
        let data = Data(repeating: 0xAA, count: 40)
        let apdu = CommandAPDU.mutualAuthenticate(data: data)
        #expect(apdu.ins == 0x82)
        #expect(apdu.data?.count == 40)
        #expect(apdu.le == 0x28)
    }

    @Test
    func `READ BINARY chunk APDU with offset`() {
        let apdu = CommandAPDU.readBinaryChunk(offset: 0x0100, length: 0xA0)
        #expect(apdu.ins == 0xB0)
        #expect(apdu.p1 == 0x01) // high byte of offset
        #expect(apdu.p2 == 0x00) // low byte of offset
        #expect(apdu.le == 0xA0) // length
    }

    @Test
    func `READ BINARY chunk APDU at offset 0`() {
        let apdu = CommandAPDU.readBinaryChunk(offset: 0, length: 4)
        #expect(apdu.p1 == 0x00)
        #expect(apdu.p2 == 0x00)
        #expect(apdu.le == 0x04)
    }
}
