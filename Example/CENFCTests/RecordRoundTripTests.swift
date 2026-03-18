// Roundtrip tests for the Example app's persistence layer.
//
// These tests verify that the simplified Record types (wrapping library models
// directly) survive JSON and PropertyList encode → decode cycles.
@testable import CENFC
import Foundation
import Testing

// MARK: - ScanRecord Roundtrip

struct ScanRecordRoundTripTests {
    @Test
    func `ScanRecord with ISO 14443A card round-trips through JSON`() throws {
        let cardInfo = CardInfo(
            type: .ntag213,
            uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
            atqa: Data([0x44, 0x00]),
            sak: 0x00,
            ats: ATSInfo(fsci: 5, ta: 0x80, tb: nil, tc: 0x02, historicalBytes: Data([0x80, 0x4F]))
        )
        let record = ScanRecord(cardInfo: cardInfo)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(record)
        let decoded = try decoder.decode(ScanRecord.self, from: data)

        #expect(decoded.id == record.id)
        #expect(decoded.cardInfo.type == .ntag213)
        #expect(decoded.cardInfo.uid == cardInfo.uid)
        #expect(decoded.cardInfo.atqa == Data([0x44, 0x00]))
        #expect(decoded.cardInfo.sak == 0x00)
        #expect(decoded.cardInfo.ats?.fsci == 5)
        #expect(decoded.cardInfo.ats?.ta == 0x80)
        #expect(decoded.cardInfo.ats?.tb == nil)
        #expect(decoded.cardInfo.ats?.tc == 0x02)
        #expect(decoded.cardInfo.ats?.maxFrameSize == 64)
    }

    @Test
    func `ScanRecord with FeliCa card round-trips`() throws {
        let cardInfo = CardInfo(
            type: .felicaLite,
            uid: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            systemCode: Data([0x88, 0xB4]),
            idm: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        )
        let record = ScanRecord(cardInfo: cardInfo)

        let data = try PropertyListEncoder().encode(record)
        let decoded = try PropertyListDecoder().decode(ScanRecord.self, from: data)

        #expect(decoded.cardInfo.type == .felicaLite)
        #expect(decoded.cardInfo.systemCode == Data([0x88, 0xB4]))
        #expect(decoded.cardInfo.idm == cardInfo.idm)
    }

    @Test
    func `ScanRecord with ISO 15693 card round-trips`() throws {
        let cardInfo = CardInfo(
            type: .iso15693_generic,
            uid: Data([0xE0, 0x04, 0x01, 0x53, 0x0B, 0x29, 0x65, 0xB7]),
            icManufacturer: 4
        )
        let record = ScanRecord(cardInfo: cardInfo)

        let data = try PropertyListEncoder().encode(record)
        let decoded = try PropertyListDecoder().decode(ScanRecord.self, from: data)

        #expect(decoded.cardInfo.type == .iso15693_generic)
        #expect(decoded.cardInfo.icManufacturer == 4)
    }

    @Test
    func `ScanRecord with unknown card type round-trips associated values`() throws {
        let cardInfo = CardInfo(
            type: .unknown(atqa: Data([0x12, 0x34]), sak: 0xAB),
            uid: Data([0x01, 0x02, 0x03, 0x04])
        )
        let record = ScanRecord(cardInfo: cardInfo)

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(ScanRecord.self, from: data)

        #expect(decoded.cardInfo.type == .unknown(atqa: Data([0x12, 0x34]), sak: 0xAB))
    }

    @Test
    func `ScanRecord array round-trips through JSON (simulates ScanStore)`() throws {
        let records = [
            ScanRecord(cardInfo: CardInfo(type: .ntag213, uid: Data([0x04, 0x01]))),
            ScanRecord(cardInfo: CardInfo(type: .mifareDesfire, uid: Data([0x04, 0x02]))),
            ScanRecord(cardInfo: CardInfo(type: .felicaStandard, uid: Data([0x01, 0x02]))),
        ]

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(records)
        let decoded = try decoder.decode([ScanRecord].self, from: data)

        #expect(decoded.count == 3)
        #expect(decoded[0].cardInfo.type == .ntag213)
        #expect(decoded[1].cardInfo.type == .mifareDesfire)
        #expect(decoded[2].cardInfo.type == .felicaStandard)
    }
}

// MARK: - DumpRecord Roundtrip

struct DumpRecordRoundTripTests {
    @Test
    func `DumpRecord with pages round-trips through JSON`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(
                type: .ntag213,
                uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
                atqa: Data([0x44, 0x00]),
                sak: 0x00
            ),
            pages: (0 ..< 45).map { .init(number: UInt8($0), data: Data(repeating: 0xAA, count: 4)) },
            facts: [
                .init(key: "IC Type", value: "NTAG213"),
                .init(key: "Signature", value: "AABB", monospaced: true),
            ],
            capabilities: [.readable, .writable]
        )
        let record = DumpRecord(from: dump)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(record)
        let decoded = try decoder.decode(DumpRecord.self, from: data)

        #expect(decoded.id == record.id)
        #expect(decoded.dump.pages.count == 45)
        #expect(decoded.dump.pages[0].number == 0)
        #expect(decoded.dump.pages[0].data == Data(repeating: 0xAA, count: 4))
        #expect(decoded.dump.facts.count == 2)
        #expect(decoded.dump.facts[0].key == "IC Type")
        #expect(decoded.dump.facts[1].monospaced == true)
        #expect(decoded.dump.capabilities == [.readable, .writable])
        #expect(decoded.dump.cardInfo.type == .ntag213)
    }

    @Test
    func `DumpRecord with blocks round-trips`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .iso15693_generic, uid: Data([0xE0, 0x04]), icManufacturer: 4),
            blocks: (0 ..< 28).map { .init(number: $0, data: Data([0xE1, 0x40, 0x0E, 0x01]), locked: $0 < 2) },
            ndefMessage: Data([0xD1, 0x01, 0x0E, 0x55]),
            capabilities: [.readable]
        )
        let record = DumpRecord(from: dump)

        let data = try PropertyListEncoder().encode(record)
        let decoded = try PropertyListDecoder().decode(DumpRecord.self, from: data)

        #expect(decoded.dump.blocks.count == 28)
        #expect(decoded.dump.blocks[0].locked == true)
        #expect(decoded.dump.blocks[2].locked == false)
        #expect(decoded.dump.ndefMessage == Data([0xD1, 0x01, 0x0E, 0x55]))
        #expect(decoded.hasMemoryData == true)
    }

    @Test
    func `DumpRecord with files round-trips`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .mifareDesfire, uid: Data([0x04, 0x01, 0x02, 0x03])),
            files: [
                .init(fileID: 0x01, data: Data([0xAA, 0xBB, 0xCC]), name: "File 1"),
                .init(fileID: 0x02, data: Data([0xDD, 0xEE]), name: nil),
            ],
            capabilities: [.partiallyReadable]
        )
        let record = DumpRecord(from: dump)

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(DumpRecord.self, from: data)

        #expect(decoded.dump.files.count == 2)
        #expect(decoded.dump.files[0].name == "File 1")
        #expect(decoded.dump.files[0].data == Data([0xAA, 0xBB, 0xCC]))
        #expect(decoded.dump.files[1].name == nil)
    }

    @Test
    func `Empty DumpRecord round-trips`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .unknown(atqa: Data([0x00]), sak: 0x00), uid: Data([0x01]))
        )
        let record = DumpRecord(from: dump)

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(DumpRecord.self, from: data)

        #expect(decoded.dump.pages.isEmpty)
        #expect(decoded.dump.blocks.isEmpty)
        #expect(decoded.dump.files.isEmpty)
        #expect(decoded.dump.ndefMessage == nil)
        #expect(decoded.dump.facts.isEmpty)
        #expect(decoded.hasMemoryData == false)
    }

    @Test
    func `DumpRecord array round-trips through JSON (simulates DumpStore)`() throws {
        let records = [
            DumpRecord(from: MemoryDump(
                cardInfo: CardInfo(type: .ntag213, uid: Data([0x04, 0x01])),
                pages: [.init(number: 0, data: Data([0x04, 0x57, 0x01, 0xCA]))]
            )),
            DumpRecord(from: MemoryDump(
                cardInfo: CardInfo(type: .iso15693_generic, uid: Data([0xE0, 0x04])),
                blocks: [.init(number: 0, data: Data([0xE1, 0x40]))]
            )),
        ]

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(records)
        let decoded = try decoder.decode([DumpRecord].self, from: data)

        #expect(decoded.count == 2)
        #expect(decoded[0].dump.pages.count == 1)
        #expect(decoded[1].dump.blocks.count == 1)
    }
}

// MARK: - PassportRecord Roundtrip

struct PassportRecordRoundTripTests {
    @Test
    func `PassportRecord with MRZ data round-trips through JSON`() throws {
        let mrz = try MRZData(
            mrzString: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        )
        let passport = PassportModel(
            ldsVersion: "0107",
            unicodeVersion: "040000",
            availableDataGroups: [.dg1, .dg2, .dg14, .dg15],
            mrz: mrz,
            faceImageData: Data([0xFF, 0xD8, 0xFF, 0xE0]),
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: nil,
            securityInfoRaw: nil,
            activeAuthPublicKey: nil,
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: nil,
            passiveAuthResult: nil,
            activeAuthResult: nil,
            rawDataGroups: [.dg1: Data([0x61, 0x02, 0x5F, 0x1F])],
            securityReport: PassportSecurityReport(
                bac: PassportSecurityStageResult(status: .succeeded, detail: "BAC OK")
            )
        )
        let record = PassportRecord(from: passport)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(record)
        let decoded = try decoder.decode(PassportRecord.self, from: data)

        #expect(decoded.id == record.id)
        #expect(decoded.passport.mrz?.documentNumber == "L898902C3")
        #expect(decoded.passport.mrz?.lastName == "ERIKSSON")
        #expect(decoded.passport.mrz?.firstName == "ANNA MARIA")
        #expect(decoded.passport.faceImageData == Data([0xFF, 0xD8, 0xFF, 0xE0]))
        #expect(decoded.passport.ldsVersion == "0107")
        #expect(decoded.passport.availableDataGroups == [.dg1, .dg2, .dg14, .dg15])
        #expect(decoded.passport.securityReport.bac.status == .succeeded)
        #expect(decoded.passport.securityReport.bac.detail == "BAC OK")
        #expect(decoded.passport.rawDataGroups[.dg1] == Data([0x61, 0x02, 0x5F, 0x1F]))
    }

    @Test
    func `PassportRecord display helpers work after round-trip`() throws {
        let mrz = try MRZData(
            mrzString: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        )
        let passport = PassportModel(
            ldsVersion: nil, unicodeVersion: nil,
            availableDataGroups: [.dg1, .dg2],
            mrz: mrz, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: [.dg1: Data([0x61]), .dg2: Data(repeating: 0xFF, count: 1024)]
        )
        let record = PassportRecord(from: passport)

        let data = try PropertyListEncoder().encode(record)
        let decoded = try PropertyListDecoder().decode(PassportRecord.self, from: data)

        #expect(decoded.displayName == "ERIKSSON, ANNA MARIA")
        #expect(decoded.formattedDOB == "12/08/74")
        #expect(decoded.formattedExpiry == "15/04/12")
        #expect(decoded.dataGroupsSummary.contains("DG1"))
        #expect(decoded.totalRawSize == 1025)
    }

    @Test
    func `PassportRecord with security report round-trips all stages`() throws {
        let passport = PassportModel(
            ldsVersion: nil, unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: [:],
            securityReport: PassportSecurityReport(
                cardAccess: PassportSecurityStageResult(status: .succeeded, detail: "OK"),
                pace: PassportSecurityStageResult(status: .notSupported, detail: "No PACE"),
                bac: PassportSecurityStageResult(status: .succeeded, detail: "BAC OK"),
                chipAuthentication: PassportSecurityStageResult(status: .skipped, detail: "Skipped"),
                passiveAuthentication: PassportSecurityStageResult(status: .succeeded, detail: "Hashes match"),
                activeAuthentication: PassportSecurityStageResult(status: .failed, detail: "Sig invalid")
            )
        )
        let record = PassportRecord(from: passport)

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(PassportRecord.self, from: data)

        let report = decoded.passport.securityReport
        #expect(report.cardAccess.status == .succeeded)
        #expect(report.pace.status == .notSupported)
        #expect(report.bac.status == .succeeded)
        #expect(report.chipAuthentication.status == .skipped)
        #expect(report.passiveAuthentication.status == .succeeded)
        #expect(report.activeAuthentication.status == .failed)
        #expect(report.activeAuthentication.detail == "Sig invalid")
    }

    @Test
    func `PassportRecord array round-trips through JSON (simulates PassportStore)`() throws {
        let passport = PassportModel(
            ldsVersion: nil, unicodeVersion: nil,
            availableDataGroups: [.dg1],
            mrz: nil, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: [:]
        )
        let records = [
            PassportRecord(from: passport),
            PassportRecord(from: passport),
        ]

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(records)
        let decoded = try decoder.decode([PassportRecord].self, from: data)

        #expect(decoded.count == 2)
        #expect(decoded[0].id != decoded[1].id)
    }
}

// MARK: - CardDocument Envelope Roundtrip

struct CardDocumentEnvelopeRoundTripTests {
    @Test
    func `CardDocumentEnvelope with scan + dump round-trips through PropertyList`() throws {
        let cardInfo = CardInfo(
            type: .ntag213,
            uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
            atqa: Data([0x44, 0x00]),
            sak: 0x00
        )
        let scan = ScanRecord(cardInfo: cardInfo)
        let dump = DumpRecord(from: MemoryDump(
            cardInfo: cardInfo,
            pages: [.init(number: 0, data: Data([0x04, 0x57, 0x01, 0xCA]))],
            capabilities: [.readable]
        ))
        let envelope = CardDocumentEnvelope(scanRecord: scan, dumpRecord: dump)

        let data = try PropertyListEncoder().encode(envelope)
        let decoded = try PropertyListDecoder().decode(CardDocumentEnvelope.self, from: data)

        #expect(decoded.scanRecord.id == scan.id)
        #expect(decoded.scanRecord.cardInfo.type == .ntag213)
        #expect(decoded.dumpRecord?.dump.pages.count == 1)
        #expect(decoded.dumpRecord?.dump.capabilities == [.readable])
    }

    @Test
    func `CardDocumentEnvelope scan-only round-trips`() throws {
        let scan = ScanRecord(cardInfo: CardInfo(type: .mifareDesfire, uid: Data([0x04, 0x01])))
        let envelope = CardDocumentEnvelope(scanRecord: scan, dumpRecord: nil)

        let data = try PropertyListEncoder().encode(envelope)
        let decoded = try PropertyListDecoder().decode(CardDocumentEnvelope.self, from: data)

        #expect(decoded.dumpRecord == nil)
        #expect(decoded.scanRecord.cardInfo.type == .mifareDesfire)
    }

    @Test
    func `File-based round-trip writes and reads back identical envelope`() throws {
        let scan = ScanRecord(cardInfo: CardInfo(type: .ntag215, uid: Data([0x04, 0x02])))
        let dump = DumpRecord(from: MemoryDump(
            cardInfo: scan.cardInfo,
            pages: (0 ..< 135).map { .init(number: UInt8($0), data: Data(repeating: 0xBB, count: 4)) }
        ))
        let envelope = CardDocumentEnvelope(scanRecord: scan, dumpRecord: dump)
        let data = try PropertyListEncoder().encode(envelope)

        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test-envelope-\(UUID().uuidString).cenfc")
        try data.write(to: tmpURL, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tmpURL) }

        let readBack = try Data(contentsOf: tmpURL)
        let decoded = try PropertyListDecoder().decode(CardDocumentEnvelope.self, from: readBack)

        #expect(decoded.scanRecord.id == scan.id)
        #expect(decoded.dumpRecord?.dump.pages.count == 135)
    }
}
