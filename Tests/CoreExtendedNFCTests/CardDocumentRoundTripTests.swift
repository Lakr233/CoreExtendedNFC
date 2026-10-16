// Round-trip tests for CardDocumentEnvelope (the .cenfc file format used by the Example app).
//
// After refactoring, ScanRecord wraps CardInfo directly and DumpRecord wraps MemoryDump
// directly. These tests verify that PropertyList encode → decode preserves all fields.
@testable import CoreExtendedNFC
import Foundation
import Testing

// MARK: - Mirror types (matching Example/CENFC/Backend/Card/ Codable layout after refactor)

private struct TestScanRecord: Codable, Equatable {
    let id: UUID
    let date: Date
    let cardInfo: CardInfo
}

private struct TestDumpRecord: Codable, Equatable {
    let id: UUID
    let date: Date
    let dump: MemoryDump
}

private struct TestCardDocumentEnvelope: Codable, Equatable {
    let scanRecord: TestScanRecord
    let dumpRecord: TestDumpRecord?
}

// MARK: - Fixtures

private let fixtureCardInfo = CardInfo(
    type: .iso15693_generic,
    uid: Data([0xE0, 0x04, 0x01, 0x53, 0x0B, 0x29, 0x65, 0xB7]),
    icManufacturer: 4
)

private let fixtureScan = TestScanRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
    date: Date(timeIntervalSince1970: 1_700_000_000),
    cardInfo: fixtureCardInfo
)

private let fixtureDump = TestDumpRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
    date: Date(timeIntervalSince1970: 1_700_000_000),
    dump: MemoryDump(
        cardInfo: fixtureCardInfo,
        blocks: (0 ..< 28).map { .init(number: $0, data: Data([0xE1, 0x40, 0x0E, 0x01])) },
        ndefMessage: Data([0xD1, 0x01, 0x0E, 0x55]),
        facts: [
            .init(key: "Block Size", value: "4 bytes"),
            .init(key: "Blocks", value: "28"),
            .init(key: "DSFID", value: "0x00", monospaced: true),
        ],
        capabilities: [.readable]
    )
)

// MARK: - Tests

struct CardDocumentRoundTripTests {
    @Test
    func `Envelope with scan + dump round-trips through PropertyList`() throws {
        let original = TestCardDocumentEnvelope(scanRecord: fixtureScan, dumpRecord: fixtureDump)

        let data = try PropertyListEncoder().encode(original)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: data)

        #expect(decoded == original)
        #expect(decoded.scanRecord.cardInfo.uid == fixtureCardInfo.uid)
        #expect(decoded.scanRecord.cardInfo.type == .iso15693_generic)
        #expect(decoded.dumpRecord != nil)
        #expect(decoded.dumpRecord?.dump.blocks.count == 28)
        #expect(decoded.dumpRecord?.dump.ndefMessage != nil)
        #expect(decoded.dumpRecord?.dump.facts.count == 3)
    }

    @Test
    func `Envelope with scan only (no dump) round-trips`() throws {
        let original = TestCardDocumentEnvelope(scanRecord: fixtureScan, dumpRecord: nil)

        let data = try PropertyListEncoder().encode(original)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: data)

        #expect(decoded == original)
        #expect(decoded.dumpRecord == nil)
        #expect(decoded.scanRecord.cardInfo.icManufacturer == 4)
    }

    @Test
    func `ScanRecord with ATS data round-trips all protocol fields`() throws {
        let cardInfo = CardInfo(
            type: .ntag213,
            uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
            atqa: Data([0x44, 0x00]),
            sak: 0x00,
            ats: ATSInfo(fsci: 5, ta: 0x80, tb: nil, tc: 0x02, historicalBytes: Data([0x80, 0x4F]))
        )
        let scan = TestScanRecord(id: UUID(), date: Date(), cardInfo: cardInfo)
        let envelope = TestCardDocumentEnvelope(scanRecord: scan, dumpRecord: nil)

        let data = try PropertyListEncoder().encode(envelope)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: data)

        #expect(decoded.scanRecord.cardInfo.atqa == Data([0x44, 0x00]))
        #expect(decoded.scanRecord.cardInfo.sak == 0x00)
        #expect(decoded.scanRecord.cardInfo.ats?.fsci == 5)
        #expect(decoded.scanRecord.cardInfo.ats?.ta == 0x80)
        #expect(decoded.scanRecord.cardInfo.ats?.tb == nil)
        #expect(decoded.scanRecord.cardInfo.ats?.tc == 0x02)
        #expect(decoded.scanRecord.cardInfo.ats?.maxFrameSize == 64)
    }

    @Test
    func `DumpRecord with page-based dump round-trips all fields`() throws {
        let cardInfo = CardInfo(
            type: .ntag213,
            uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
            atqa: Data([0x44, 0x00]),
            sak: 0x00
        )
        let dump = MemoryDump(
            cardInfo: cardInfo,
            pages: (0 ..< 45).map { .init(number: UInt8($0), data: Data(repeating: 0xAA, count: 4)) },
            facts: [
                .init(key: "IC Type", value: "NTAG213"),
                .init(key: "Signature", value: "AABB", monospaced: true),
            ],
            capabilities: [.readable, .writable]
        )
        let dumpRecord = TestDumpRecord(id: UUID(), date: Date(), dump: dump)
        let scan = TestScanRecord(id: UUID(), date: dumpRecord.date, cardInfo: cardInfo)
        let envelope = TestCardDocumentEnvelope(scanRecord: scan, dumpRecord: dumpRecord)

        let data = try PropertyListEncoder().encode(envelope)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: data)

        #expect(decoded.dumpRecord?.dump.pages.count == 45)
        #expect(decoded.dumpRecord?.dump.blocks.count == 0)
        #expect(decoded.dumpRecord?.dump.capabilities == [.readable, .writable])
        #expect(decoded.dumpRecord?.dump.facts[1].monospaced == true)
    }

    @Test
    func `File-based round-trip writes and reads back identical envelope`() throws {
        let original = TestCardDocumentEnvelope(scanRecord: fixtureScan, dumpRecord: fixtureDump)
        let data = try PropertyListEncoder().encode(original)

        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test-roundtrip-\(UUID().uuidString).cenfc")
        try data.write(to: tmpURL, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tmpURL) }

        let readBack = try Data(contentsOf: tmpURL)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: readBack)

        #expect(decoded == original)
    }

    @Test
    func `Empty dump fields survive round-trip`() throws {
        let cardInfo = CardInfo(type: .unknown(atqa: Data([0x00, 0x00]), sak: 0x00), uid: Data([0x01]))
        let dump = MemoryDump(cardInfo: cardInfo)
        let dumpRecord = TestDumpRecord(id: UUID(), date: Date(), dump: dump)
        let scan = TestScanRecord(id: UUID(), date: dumpRecord.date, cardInfo: cardInfo)
        let original = TestCardDocumentEnvelope(scanRecord: scan, dumpRecord: dumpRecord)

        let data = try PropertyListEncoder().encode(original)
        let decoded = try PropertyListDecoder().decode(TestCardDocumentEnvelope.self, from: data)

        #expect(decoded == original)
        #expect(decoded.dumpRecord?.dump.pages.isEmpty == true)
        #expect(decoded.dumpRecord?.dump.facts.isEmpty == true)
        #expect(decoded.dumpRecord?.dump.capabilities.isEmpty == true)
    }

    @Test
    func `JSON round-trip for ScanRecord (simulates ScanStore)`() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let records = [fixtureScan]
        let data = try encoder.encode(records)
        let decoded = try decoder.decode([TestScanRecord].self, from: data)

        #expect(decoded.count == 1)
        #expect(decoded[0].cardInfo.uid == fixtureCardInfo.uid)
        #expect(decoded[0].cardInfo.type == .iso15693_generic)
    }

    @Test
    func `JSON round-trip for DumpRecord (simulates DumpStore)`() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let records = [fixtureDump]
        let data = try encoder.encode(records)
        let decoded = try decoder.decode([TestDumpRecord].self, from: data)

        #expect(decoded.count == 1)
        #expect(decoded[0].dump.blocks.count == 28)
        #expect(decoded[0].dump.ndefMessage != nil)
    }

    @Test
    func `CardType.unknown with associated values round-trips`() throws {
        let cardInfo = CardInfo(
            type: .unknown(atqa: Data([0x12, 0x34]), sak: 0xAB),
            uid: Data([0x01, 0x02, 0x03, 0x04])
        )
        let scan = TestScanRecord(id: UUID(), date: Date(), cardInfo: cardInfo)

        let data = try PropertyListEncoder().encode(scan)
        let decoded = try PropertyListDecoder().decode(TestScanRecord.self, from: data)

        #expect(decoded.cardInfo.type == .unknown(atqa: Data([0x12, 0x34]), sak: 0xAB))
    }

    @Test
    func `PassportModel round-trips through JSON`() throws {
        let mrz = try MRZData(mrzString: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10")
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

        struct TestPassportRecord: Codable, Equatable {
            let id: UUID
            let date: Date
            let passport: PassportModel
        }

        let original = TestPassportRecord(id: UUID(), date: Date(), passport: passport)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data = try encoder.encode(original)
        let decoded = try decoder.decode(TestPassportRecord.self, from: data)

        #expect(decoded.passport.mrz?.documentNumber == "L898902C3")
        #expect(decoded.passport.mrz?.lastName == "ERIKSSON")
        #expect(decoded.passport.faceImageData == Data([0xFF, 0xD8, 0xFF, 0xE0]))
        #expect(decoded.passport.ldsVersion == "0107")
        #expect(decoded.passport.availableDataGroups == [.dg1, .dg2, .dg14, .dg15])
        #expect(decoded.passport.securityReport.bac.status == .succeeded)
        #expect(decoded.passport.securityReport.bac.detail == "BAC OK")
        #expect(decoded.passport.rawDataGroups[.dg1] == Data([0x61, 0x02, 0x5F, 0x1F]))
    }
}
