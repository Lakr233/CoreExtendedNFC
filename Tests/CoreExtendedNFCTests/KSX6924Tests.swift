// South Korea KS X 6924 transit card test suite.
//
// ## References
// - KS X 6924 specification
// - T-Money AID: D4100000030001
// - Balance: CLA=0x90 INS=0x4C → 4 bytes big-endian (KRW)
// - Purse info: tag 0xB0 in FCI response
@testable import CoreExtendedNFC
import Foundation
import Testing

struct KSX6924Tests {
    // MARK: - AID Selection

    @Test
    func `Select T-Money AID successfully`() async throws {
        let transport = MockTransport()
        // SELECT succeeds with FCI containing purse info
        let fci = buildFCI(serial: "1234567890ABCDEF", issueDate: "20200101", expiryDate: "20301231")
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // Hyundai SELECT fails
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x27, 0x10]), sw1: 0x90, sw2: 0x00), // GET BALANCE: 10000 KRW
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83), // SFI 4: no records
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.cardName == "T-Money")
        #expect(result.balanceRaw == 10000)
        #expect(result.currencyCode == "KRW")
        #expect(result.serialNumber == "1234567890ABCDEF")
    }

    @Test
    func `Falls back to Cashbee when T-Money fails`() async throws {
        let transport = MockTransport()
        let fci = buildFCI(serial: "AABBCCDD11223344", issueDate: "20210601", expiryDate: "20310601")
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // Hyundai SELECT fails
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // T-Money SELECT fails
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // Cashbee SELECT succeeds
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00), // GET BALANCE: 5000 KRW
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.cardName == "Cashbee")
        #expect(result.balanceRaw == 5000)
    }

    @Test
    func `Continues AID selection after thrown status word`() async throws {
        let transport = MockTransport()
        transport.apduFailures = [
            0: .unexpectedStatusWord(0x6A, 0x82),
        ]
        let fci = buildFCI(serial: "1234567890ABCDEF", issueDate: "20200101", expiryDate: "20301231")
        transport.apduResponses = [
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x27, 0x10]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83), // SFI 4: no records
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.cardName == "T-Money")
        #expect(result.balanceRaw == 10000)
    }

    @Test
    func `All AIDs fail throws error`() async {
        let transport = MockTransport()
        // All SELECTs fail
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
        ]

        let reader = KSX6924Reader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    // MARK: - Balance Parsing

    @Test
    func `Parse 4-byte big-endian balance`() async throws {
        let transport = MockTransport()
        let fci = buildMinimalFCI()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // Hyundai SELECT fails
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x01, 0x86, 0xA0]), sw1: 0x90, sw2: 0x00), // 100000 KRW
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83), // SFI 4: no records
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 100_000)
        #expect(result.formattedBalance == "₩100000")
    }

    // MARK: - BCD Date Parsing

    @Test
    func `Parse BCD date 20251231`() throws {
        let data = Data([0x20, 0x25, 0x12, 0x31])
        let date = KSX6924Reader.parseBCDDate(data)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = try calendar.dateComponents(
            in: #require(TimeZone(identifier: "Asia/Seoul")),
            from: #require(date)
        )
        #expect(components.year == 2025)
        #expect(components.month == 12)
        #expect(components.day == 31)
    }

    @Test
    func `Invalid BCD date returns nil`() {
        let data = Data([0x20, 0x25, 0x13, 0x01]) // month 13 invalid
        let date = KSX6924Reader.parseBCDDate(data)
        #expect(date == nil)
    }

    // MARK: - Record Parsing (SFI 4, Metrodroid TMoneyTrip layout)

    /// 46-byte TMoneyTrip record: type 01, balance 5000, counter 7, cost 1250,
    /// 2025-03-15 08:30:00 KST at offset 26.
    static let tripRecordHex = "01000000138800000007000004E20000000000000000000000002025031508300000000000000000000000000000"

    @Test
    func `Parse SFI 4 trip record with TMoneyTrip layout`() throws {
        let tx = try #require(KSX6924Reader.parseRecord(hexToData(Self.tripRecordHex), recordNumber: 1))
        #expect(tx.type == .trip)
        #expect(tx.balanceAfter == 5000)
        #expect(tx.amount == 1250)
        #expect(tx.date == Date(timeIntervalSince1970: 1_741_995_000))
        #expect(tx.recordNumber == 1)
        #expect(tx.metadata["counter"] == "7")
    }

    @Test
    func `Top-up record keeps a positive amount`() throws {
        var record = hexToData(Self.tripRecordHex)
        record[0] = 0x02
        let tx = try #require(KSX6924Reader.parseRecord(record))
        #expect(tx.type == .topup)
        #expect(tx.amount == 1250)
    }

    @Test
    func `Unused record slot is skipped`() {
        let empty = Data(repeating: 0x00, count: 46)
        #expect(KSX6924Reader.parseRecord(empty) == nil)
        #expect(KSX6924Reader.parseRecord(Data(repeating: 0x00, count: 20)) == nil)
    }

    @Test
    func `History is read from SFI 4 with READ RECORD`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // Hyundai SELECT fails
            ResponseAPDU(data: buildMinimalFCI(), sw1: 0x90, sw2: 0x00), // T-Money SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00), // GET BALANCE
            ResponseAPDU(data: hexToData(Self.tripRecordHex), sw1: 0x90, sw2: 0x00), // record 1
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83), // record 2: not found
        ]

        let result = try await KSX6924Reader(transport: transport).readBalanceAndHistory()

        #expect(result.cardName == "T-Money")
        #expect(result.currencyCode == "KRW")
        #expect(result.transactions.count == 1)
        #expect(result.transactions.first?.amount == 1250)
        #expect(transport.sentAPDUs[3].bytes == Data([0x00, 0xB2, 0x01, 0x24, 0x00]))
        #expect(transport.sentAPDUs[4].bytes == Data([0x00, 0xB2, 0x02, 0x24, 0x00]))
        #expect(!transport.sentAPDUs.contains { $0.ins == 0x78 })
    }

    @Test
    func `Tag loss while reading records propagates`() async {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: buildMinimalFCI(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00),
        ]
        transport.apduFailures = [3: .tagConnectionLost]

        await expectTransitNFCError(.tagConnectionLost) {
            _ = try await KSX6924Reader(transport: transport).readBalanceAndHistory()
        }
    }

    // MARK: - Snapper / MOIBA

    @Test
    func `Snapper records on the T-Money AID report NZD`() async throws {
        var snapperRecord = Data(repeating: 0x00, count: 26) + Data(repeating: 0xFF, count: 20)
        snapperRecord[0] = 0x01
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: buildMinimalFCI(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x04, 0xD2]), sw1: 0x90, sw2: 0x00), // 1234 cents
            ResponseAPDU(data: snapperRecord, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83),
        ]

        let result = try await KSX6924Reader(transport: transport).readBalance()

        #expect(result.cardName == "Snapper")
        #expect(result.currencyCode == "NZD")
        #expect(result.formattedBalance == "NZ$12.34")
        #expect(result.transactions.isEmpty)
    }

    @Test
    func `Snapper discriminator requires every record to carry the FF filler`() {
        let snapper = Data(repeating: 0x00, count: 26) + Data(repeating: 0xFF, count: 20)
        #expect(KSX6924Reader.isSnapper(records: [snapper, snapper]))
        #expect(!KSX6924Reader.isSnapper(records: []))
        #expect(!KSX6924Reader.isSnapper(records: [snapper, hexToData(Self.tripRecordHex)]))
        #expect(!KSX6924Reader.isSnapper(records: [snapper + Data([0xFF])]))
    }

    @Test
    func `Snapper discriminator keeps Snapper records whose type byte is 1 or 2`() {
        // Metrodroid SnapperTransaction.parseTransaction reads the transaction type from
        // byte 0 of the SFI 4 record and treats 2 as a top-up, so real Snapper records
        // carry the same type values as T-Money trips; the type byte cannot rule Snapper out.
        var topUp = Data(repeating: 0x00, count: 26) + Data(repeating: 0xFF, count: 20)
        topUp[0] = 0x02
        var trip = topUp
        trip[0] = 0x01
        #expect(KSX6924Reader.isSnapper(records: [trip, topUp]))
    }

    @Test
    func `Snapper discriminator rejects any record with a T-Money timestamp`() {
        // A T-Money record keeps its BCD date-time at 26..<33, so the FF filler is absent.
        let snapper = Data(repeating: 0x00, count: 26) + Data(repeating: 0xFF, count: 20)
        var tMoney = snapper
        tMoney.replaceSubrange(26 ..< 33, with: [0x20, 0x25, 0x03, 0x15, 0x08, 0x30, 0x00])
        #expect(!KSX6924Reader.isSnapper(records: [tMoney]))
        #expect(!KSX6924Reader.isSnapper(records: [snapper, tMoney, snapper]))
    }

    @Test
    func `AID labels follow Metrodroid`() {
        let names = Dictionary(uniqueKeysWithValues: KSX6924Constants.allAIDs.map { ($0.aid.hexString, $0.name) })
        #expect(names["D4100000300001"] == "MOIBA")
        #expect(names["D4100000030001"] == "T-Money / Snapper")
    }

    // MARK: - Helpers

    /// Build a minimal FCI with no purse info (empty data).
    private func buildMinimalFCI() -> Data {
        Data()
    }

    /// Build FCI data containing a purse info tag 0xB0 with the given fields.
    private func buildFCI(serial: String, issueDate: String, expiryDate: String) -> Data {
        // Construct purse info: 25+ bytes
        var purse = Data(repeating: 0x00, count: 25)

        // Serial at offset 4 (8 bytes)
        let serialBytes = hexToData(serial)
        for (i, byte) in serialBytes.prefix(8).enumerated() {
            purse[4 + i] = byte
        }

        // Issue date at offset 17 (4 bytes BCD)
        let issueBytes = hexToData(issueDate)
        for (i, byte) in issueBytes.prefix(4).enumerated() {
            purse[17 + i] = byte
        }

        // Expiry date at offset 21 (4 bytes BCD)
        let expiryBytes = hexToData(expiryDate)
        for (i, byte) in expiryBytes.prefix(4).enumerated() {
            purse[21 + i] = byte
        }

        // Wrap in TLV: tag 0xB0 + length + purse
        return ASN1Parser.encodeTLV(tag: 0xB0, value: purse)
    }

    private func hexToData(_ hex: String) -> Data {
        var data = Data()
        var chars = hex.makeIterator()
        while let c1 = chars.next(), let c2 = chars.next() {
            if let byte = UInt8(String([c1, c2]), radix: 16) {
                data.append(byte)
            }
        }
        return data
    }
}
