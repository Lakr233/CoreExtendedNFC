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

    @Test("Select T-Money AID successfully")
    func selectTMoney() async throws {
        let transport = MockTransport()
        // SELECT succeeds with FCI containing purse info
        let fci = buildFCI(serial: "1234567890ABCDEF", issueDate: "20200101", expiryDate: "20301231")
        transport.apduResponses = [
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x27, 0x10]), sw1: 0x90, sw2: 0x00), // GET BALANCE: 10000 KRW
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.cardName == "T-Money")
        #expect(result.balanceRaw == 10000)
        #expect(result.currencyCode == "KRW")
        #expect(result.serialNumber == "1234567890ABCDEF")
    }

    @Test("Falls back to Cashbee when T-Money fails")
    func fallbackToCashbee() async throws {
        let transport = MockTransport()
        let fci = buildFCI(serial: "AABBCCDD11223344", issueDate: "20210601", expiryDate: "20310601")
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // T-Money SELECT fails
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // Cashbee SELECT succeeds
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00), // GET BALANCE: 5000 KRW
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.cardName == "Cashbee")
        #expect(result.balanceRaw == 5000)
    }

    @Test("All AIDs fail throws error")
    func allAIDsFail() async {
        let transport = MockTransport()
        // All 4 SELECTs fail
        transport.apduResponses = [
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

    @Test("Parse 4-byte big-endian balance")
    func parseBalance() async throws {
        let transport = MockTransport()
        let fci = buildMinimalFCI()
        transport.apduResponses = [
            ResponseAPDU(data: fci, sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x01, 0x86, 0xA0]), sw1: 0x90, sw2: 0x00), // 100000 KRW
        ]

        let reader = KSX6924Reader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 100_000)
        #expect(result.formattedBalance == "₩100000")
    }

    // MARK: - BCD Date Parsing

    @Test("Parse BCD date 20251231")
    func parseBCDDate() {
        let data = Data([0x20, 0x25, 0x12, 0x31])
        let date = KSX6924Reader.parseBCDDate(data)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(
            in: TimeZone(identifier: "Asia/Seoul")!,
            from: date!
        )
        #expect(components.year == 2025)
        #expect(components.month == 12)
        #expect(components.day == 31)
    }

    @Test("Invalid BCD date returns nil")
    func invalidBCDDate() {
        let data = Data([0x20, 0x25, 0x13, 0x01]) // month 13 invalid
        let date = KSX6924Reader.parseBCDDate(data)
        #expect(date == nil)
    }

    // MARK: - Record Parsing

    @Test("Parse trip transaction record")
    func parseTripRecord() {
        var record = Data(repeating: 0x00, count: 16)
        record[0] = 0x01 // trip
        record[2] = 0x00; record[3] = 0x00; record[4] = 0x13; record[5] = 0x88 // balance 5000
        record[6] = 0x00; record[7] = 0x00; record[8] = 0x04; record[9] = 0xB0 // amount 1200
        record[10] = 0x20; record[11] = 0x25; record[12] = 0x03; record[13] = 0x15 // date 20250315

        let tx = KSX6924Reader.parseRecord(record)
        #expect(tx != nil)
        #expect(tx?.type == .trip)
        #expect(tx?.balanceAfter == 5000)
        #expect(tx?.amount == 1200)
    }

    @Test("Parse topup transaction record")
    func parseTopupRecord() {
        var record = Data(repeating: 0x00, count: 16)
        record[0] = 0x02 // topup
        record[2] = 0x00; record[3] = 0x00; record[4] = 0x27; record[5] = 0x10 // balance 10000
        record[6] = 0x00; record[7] = 0x00; record[8] = 0x13; record[9] = 0x88 // amount 5000
        record[10] = 0x20; record[11] = 0x25; record[12] = 0x03; record[13] = 0x10 // date 20250310

        let tx = KSX6924Reader.parseRecord(record)
        #expect(tx != nil)
        #expect(tx?.type == .topup)
        #expect(tx?.balanceAfter == 10000)
        #expect(tx?.amount == 5000)
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
