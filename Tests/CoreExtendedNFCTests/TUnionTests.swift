// China T-Union transit card test suite.
//
// ## References
// - T-Union AID: A000000632010105
// - GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02 → 4 bytes
// - Balance: bits 1-31 as signed integer (CNY fen)
// - File 0x15: serial (bytes 10-19), validity (bytes 20-27)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct TUnionTests {
    // MARK: - AID Selection

    @Test("Select T-Union AID and read balance")
    func selectAndReadBalance() async throws {
        let transport = MockTransport()
        // Balance = 5000 fen (50 yuan). Shifted left by 1: 5000 << 1 = 10000 = 0x00002710
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AID
            ResponseAPDU(data: Data([0x00, 0x00, 0x27, 0x10]), sw1: 0x90, sw2: 0x00), // GET BALANCE
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT file 0x15
            ResponseAPDU(data: buildFile15Data(), sw1: 0x90, sw2: 0x00), // READ BINARY
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 5000)
        #expect(result.currencyCode == "CNY")
        #expect(result.cardName == "T-Union")
        #expect(result.formattedBalance == "¥50.00")
    }

    @Test("T-Union AID not found throws error")
    func aidNotFound() async {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // SELECT fails
        ]

        let reader = TUnionReader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    // MARK: - Balance Parsing

    @Test("Parse balance with bit shift (bits 1-31)")
    func parseBalanceBitShift() async throws {
        let transport = MockTransport()
        // 12345 fen → shifted: 12345 << 1 = 24690 = 0x00006072
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x60, 0x72]), sw1: 0x90, sw2: 0x00), // GET BALANCE
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // SELECT file fails (no file info)
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 12345)
    }

    @Test("Zero balance")
    func zeroBalance() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // no file info
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 0)
        #expect(result.formattedBalance == "¥0.00")
    }

    // MARK: - Hex Date Parsing

    @Test("Parse hex date 20251231")
    func parseHexDate() {
        let data = Data([0x20, 0x25, 0x12, 0x31])
        let date = TUnionReader.parseHexDate(data)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(
            in: TimeZone(identifier: "Asia/Shanghai")!,
            from: date!
        )
        #expect(components.year == 2025)
        #expect(components.month == 12)
        #expect(components.day == 31)
    }

    @Test("Invalid hex date returns nil")
    func invalidHexDate() {
        let data = Data([0x20, 0x25, 0x13, 0x01]) // month 13
        let date = TUnionReader.parseHexDate(data)
        #expect(date == nil)
    }

    // MARK: - Serial Number Parsing

    @Test("Serial number extracted from file 0x15 with first nibble skipped")
    func serialNumberParsing() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AID
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x02]), sw1: 0x90, sw2: 0x00), // GET BALANCE: 1 fen
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT file
            ResponseAPDU(data: buildFile15Data(serial: "31234567890123456789"), sw1: 0x90, sw2: 0x00),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        // Serial is hex of bytes 10-19, with first nibble skipped
        // "31234567890123456789" → skip first char → "1234567890123456789"
        #expect(result.serialNumber == "1234567890123456789")
    }

    // MARK: - Helpers

    private func buildFile15Data(serial: String = "30112233445566778899") -> Data {
        var data = Data(repeating: 0x00, count: 30)

        // Serial at offset 10 (10 bytes)
        let serialBytes = hexToData(serial)
        for (i, byte) in serialBytes.prefix(10).enumerated() {
            data[10 + i] = byte
        }

        // Valid from at offset 20: 2020-01-01
        data[20] = 0x20; data[21] = 0x20; data[22] = 0x01; data[23] = 0x01
        // Valid until at offset 24: 2030-12-31
        data[24] = 0x20; data[25] = 0x30; data[26] = 0x12; data[27] = 0x31

        return data
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
