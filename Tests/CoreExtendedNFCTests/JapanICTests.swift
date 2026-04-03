// Japan FeliCa IC transit card test suite.
//
// ## References
// - CJRC system code 0x0003
// - Balance: service 0x008B, 1 block, bytes 0x0A-0x0B little-endian (JPY)
// - History: service 0x090F, up to 20 blocks (cyclic)
// - Date encoding: 2 bytes BE, year(7) month(4) day(5), base 2000
@testable import CoreExtendedNFC
import Foundation
import Testing

struct JapanICTests {
    // MARK: - Balance Reading

    @Test("Read balance from Japan IC card")
    func readBalance() async throws {
        // Build a 16-byte balance block with 1,234 yen at offset 0x0A (LE)
        var balanceBlock = Data(repeating: 0x00, count: 16)
        balanceBlock[0x0A] = 0xD2 // 1234 & 0xFF
        balanceBlock[0x0B] = 0x04 // 1234 >> 8

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x8B, 0x00]): [balanceBlock]],
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 1234)
        #expect(result.currencyCode == "JPY")
        #expect(result.cardName == "Japan IC")
        #expect(result.formattedBalance == "¥1234")
        #expect(result.transactions.isEmpty)
    }

    @Test("Read balance and history")
    func readBalanceAndHistory() async throws {
        var balanceBlock = Data(repeating: 0x00, count: 16)
        balanceBlock[0x0A] = 0xE8 // 500 & 0xFF = 0xF4... wait, 500 = 0x01F4
        balanceBlock[0x0A] = 0xF4
        balanceBlock[0x0B] = 0x01

        // History block: usage=0x01 (trip), date=2024-03-15, balance=500
        var historyBlock = Data(repeating: 0x00, count: 16)
        historyBlock[1] = 0x01 // usage type: trip
        // Date: year=24 (2024-2000), month=3, day=15
        // packed = (24 << 9) | (3 << 5) | 15 = 12288 | 96 | 15 = 12399 = 0x306F
        historyBlock[4] = 0x30
        historyBlock[5] = 0x6F
        historyBlock[6] = 0x01 // entry station high
        historyBlock[7] = 0x23 // entry station low
        historyBlock[8] = 0x04 // exit station high
        historyBlock[9] = 0x56 // exit station low
        historyBlock[0x0A] = 0xF4 // balance 500 LE
        historyBlock[0x0B] = 0x01

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [
                Data([0x8B, 0x00]): Data([0x00, 0x10]),
                Data([0x0F, 0x09]): Data([0x00, 0x10]),
            ],
            serviceBlocks: [
                Data([0x8B, 0x00]): [balanceBlock],
                Data([0x0F, 0x09]): [historyBlock],
            ],
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalanceAndHistory()

        #expect(result.balanceRaw == 500)
        #expect(result.transactions.count == 1)

        let tx = result.transactions[0]
        #expect(tx.type == .trip)
        #expect(tx.balanceAfter == 500)
        #expect(tx.entryStation == "0123")
        #expect(tx.exitStation == "0456")
    }

    @Test("System code mismatch throws error")
    func systemCodeMismatch() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [:],
            systemCode: Data([0x88, 0xB4]) // wrong system code
        )

        let reader = JapanICReader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    @Test("Balance service unavailable throws error")
    func balanceServiceUnavailable() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0xFF, 0xFF])], // service not found
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    // MARK: - Date Parsing

    @Test("Parse packed date from history block")
    func parseDateField() {
        var block = Data(repeating: 0x00, count: 16)
        // 2025-01-20: year=25, month=1, day=20
        // packed = (25 << 9) | (1 << 5) | 20 = 12800 | 32 | 20 = 12852 = 0x3234
        block[4] = 0x32
        block[5] = 0x34

        let date = JapanICReader.parseDate(block)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(
            in: TimeZone(identifier: "Asia/Tokyo")!,
            from: date!
        )
        #expect(components.year == 2025)
        #expect(components.month == 1)
        #expect(components.day == 20)
    }

    @Test("Parse date with invalid month returns nil")
    func parseDateInvalidMonth() {
        var block = Data(repeating: 0x00, count: 16)
        // month=0 is invalid: (25 << 9) | (0 << 5) | 15 = 12800 | 0 | 15 = 12815 = 0x320F
        block[4] = 0x32
        block[5] = 0x0F

        let date = JapanICReader.parseDate(block)
        #expect(date == nil)
    }

    // MARK: - History Block Parsing

    @Test("Topup transaction type detection")
    func topupTypeDetection() {
        var block = Data(repeating: 0x00, count: 16)
        block[1] = 0x02 // top-up usage type
        block[4] = 0x32 // valid date
        block[5] = 0x34
        block[0x0A] = 0xE8 // balance 1000
        block[0x0B] = 0x03

        let tx = JapanICReader.parseHistoryBlock(block)
        #expect(tx != nil)
        #expect(tx?.type == .topup)
        #expect(tx?.balanceAfter == 1000)
    }

    @Test("Purchase transaction type detection")
    func purchaseTypeDetection() {
        var block = Data(repeating: 0x00, count: 16)
        block[1] = 0x46 // purchase usage type
        block[4] = 0x32
        block[5] = 0x34
        block[0x0A] = 0x64 // balance 100
        block[0x0B] = 0x00

        let tx = JapanICReader.parseHistoryBlock(block)
        #expect(tx != nil)
        #expect(tx?.type == .purchase)
        #expect(tx?.balanceAfter == 100)
    }

    @Test("Empty history block is skipped")
    func emptyBlockSkipped() {
        let block = Data(repeating: 0x00, count: 16)
        // parseHistoryBlock still returns a transaction (all zeros) but
        // the reader's readHistory() skips all-zero blocks.
        // Here we just verify parseHistoryBlock handles it.
        let tx = JapanICReader.parseHistoryBlock(block)
        #expect(tx != nil)
    }

    @Test("Zero balance is valid")
    func zeroBalance() async throws {
        let balanceBlock = Data(repeating: 0x00, count: 16)

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x8B, 0x00]): [balanceBlock]],
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalance()
        #expect(result.balanceRaw == 0)
    }
}
