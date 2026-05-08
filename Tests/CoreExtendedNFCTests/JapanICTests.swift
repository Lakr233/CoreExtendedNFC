// Japan FeliCa IC transit card test suite.
//
// ## References
// - CJRC system code 0x0003
// - Balance: service 0x008B, 1 block, bytes 0x0B-0x0C little-endian (JPY)
// - History: service 0x090F, up to 20 blocks (cyclic)
// - Date encoding: 2 bytes BE, year(7) month(4) day(5), base 2000
@testable import CoreExtendedNFC
import Foundation
import Testing

struct JapanICTests {
    // MARK: - Balance Reading

    @Test
    func `Read balance from Japan IC card`() async throws {
        // Build a 16-byte balance block with 1,234 yen at offset 0x0B (LE)
        var balanceBlock = Data(repeating: 0x00, count: 16)
        balanceBlock[0x0B] = 0xD2 // 1234 & 0xFF
        balanceBlock[0x0C] = 0x04 // 1234 >> 8

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x8B, 0x00]): [balanceBlock]],
            systemCode: Data([0x00, 0x03]),
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 1234)
        #expect(result.currencyCode == "JPY")
        #expect(result.cardName == "Japan IC")
        #expect(result.formattedBalance == "¥1234")
        #expect(result.transactions.isEmpty)
    }

    @Test
    func `Read balance and history`() async throws {
        var balanceBlock = Data(repeating: 0x00, count: 16)
        balanceBlock[0x0B] = 0xF4
        balanceBlock[0x0C] = 0x01

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
            systemCode: Data([0x00, 0x03]),
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

    @Test
    func `Logged Japan IC card replays twenty history blocks`() async throws {
        let transport = loggedJapanICTransport(
            identifier: "010103126B20DB14",
            balanceBlock: "00000000000000002000001B0000006F",
            historyBlocks: [
                "C746000030B59825DCAD1B0000006F00",
                "1601000230B563237024A80000006E00",
                "1601000230B501E66323740200006C00",
                "1601001730B5D470FABBA80500006AA0",
                "050F000F30B40E38011F7808000068A0",
                "1601000230B401FB01F84A0900006700",
                "1601000230B401E601FBF40900006500",
                "C746000030B44F05E0AB2E0C00006300",
                "1601000230B381248117C70D000062A0",
                "1601000230B3812A8123E90E000060A0",
                "1601000230B363110C0CD90F00005E00",
                "1601000230B363136311191100005C00",
                "1601000230B363116313A51100005A00",
                "1601000230B301E86311311200005800",
                "1601000230B38117811C1114000056A0",
                "0802000030B381170000011500005480",
                "1601000230B2812A81177901000053A0",
                "C846000030B2A5C869709B0200005100",
                "1601000230B2811C81288B03000050A0",
                "1601000230B28117811C7B0400004EA0",
            ]
        )

        let result = try await JapanICReader(transport: transport).readBalanceAndHistory()

        #expect(result.serialNumber == "010103126B20DB14")
        #expect(result.balanceRaw == 27)
        #expect(result.transactions.count == 20)

        let first = try #require(result.transactions.first)
        #expect(first.type == .purchase)
        #expect(first.balanceAfter == 27)
        #expect(first.entryStation == "9825")
        #expect(first.exitStation == "DCAD")

        let topup = result.transactions[15]
        #expect(topup.type == .topup)
        #expect(topup.balanceAfter == 5377)
        #expect(topup.entryStation == "8117")
    }

    @Test
    func `Logged low-balance Japan IC card preserves sparse history blocks`() async throws {
        let transport = loggedJapanICTransport(
            identifier: "0101011278224813",
            balanceBlock: "00000000000000003000000A00000006",
            historyBlocks: [
                "C746000030B59825DCAD0A0000000600",
                "1601000230AE01CC0B02C80000000500",
                "1601000230AE0B0201CC5E0100000300",
                "0807000030AE0B020000F40100000100",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
                "00000080000000000000000000000000",
                "00000000000000000000000000000000",
            ]
        )

        let result = try await JapanICReader(transport: transport).readBalanceAndHistory()

        #expect(result.serialNumber == "0101011278224813")
        #expect(result.balanceRaw == 10)
        #expect(result.transactions.count == 12)

        let first = try #require(result.transactions.first)
        #expect(first.type == .purchase)
        #expect(first.balanceAfter == 10)
        #expect(first.entryStation == "9825")
        #expect(first.exitStation == "DCAD")

        let sparse = result.transactions[4]
        #expect(sparse.type == .trip)
        #expect(sparse.balanceAfter == 0)
        #expect(sparse.entryStation == "0000")
    }

    @Test
    func `System code mismatch throws error`() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [:],
            systemCode: Data([0x88, 0xB4]), // wrong system code
        )

        let reader = JapanICReader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    @Test
    func `Balance service unavailable throws error`() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0xFF, 0xFF])], // service not found
            systemCode: Data([0x00, 0x03]),
        )

        let reader = JapanICReader(transport: transport)
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBalance()
        }
    }

    // MARK: - Date Parsing

    @Test
    func `Parse packed date from history block`() throws {
        var block = Data(repeating: 0x00, count: 16)
        // 2025-01-20: year=25, month=1, day=20
        // packed = (25 << 9) | (1 << 5) | 20 = 12800 | 32 | 20 = 12852 = 0x3234
        block[4] = 0x32
        block[5] = 0x34

        let date = JapanICReader.parseDate(block)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = try calendar.dateComponents(
            in: #require(TimeZone(identifier: "Asia/Tokyo")),
            from: #require(date),
        )
        #expect(components.year == 2025)
        #expect(components.month == 1)
        #expect(components.day == 20)
    }

    @Test
    func `Parse date with invalid month returns nil`() {
        var block = Data(repeating: 0x00, count: 16)
        // month=0 is invalid: (25 << 9) | (0 << 5) | 15 = 12800 | 0 | 15 = 12815 = 0x320F
        block[4] = 0x32
        block[5] = 0x0F

        let date = JapanICReader.parseDate(block)
        #expect(date == nil)
    }

    // MARK: - History Block Parsing

    @Test
    func `Topup transaction type detection`() {
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

    @Test
    func `Purchase transaction type detection`() {
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

    @Test
    func `Empty history block is skipped`() {
        let block = Data(repeating: 0x00, count: 16)
        // parseHistoryBlock still returns a transaction (all zeros) but
        // the reader's readHistory() skips all-zero blocks.
        // Here we just verify parseHistoryBlock handles it.
        let tx = JapanICReader.parseHistoryBlock(block)
        #expect(tx != nil)
    }

    @Test
    func `Zero balance is valid`() async throws {
        let balanceBlock = Data(repeating: 0x00, count: 16)

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x8B, 0x00]): [balanceBlock]],
            systemCode: Data([0x00, 0x03]),
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalance()
        #expect(result.balanceRaw == 0)
    }

    private func loggedJapanICTransport(
        identifier: String,
        balanceBlock: String,
        historyBlocks: [String]
    ) -> MockFeliCaServiceTransport {
        MockFeliCaServiceTransport(
            serviceVersions: [
                JapanICConstants.balanceServiceCode: Data([0x03, 0x00]),
                JapanICConstants.historyServiceCode: Data([0x03, 0x00]),
            ],
            serviceBlocks: [
                JapanICConstants.balanceServiceCode: [hexToData(balanceBlock)],
                JapanICConstants.historyServiceCode: historyBlocks.map(hexToData),
            ],
            systemCode: JapanICConstants.systemCode,
            identifier: hexToData(identifier),
        )
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
