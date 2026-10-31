import Foundation
import Testing

// Japan FeliCa IC transit card test suite.
//
// ## References
// - CJRC system code 0x0003
// - Balance: service 0x008B, 1 block, bytes 0x0B-0x0C little-endian (JPY)
// - History: service 0x090F, up to 20 blocks (cyclic)
// - Date encoding: 2 bytes BE, year(7) month(4) day(5), base 2000
@testable import CoreExtendedNFC

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
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalanceAndHistory()

        #expect(result.balanceRaw == 500)
        #expect(result.transactions.count == 1)

        let tx = result.transactions[0]
        #expect(tx.type == .trip)
        #expect(tx.amount == nil)
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
        #expect(first.amount == nil)
        #expect(first.balanceAfter == 27)
        #expect(first.entryStation == nil)
        #expect(first.exitStation == nil)
        // 30B5 = 2024-05-21, 9825 = 19:01 JST
        #expect(first.date == Date(timeIntervalSince1970: 1_716_285_660))

        let topup = result.transactions[15]
        #expect(topup.type == .topup)
        #expect(topup.amount == nil)
        #expect(topup.balanceAfter == 5377)
        #expect(topup.entryStation == nil) // process 0x02 charge carries no stations
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
        // Unused `00 00 00 80 …` slots carry no date and are dropped, as in Metrodroid
        // SuicaTransitData; only the four real records remain.
        #expect(result.transactions.count == 4)
        #expect(result.transactions.allSatisfy { $0.date != nil })

        let first = try #require(result.transactions.first)
        #expect(first.type == .purchase)
        #expect(first.balanceAfter == 10)
        #expect(first.entryStation == nil)
        #expect(first.exitStation == nil)

        // Process 07h (new issue) credits the initial 500 yen.
        let issue = try #require(result.transactions.last)
        #expect(issue.type == .topup)
        #expect(issue.balanceAfter == 500)
    }

    @Test
    func `System code mismatch throws error`() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [:],
            systemCode: Data([0x88, 0xB4]) // wrong system code
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
            systemCode: Data([0x00, 0x03])
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
            from: #require(date)
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
    func `Register deposit at POS is a top-up without stations`() throws {
        let tx = try #require(JapanICReader.parseHistoryBlock(hexToData("C7490000306F6DA00000721400000000")))
        #expect(tx.type == .topup)
        #expect(tx.balanceAfter == 5234)
        #expect(tx.entryStation == nil)
        #expect(tx.exitStation == nil)
    }

    @Test
    func `POS purchase decodes purchase time instead of stations`() throws {
        let tx = try #require(JapanICReader.parseHistoryBlock(hexToData("C7460000306F6DA00000D20400000000")))
        #expect(tx.type == .purchase)
        #expect(tx.balanceAfter == 1234)
        // 2024-03-15 13:45 JST
        #expect(tx.date == Date(timeIntervalSince1970: 1_710_477_900))
        #expect(tx.entryStation == nil)
    }

    @Test
    func `Ticket machine records report an entry station and no exit station`() throws {
        // Process 0x01, 2024-03-15, station 0123, bytes 8-9 ignored; console set per Metrodroid isTVM.
        for console in [UInt8(0x03), 0x07, 0x08, 0x12, 0x13, 0x14, 0x15] {
            var block = hexToData("00010000306F0123ABCDF40100000000")
            block[0] = console
            let tx = try #require(JapanICReader.parseHistoryBlock(block))
            #expect(tx.entryStation == "0123")
            #expect(tx.exitStation == nil)
            #expect(tx.mode == nil)
        }
    }

    @Test
    func `Bus records carry line and stop codes instead of stations`() throws {
        // Logged bus record: console 0x05, line 0E38, stop 011F.
        let tx = try #require(JapanICReader.parseHistoryBlock(hexToData("050F000F30B40E38011F7808000068A0")))
        #expect(tx.type == .trip)
        #expect(tx.entryStation == nil)
        #expect(tx.exitStation == nil)
        #expect(tx.metadata["busLineCode"] == "0E38")
        #expect(tx.metadata["busStopCode"] == "011F")
        #expect(tx.mode == .bus)
        #expect(tx.balanceAfter == 2168)
    }

    @Test
    func `Gate records keep entry and exit stations`() throws {
        let tx = try #require(JapanICReader.parseHistoryBlock(hexToData("1601000230B563237024A80000006E00")))
        #expect(tx.entryStation == "6323")
        #expect(tx.exitStation == "7024")
        #expect(tx.mode == .rail)
    }

    @Test
    func `Gate records carry entry and exit region codes`() throws {
        // Byte 15 bits 7-6 entry region, bits 5-4 exit region: MJS ICカードリーダー,
        // Jobcan, yanzm Suica Reader and Metrodroid SuicaTrip agree; station codes
        // are only unique together with their region.
        var block = hexToData("1601000230B563237024A80000006E00")
        block[15] = 0x60
        let tx = try #require(JapanICReader.parseHistoryBlock(block))
        #expect(tx.metadata["entryRegion"] == "1")
        #expect(tx.metadata["exitRegion"] == "2")
    }

    @Test
    func `Bus auto-charge process 17h is a top-up`() throws {
        // yanzm Suica Reader (AUTO_CHARGE_BUS) and Jobcan (charge) both classify 17h as a charge.
        var block = hexToData("1601000230B563237024A80000006E00")
        block[1] = 0x17
        let tx = try #require(JapanICReader.parseHistoryBlock(block))
        #expect(tx.type == .topup)
    }

    @Test
    func `Process type classification follows Metrodroid tables`() throws {
        func type(console: UInt8, process: UInt8) throws -> TransactionType {
            var block = Data(repeating: 0x00, count: 16)
            block[0] = console
            block[1] = process
            block[4] = 0x30
            block[5] = 0x6F
            return try #require(JapanICReader.parseHistoryBlock(block)).type
        }
        for process: UInt8 in [0x02, 0x14, 0x15, 0x1F, 0x48, 0x49, 0x82] {
            #expect(try type(console: 0x16, process: process) == .topup)
        }
        for process: UInt8 in [0x46, 0x4A, 0x4B, 0xC6, 0xCB] {
            #expect(try type(console: 0x16, process: process) == .purchase)
        }
        #expect(try type(console: 0xC8, process: 0x00) == .purchase)
        #expect(try type(console: 0x16, process: 0x01) == .trip)
        #expect(try type(console: 0x16, process: 0x3F) == .trip)
    }

    @Test
    func `Tag loss while reading history propagates`() async {
        var balanceBlock = Data(repeating: 0x00, count: 16)
        balanceBlock[0x0B] = 0xD2
        let base = MockFeliCaServiceTransport(
            serviceVersions: [
                JapanICConstants.balanceServiceCode: Data([0x00, 0x10]),
                JapanICConstants.historyServiceCode: Data([0x00, 0x10]),
            ],
            serviceBlocks: [
                JapanICConstants.balanceServiceCode: [balanceBlock],
                JapanICConstants.historyServiceCode: [hexToData("1601000230B563237024A80000006E00")],
            ],
            systemCode: JapanICConstants.systemCode
        )
        let transport = HistoryTagLossTransport(base: base)

        await expectTransitNFCError(.tagConnectionLost) {
            _ = try await JapanICReader(transport: transport).readBalanceAndHistory()
        }
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
            systemCode: Data([0x00, 0x03])
        )

        let reader = JapanICReader(transport: transport)
        let result = try await reader.readBalance()
        #expect(result.balanceRaw == 0)
    }

    @Test
    func `History keeps records whose date fields are out of range`() async throws {
        // Metrodroid SuicaUtil.extractDate returns null only for a raw date of 0, and
        // SuicaTransitData skips only those slots.
        let raw = 24 << 9 | 0 << 5 | 15 // month 0
        let rail = Data([0x16, 0x01, 0x00, 0x02, UInt8(raw >> 8), UInt8(raw & 0xFF), 0x01, 0x02, 0x03, 0x04, 0xE8, 0x03, 0, 0, 0x01, 0x00])
        let raw2 = 24 << 9 | 5 << 5 | 15
        let time = 24 << 11 | 10 << 5 // POS hour 24
        let pos = Data([0xC7, 0x46, 0x00, 0x00, UInt8(raw2 >> 8), UInt8(raw2 & 0xFF), UInt8(time >> 8), UInt8(time & 0xFF), 0, 0, 0xD0, 0x07, 0, 0, 0x02, 0x00])
        let good = Data([0x16, 0x01, 0x00, 0x02, UInt8(raw2 >> 8), UInt8(raw2 & 0xFF), 0x01, 0x02, 0x03, 0x04, 0x10, 0x27, 0, 0, 0x03, 0x00])
        let unused = Data([0x00, 0x00, 0x00, 0x80] + [UInt8](repeating: 0, count: 12)) // PASMO unused slot

        var balance = Data(count: 16)
        balance[0x0B] = 0xE8
        balance[0x0C] = 0x03
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [
                JapanICConstants.balanceServiceCode: Data([0x00, 0x00]),
                JapanICConstants.historyServiceCode: Data([0x00, 0x00]),
            ],
            serviceBlocks: [
                JapanICConstants.balanceServiceCode: [balance],
                JapanICConstants.historyServiceCode: [good, rail, pos, unused],
            ],
            systemCode: JapanICConstants.systemCode
        )
        let result = try await JapanICReader(transport: transport).readBalanceAndHistory()

        try #require(result.transactions.count == 3) // before: 1
        #expect(result.transactions.map(\.balanceAfter) == [10000, 1000, 2000])
        #expect(result.transactions[1].date == nil)
        #expect(result.transactions[1].entryStation == "0102") // like SuicaTrip: stations kept when the raw date is set
        #expect(result.transactions[2].type == .purchase)
        #expect(result.transactions[2].date == nil)
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
            identifier: hexToData(identifier)
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

/// Serves the first history block, then reports tag loss on the next history read.
private final class HistoryTagLossTransport: FeliCaTagTransporting, @unchecked Sendable {
    let base: MockFeliCaServiceTransport
    private var historyReads = 0

    init(base: MockFeliCaServiceTransport) {
        self.base = base
    }

    var identifier: Data { base.identifier }
    var systemCode: Data { base.systemCode }

    func send(_ data: Data) async throws -> Data { try await base.send(data) }
    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU { try await base.sendAPDU(apdu) }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        if serviceCode == JapanICConstants.historyServiceCode {
            historyReads += 1
            if historyReads > 1 { throw NFCError.tagConnectionLost }
        }
        return try await base.readWithoutEncryption(serviceCode: serviceCode, blockList: blockList)
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        try await base.requestService(nodeCodeList: nodeCodeList)
    }
}
