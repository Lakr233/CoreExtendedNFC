// China T-Union transit card test suite.
//
// ## References
// - T-Union AID: A000000632010105
// - GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02 → 4 bytes
// - Balance: low 31 bits of a 4-byte big-endian CNY fen value
// - File 0x15: serial (bytes 10-19), validity (bytes 20-27)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct TUnionTests {
    // MARK: - AID Selection

    @Test
    func `Select T-Union AID and read balance`() async throws {
        let transport = MockTransport()
        // Balance = 5000 fen (50 yuan).
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AID
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 0
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 1
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

    @Test
    func `T-Union AID not found throws error`() async {
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

    @Test
    func `Parse balance as big-endian fen`() async throws {
        let transport = MockTransport()
        // 12345 fen = 0x00003039
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x30, 0x39]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 0
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 1
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // SELECT file fails (no file info)
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 12345)
    }

    @Test
    func `Parse balance masks upper garbage bit`() {
        #expect(TUnionReader.parseBalanceFen(Data([0x80, 0x00, 0x13, 0x88])) == 5000)
    }

    @Test
    func `Zero balance`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 0
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 1
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // no file info
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 0)
        #expect(result.formattedBalance == "¥0.00")
    }

    // MARK: - Hex Date Parsing

    @Test
    func `Parse hex date 20251231`() throws {
        let data = Data([0x20, 0x25, 0x12, 0x31])
        let date = TUnionReader.parseHexDate(data)
        #expect(date != nil)

        let calendar = Calendar(identifier: .gregorian)
        let components = try calendar.dateComponents(
            in: #require(TimeZone(identifier: "Asia/Shanghai")),
            from: #require(date)
        )
        #expect(components.year == 2025)
        #expect(components.month == 12)
        #expect(components.day == 31)
    }

    @Test
    func `Invalid hex date returns nil`() {
        let data = Data([0x20, 0x25, 0x13, 0x01]) // month 13
        let date = TUnionReader.parseHexDate(data)
        #expect(date == nil)
    }

    // MARK: - Serial Number Parsing

    @Test
    func `Serial number extracted from file 0x15 with first nibble skipped`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AID
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x01]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 0: 1 fen
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00), // GET BALANCE slot 1
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT file
            ResponseAPDU(data: buildFile15Data(serial: "31234567890123456789"), sw1: 0x90, sw2: 0x00),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        // Serial is hex of bytes 10-19, with first nibble skipped
        // "31234567890123456789" → skip first char → "1234567890123456789"
        #expect(result.serialNumber == "1234567890123456789")
        #expect(transport.sentAPDUs[3].bytes == Data([0x00, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x15, 0x00]))
    }

    @Test
    func `Display balance subtracts negative purse`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x13, 0x88]), sw1: 0x90, sw2: 0x00), // 5000
            ResponseAPDU(data: Data([0x00, 0x00, 0x03, 0xE8]), sw1: 0x90, sw2: 0x00), // 1000
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 4000)
    }

    @Test
    func `Display balance can be negative`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x03, 0xE8]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == -1000)
    }

    @Test
    func `Shanghai public transit card uses purse delta`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(
                data: hexToData("6F318408A000000632010105A5259F0801029F0C1E02002900FFFFFFFF02010310477004006744280220200115204012310114"),
                sw1: 0x90,
                sw2: 0x00
            ),
            ResponseAPDU(data: Data([0x00, 0x00, 0x03, 0x20]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x03, 0x20]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x86),
            ResponseAPDU(data: buildFile15Data(serial: "31234567890123456789"), sw1: 0x90, sw2: 0x00),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 0)
        #expect(result.formattedBalance == "¥0.00")
        #expect(result.serialNumber == "1234567890123456789")
        #expect(result.metadata["balanceSource"] == "TUnion dual purse")
        #expect(result.metadata["primaryPurseFen"] == "800")
        #expect(result.metadata["negativePurseFen"] == "800")
        #expect(result.metadata["fileInfoSource"] == "SFI 15 READ BINARY")
        #expect(transport.sentAPDUs[4].bytes == Data([0x00, 0xB0, 0x95, 0x00, 0x00]))
    }

    @Test
    func `Logged Shanghai T-Union card replays balance and transactions`() async throws {
        let transport = loggedTUnionTransport(
            selectFCI: "6F318408A000000632010105A5259F0801029F0C1E02002900FFFFFFFF02010310477004006744280220200115204012310114",
            balance0: "00000320",
            balance1: "00000320",
            sfi18: [
                "0002000000000000000220009999004020200115151321",
                "0001000000000000000220009299004020200115151321",
            ]
        )

        let result = try await TUnionReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 0)
        #expect(result.transactions.count == 2)
        let first = try #require(result.transactions.first)
        #expect(first.type == .topup)
        #expect(first.amount == 0)
        #expect(first.entryStation == "200099990040")
        #expect(try #require(first.rawData).hexString == "0002000000000000000220009999004020200115151321")
    }

    @Test
    func `Logged Beijing T-Union card replays balance and ten transactions`() async throws {
        let transport = loggedTUnionTransport(
            selectFCI: "6F318408A000000632010105A5259F0801029F0C1E00083010FFFFFFFF02010310483001000641250720220301204912310000",
            balance0: "000002E4",
            balance1: "00000000",
            sfi18: [
                "00B1000000000000000941310062938020240310211508",
                "00B0000000000000A00941310062938820240310195719",
                "00AF0000000000017C0941310040552720240308200056",
                "00AE000000000000000941310043483620240308192014",
                "00AD000000000000BE0941310043484320240308171554",
                "00AC000000000000000941310043501520240308170331",
                "00AB000000000001DB0941310043502920240308140501",
                "00AA000000000000000941310004150620240308131356",
                "00A9000000000000BE0941310040552720240223210850",
                "00A8000000000000000941310064192120240223205019",
            ]
        )

        let result = try await TUnionReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 740)
        #expect(result.formattedBalance == "¥7.40")
        #expect(result.transactions.count == 10)
        let first = try #require(result.transactions.first)
        #expect(first.recordNumber == 1)
        #expect(first.entryStation == "413100629380")
        #expect(try #require(first.rawData).hexString == "00B1000000000000000941310062938020240310211508")

        let second = try #require(result.transactions.dropFirst().first)
        #expect(second.amount == -160)
        #expect(second.entryStation == "413100629388")
    }

    @Test
    func `Logged zero-balance T-Union card keeps empty records empty`() async throws {
        let transport = loggedTUnionTransport(
            selectFCI: "6F368408A000000632010105A5269F080200309F0C1E02215840FFFFFFFF0201031048704040106424182024110720541107000000000000",
            balance0: "00000000",
            balance1: "00000000",
            sfi18: Array(repeating: "0000000000000000000000000000000000000000000000", count: 10)
        )

        let result = try await TUnionReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 0)
        #expect(result.transactions.isEmpty)
    }

    @Test
    func `Logged Shenzhen T-Union card replays stored balance and station data`() async throws {
        let transport = loggedTUnionTransport(
            selectFCI: "6F318408A000000632010105A5259F0801029F0C1E00083010FFFFFFFF02010310483001000732696420230828209912310000",
            balance0: "000000FA",
            balance1: "00000000",
            sfi18: [
                "0057000000000002580941310192596920240614142250",
                "0056000000000000000941310614805320240614133122",
                "0055000000000000BE0941310043546620240613120710",
                "0054000000000000000941310040553220240613115300",
                "0053000000000000000930100500319220240612180513",
                "0052000000000000A00941310062938120240612162245",
                "0051000000000000BE0941310040552120240611181322",
                "0050000000000000000941310004193920240611180136",
                "004F000000000000BE0941310004156920240604195201",
                "004E000000000000000941310004150620240604194012",
            ]
        )

        let result = try await TUnionReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 250)
        #expect(result.transactions.count == 10)
        let first = try #require(result.transactions.first)
        #expect(first.amount == -600)
        #expect(first.entryStation == "413101925969")
        #expect(try #require(first.rawData).hexString == "0057000000000002580941310192596920240614142250")
    }

    // MARK: - Records

    @Test
    func `Read T-Union transaction records from SFI 18`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x02, 0xE4]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x00]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
            ResponseAPDU(data: buildTransactionRecord(amount: 260, type: 0x06), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83),
        ]

        let reader = TUnionReader(transport: transport)
        let result = try await reader.readBalance()

        #expect(result.balanceRaw == 740)
        #expect(result.transactions.count == 1)
        let tx = try #require(result.transactions.first)
        #expect(tx.type == .purchase)
        #expect(tx.amount == -260)
        #expect(tx.recordNumber == 1)
        #expect(tx.entryStation == "010203040506")
        #expect(tx.metadata["source"] == "TUnion SFI 18")
        #expect(transport.sentAPDUs.contains { $0.bytes == Data([0x00, 0xB2, 0x01, 0xC4, 0x17]) })
    }

    @Test
    func `Parse top-up transaction record`() throws {
        let tx = try #require(TUnionReader.parseTransactionRecord(buildTransactionRecord(amount: 10000, type: 0x02), recordNumber: 3))
        #expect(tx.type == .topup)
        #expect(tx.amount == 10000)
        #expect(tx.recordNumber == 3)
    }

    @Test
    func `Parse BCD date time`() throws {
        let date = try #require(TUnionReader.parseBCDDateTime(Data([0x20, 0x26, 0x05, 0x09, 0x12, 0x34, 0x56])))
        let components = try Calendar(identifier: .gregorian).dateComponents(
            in: #require(TimeZone(identifier: "Asia/Shanghai")),
            from: date
        )
        #expect(components.year == 2026)
        #expect(components.month == 5)
        #expect(components.day == 9)
        #expect(components.hour == 12)
        #expect(components.minute == 34)
        #expect(components.second == 56)
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

    private func buildTransactionRecord(amount: Int, type: UInt8) -> Data {
        var data = Data(repeating: 0x00, count: 0x17)
        let amountBytes = UInt32(amount).bigEndian
        withUnsafeBytes(of: amountBytes) { bytes in
            data[5] = bytes[0]
            data[6] = bytes[1]
            data[7] = bytes[2]
            data[8] = bytes[3]
        }
        data[9] = type
        data[10] = 0x01
        data[11] = 0x02
        data[12] = 0x03
        data[13] = 0x04
        data[14] = 0x05
        data[15] = 0x06
        data[16] = 0x20
        data[17] = 0x26
        data[18] = 0x05
        data[19] = 0x09
        data[20] = 0x12
        data[21] = 0x34
        data[22] = 0x56
        return data
    }

    private func loggedTUnionTransport(
        selectFCI: String,
        balance0: String,
        balance1: String,
        sfi18: [String],
        sfi1E: [String] = []
    ) -> MockTransport {
        let transport = MockTransport()
        var responses: [ResponseAPDU] = [
            ResponseAPDU(data: hexToData(selectFCI), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: hexToData(balance0), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: hexToData(balance1), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x86),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
        ]

        responses.append(contentsOf: sfi18.map {
            ResponseAPDU(data: hexToData($0), sw1: 0x90, sw2: 0x00)
        })
        if sfi18.count < TUnionConstants.maxTransactionRecords {
            responses.append(ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83))
        }

        responses.append(contentsOf: sfi1E.map {
            ResponseAPDU(data: hexToData($0), sw1: 0x90, sw2: 0x00)
        })
        if sfi1E.count < TUnionConstants.maxTransitActivityRecords {
            responses.append(ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83))
        }

        transport.apduResponses = responses
        return transport
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
