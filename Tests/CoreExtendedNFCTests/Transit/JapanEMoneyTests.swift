// Rakuten Edy, WAON and nanaco (FeliCa common area 0xFE00) test suite.
//
// ## References
// - Edy: Metrodroid EdyTrip and jennychan edy.html. The four history records below are the
//   samples printed on iccard.jennychan.at-ninja.jp/format/edy.html with their decoded values.
//   A physical-card capture from an ACR122U on 2026-10-31 is replayed with identifiers omitted.
// - WAON: TRETJapanNFCReader WaonCardData and jennychan waon.html. Synthetic history records
//   agree with TRETJapanNFCReader's byte arithmetic; an Apple Wallet capture is also replayed.
// - nanaco: TRETJapanNFCReader NanacoCardData and jennychan nanaco.html (synthetic records),
//   plus a physical-card capture from an ACR122U on 2026-10-31 with identifiers omitted.
import Foundation
import Testing

@testable import CoreExtendedNFC

struct JapanEMoneyTests {
    // MARK: - Rakuten Edy

    @Test
    func `Edy history matches the jennychan sample records`() throws {
        let charge = try #require(EdyReader.parseHistoryBlock(hex("02 00 02 0B 10 26 D1 2A 00 00 13 88 00 00 13 DB")))
        #expect(charge.type == .topup)
        #expect(charge.amount == 5000)
        #expect(charge.balanceAfter == 5083)
        #expect(charge.date == jst(2005, 8, 29, 14, 52, 26))
        #expect(charge.metadata["sequenceNumber"] == "523")
        #expect(charge.metadata["processType"] == "02")

        let viewerCharge = try #require(EdyReader.parseHistoryBlock(hex("02 00 03 95 12 DB 13 61 00 00 0B B8 00 00 0D 92")))
        #expect(viewerCharge.type == .topup)
        #expect(viewerCharge.amount == 3000)
        #expect(viewerCharge.balanceAfter == 3474)
        #expect(viewerCharge.date == jst(2006, 8, 10, 19, 34, 57))
        #expect(viewerCharge.metadata["sequenceNumber"] == "917")

        let valueCharge = try #require(EdyReader.parseHistoryBlock(hex("04 00 01 C0 0F C7 2D E9 00 00 01 F4 00 00 0E AD")))
        #expect(valueCharge.type == .topup)
        #expect(valueCharge.amount == 500)
        #expect(valueCharge.balanceAfter == 3757)
        #expect(valueCharge.date == jst(2005, 7, 12, 21, 28, 9))

        let payment = try #require(EdyReader.parseHistoryBlock(hex("20 00 01 BF 0F C7 15 C5 00 00 02 0E 00 00 0C B9")))
        #expect(payment.type == .purchase)
        #expect(payment.amount == 526)
        #expect(payment.balanceAfter == 3257)
        #expect(payment.date == jst(2005, 7, 12, 19, 45, 9))
        #expect(payment.metadata["sequenceNumber"] == "447")
    }

    @Test
    func `Edy unknown process types keep the balance but no amount`() throws {
        let tx = try #require(EdyReader.parseHistoryBlock(hex("31 00 00 01 00 00 00 00 00 00 00 64 00 00 01 F4")))
        #expect(tx.type == .unknown)
        #expect(tx.amount == nil)
        #expect(tx.balanceAfter == 500)
        #expect(tx.date == nil) // a zero timestamp means no date
        #expect(EdyReader.parseHistoryBlock(Data(repeating: 0, count: 16)) == nil)
    }

    @Test
    func `Read Edy balance, ID, issue date and history`() async throws {
        // Issue date 2005-12-28 19:17:45 JST: 2188 days << 17 | 69465 seconds = 0x11190F59.
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [EdyConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                EdyConstants.balanceServiceCode: [hex("DB 13 00 00 0E 02 00 00 00 00 00 00 00 00 0C 02")],
                EdyConstants.idServiceCode: [hex("00 02 12 34 56 78 12 34 56 78 11 19 0F 59 00 00")],
                EdyConstants.historyServiceCode: [
                    hex("02 00 02 0B 10 26 D1 2A 00 00 13 88 00 00 13 DB"),
                    Data(repeating: 0, count: 16),
                    hex("20 00 01 BF 0F C7 15 C5 00 00 02 0E 00 00 0C B9"),
                ],
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await EdyReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 5083)
        #expect(result.currencyCode == "JPY")
        #expect(result.cardName == "Rakuten Edy")
        #expect(result.formattedBalance == "¥5083")
        #expect(result.serialNumber == "1234567812345678")
        #expect(result.metadata["edyID"] == "1234567812345678")
        #expect(result.metadata["idm"] == transport.identifier.hexString)
        #expect(result.validFrom == jst(2005, 12, 28, 19, 17, 45))
        #expect(result.transactions.map(\.amount) == [5000, 526])
        // Six history blocks are requested one at a time; the mock refuses blocks 3-5, which ends the history.
        #expect(transport.readLog.contains(["0F17:3"]))
        #expect(!transport.readLog.contains(["0F17:4"]))
    }

    @Test
    func `Edy falls back to the IDm when the card information block is refused`() async throws {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [EdyConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [EdyConstants.balanceServiceCode: [hex("64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")]],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await EdyReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 100)
        #expect(result.serialNumber == transport.identifier.hexString)
        #expect(result.metadata["edyID"] == nil)
        #expect(result.validFrom == nil)
        #expect(result.transactions.isEmpty)
    }

    @Test
    func `Optional block reads still propagate session loss`() async {
        let transport = SessionLossFeliCaTransport(
            base: MockFeliCaServiceTransport(
                serviceVersions: [EdyConstants.balanceServiceCode: Data([0x00, 0x10])],
                serviceBlocks: [EdyConstants.balanceServiceCode: [Data(repeating: 0, count: 16)]],
                systemCode: Data([0xFE, 0x00])
            ),
            failingService: EdyConstants.idServiceCode
        )

        await expectTransitNFCError(.tagConnectionLost) {
            _ = try await EdyReader(transport: transport).readBalance()
        }
    }

    @Test
    func `Edy capture matches 542 yen and six purchases`() async throws {
        // ACR122U capture on 2026-10-31. Card identifiers are omitted; the transport supplies
        // a synthetic IDm. The cardholder confirmed the 542-yen balance.
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [EdyConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                EdyConstants.balanceServiceCode: [hex("1E 02 00 00 5E 01 00 00 00 00 00 00 00 00 2D 00")],
                EdyConstants.historyServiceCode: [
                    hex("20 00 00 2D 4A EC BA 73 00 00 01 5E 00 00 02 1E"),
                    hex("20 00 00 2C 4A E2 EA 4A 00 00 01 5E 00 00 03 7C"),
                    hex("20 00 00 2B 4A E0 BB CC 00 00 04 1F 00 00 04 DA"),
                    hex("20 00 00 2A 4A DD 1F 13 00 00 03 F9 00 00 08 F9"),
                    hex("20 00 00 29 47 90 CD F3 00 00 0D 7C 00 00 0C F2"),
                    hex("20 00 00 28 47 5D 24 8F 00 00 0C A2 00 00 1A 6E"),
                ],
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await EdyReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 542)
        #expect(result.currencyCode == "JPY")
        #expect(result.serialNumber == transport.identifier.hexString)
        #expect(result.transactions.map(\.type) == [.purchase, .purchase, .purchase, .purchase, .purchase, .purchase])
        #expect(result.transactions.map(\.amount) == [350, 350, 1055, 1017, 3452, 3234])
        #expect(result.transactions.map(\.balanceAfter) == [542, 892, 1242, 2297, 3314, 6766])
        #expect(
            result.transactions.map(\.date) == [
                jst(2026, 4, 4, 13, 15, 31),
                jst(2026, 3, 30, 16, 39, 38),
                jst(2026, 3, 29, 13, 21, 16),
                jst(2026, 3, 27, 20, 24, 51),
                jst(2025, 1, 29, 14, 38, 43),
                jst(2025, 1, 3, 20, 48, 15),
            ])
        #expect(result.transactions.map { $0.metadata["sequenceNumber"] } == ["45", "44", "43", "42", "41", "40"])
    }

    // MARK: - WAON

    @Test
    func `WAON history records decode packed fields`() throws {
        let payment = try #require(WAONReader.parseHistoryRecord(Self.waonPayment))
        #expect(payment.type == .purchase)
        #expect(payment.amount == 500)
        #expect(payment.balanceAfter == 1234)
        #expect(payment.date == jst(2024, 3, 15, 12, 34))
        #expect(payment.metadata["usageType"] == "04")
        #expect(payment.metadata["terminalNumber"] == "30313233343536373839414243")
        #expect(payment.metadata["cardSequence"] == "002A")
        #expect(payment.metadata["chargeAmount"] == "0")

        let charge = try #require(WAONReader.parseHistoryRecord(Self.waonCharge))
        #expect(charge.type == .topup)
        #expect(charge.amount == 5000)
        #expect(charge.balanceAfter == 6234)
        #expect(charge.date == jst(2024, 3, 16, 9, 5))

        let pointDownload = try #require(WAONReader.parseHistoryRecord(Self.waonPointDownload))
        #expect(pointDownload.type == .unknown)
        #expect(pointDownload.amount == nil)
        #expect(pointDownload.balanceAfter == 1734)
        #expect(pointDownload.date == jst(2024, 2, 1, 23, 59))
        #expect(pointDownload.metadata["event"] == "pointDownload")

        #expect(WAONReader.parseHistoryRecord(Data(repeating: 0, count: 32)) == nil)
    }

    @Test
    func `Read WAON balance, number, points and history newest first`() async throws {
        let blocks = [Self.waonPointDownload, Self.waonCharge, Self.waonPayment].flatMap { [Data($0.prefix(16)), Data($0.suffix(16))] }
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [WAONConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                WAONConstants.balanceServiceCode: [hex("5A 18 00 00 00 00 00 00 00 00 00 00 00 00 2B 00")],
                WAONConstants.numberServiceCode: [hex("68 90 12 34 56 78 90 12 00 00 00 00 00 00 00 00")],
                WAONConstants.pointsServiceCode: [hex("00 01 2C 00 00 00 00 00 00 00 00 24 03 16 00 00")],
                WAONConstants.historyServiceCode: blocks,
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await WAONReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 6234)
        #expect(result.cardName == "WAON")
        #expect(result.serialNumber == "6890123456789012")
        #expect(result.metadata["waonNumber"] == "6890123456789012")
        #expect(result.metadata["points"] == "300")
        #expect(result.transactions.map(\.date) == [jst(2024, 3, 16, 9, 5), jst(2024, 3, 15, 12, 34), jst(2024, 2, 1, 23, 59)])
        #expect(result.transactions.map(\.type) == [.topup, .purchase, .unknown])
    }

    @Test
    func `WAON without number or points services keeps the IDm`() async throws {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [WAONConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [WAONConstants.balanceServiceCode: [hex("E8 03 00 00 00 00 00 00 00 00 00 00 00 00 01 00")]],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await WAONReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 1000)
        #expect(result.serialNumber == transport.identifier.hexString)
        #expect(result.metadata["points"] == nil)
    }

    @Test
    func `WAON Wallet capture matches 77 yen and three purchases`() async throws {
        // ACR122U capture from Apple Wallet on 2026-10-31; the cardholder confirmed
        // 77 yen. Terminal identifiers are replaced with zeros; slot order is retained.
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [WAONConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                WAONConstants.balanceServiceCode: [hex("4D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04")],
                WAONConstants.historyServiceCode: [
                    Data(repeating: 0, count: 13) + hex("00 04 80"),
                    hex("3D 04 AA 65 CD 00 09 A0 03 A0 00 00 00 00 00 00"),
                    Data(repeating: 0, count: 13) + hex("00 02 7F"),
                    hex("47 04 AA 4A 43 80 5C 20 08 38 00 00 00 00 00 00"),
                    Data(repeating: 0, count: 13) + hex("00 03 AE"),
                    hex("C8 04 AA 52 0C 00 18 20 11 00 00 00 00 00 00 00"),
                ],
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await WAONReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 77)
        #expect(result.currencyCode == "JPY")
        #expect(result.transactions.map(\.type) == [.purchase, .purchase, .purchase])
        #expect(result.transactions.map(\.amount) == [116, 544, 263])
        #expect(result.transactions.map(\.balanceAfter) == [77, 193, 737])
        #expect(
            result.transactions.map(\.date) == [
                jst(2026, 4, 25, 14, 26),
                jst(2026, 4, 20, 16, 24),
                jst(2026, 4, 18, 18, 7),
            ])
        #expect(result.transactions.map { $0.metadata["cardSequence"] } == ["0004", "0003", "0002"])
    }

    // MARK: - nanaco

    @Test
    func `nanaco history types and packed dates`() throws {
        let payment = try #require(NanacoReader.parseHistoryBlock(hex("47 00 00 01 F4 00 00 04 D2 03 06 F3 22 00 2A 00")))
        #expect(payment.type == .purchase)
        #expect(payment.amount == 500)
        #expect(payment.balanceAfter == 1234)
        #expect(payment.date == jst(2024, 3, 15, 12, 34))
        #expect(payment.metadata["sequenceNumber"] == "42")

        let charge = try #require(NanacoReader.parseHistoryBlock(hex("6F 00 00 13 88 00 00 18 5A 03 07 02 45 00 2B 00")))
        #expect(charge.type == .topup)
        #expect(charge.amount == 5000)
        #expect(charge.balanceAfter == 6234)
        #expect(charge.date == jst(2024, 3, 16, 9, 5))

        let exchange = try #require(NanacoReader.parseHistoryBlock(hex("83 00 00 00 64 00 00 18 BE 03 07 02 45 00 2C 00")))
        #expect(exchange.type == .topup)
        #expect(exchange.amount == 100)
        #expect(exchange.metadata["event"] == "pointExchange")

        let transfer = try #require(NanacoReader.parseHistoryBlock(hex("35 00 00 00 64 00 00 18 BE 03 07 02 45 00 2D 00")))
        #expect(transfer.type == .unknown)
        #expect(transfer.amount == nil)
        #expect(transfer.balanceAfter == 6334)
        #expect(transfer.metadata["event"] == "transfer")
    }

    @Test
    func `Read nanaco balance, number, dates, points and history`() async throws {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [NanacoConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                NanacoConstants.balanceServiceCode: [hex("5A 18 00 00 F4 01 00 00 00 00 00 00 00 00 00 00")],
                NanacoConstants.numberServiceCode: [hex("76 00 12 34 56 78 90 12 00 00 00 00 00 00 00 00")],
                // Last use 2024-03-15, sequence 43, issued 2007-04-21.
                NanacoConstants.infoServiceCode: [hex("30 6F 00 2B 0E 95 00 00 00 00 00 00 00 00 00 00")],
                // Block 1: bucket one 120 points, bucket two 30 points.
                NanacoConstants.pointsServiceCode: [Data(repeating: 0, count: 16), hex("00 00 78 30 6F 00 00 1E 30 6F 00 00 00 00 00 00")],
                NanacoConstants.historyServiceCode: [
                    hex("6F 00 00 13 88 00 00 18 5A 03 07 02 45 00 2B 00"),
                    hex("47 00 00 01 F4 00 00 04 D2 03 06 F3 22 00 2A 00"),
                ],
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await NanacoReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 6234)
        #expect(result.cardName == "nanaco")
        #expect(result.serialNumber == "7600123456789012")
        #expect(result.metadata["nanacoNumber"] == "7600123456789012")
        #expect(result.metadata["lastUseDate"] == "2024-03-15")
        #expect(result.metadata["points"] == "150")
        #expect(result.validFrom == jst(2007, 4, 21))
        #expect(result.transactions.map(\.type) == [.topup, .purchase])
        #expect(transport.readLog.contains(["0B56:1"]))
    }

    @Test
    func `nanaco physical card capture matches 200 yen and 36 points`() async throws {
        // The cardholder confirmed 200 yen and 36 points. Keep the captured balance,
        // points and history blocks; omit card-number and metadata services.
        // The transport supplies a synthetic IDm. Points are 25 + 11, both big-endian.
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [NanacoConstants.balanceServiceCode: Data([0x00, 0x10])],
            serviceBlocks: [
                NanacoConstants.balanceServiceCode: [hex("C8 00 00 00 2C 01 00 00 00 00 00 00 00 00 2E 00")],
                NanacoConstants.pointsServiceCode: [
                    hex("01 00 34 B1 00 0C 00 00 00 00 00 00 00 00 00 00"),
                    hex("00 00 19 36 7F 00 00 0B 38 7F 00 00 00 00 00 00"),
                ],
                NanacoConstants.historyServiceCode: [
                    hex("47 00 00 01 2C 00 00 00 C8 03 50 43 C2 00 39 00"),
                    hex("47 00 00 01 2C 00 00 01 F4 03 50 43 C1 00 38 00"),
                    hex("47 00 00 02 58 00 00 03 20 03 50 43 C0 00 37 00"),
                    hex("47 00 00 01 2C 00 00 05 78 03 50 43 BB 00 36 00"),
                    hex("47 00 00 01 2C 00 00 06 A4 03 50 43 BA 00 35 00"),
                ],
            ],
            systemCode: Data([0xFE, 0x00])
        )

        let result = try await NanacoReader(transport: transport).readBalanceAndHistory()

        #expect(result.balanceRaw == 200)
        #expect(result.currencyCode == "JPY")
        #expect(result.metadata["points"] == "36")
        #expect(result.serialNumber == transport.identifier.hexString)
        #expect(result.transactions.map(\.type) == [.purchase, .purchase, .purchase, .purchase, .purchase])
        #expect(result.transactions.map(\.amount) == [300, 300, 600, 300, 300])
        #expect(result.transactions.map(\.balanceAfter) == [200, 500, 800, 1400, 1700])
        #expect(
            result.transactions.map(\.date) == [
                jst(2026, 8, 4, 15, 2),
                jst(2026, 8, 4, 15, 1),
                jst(2026, 8, 4, 15, 0),
                jst(2026, 8, 4, 14, 59),
                jst(2026, 8, 4, 14, 58),
            ])
        #expect(result.transactions.map { $0.metadata["sequenceNumber"] } == ["57", "56", "55", "54", "53"])
        #expect(transport.readLog.contains(["0B56:1"]))
    }

    // MARK: - Card checks

    @Test
    func `Readers reject other system codes and missing purse services`() async {
        let suica = MockFeliCaServiceTransport(
            serviceVersions: [EdyConstants.balanceServiceCode: Data([0x00, 0x10])],
            systemCode: Data([0x00, 0x03])
        )
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await EdyReader(transport: suica).readBalance()
        }

        let emptyCommonArea = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: Data([0xFE, 0x00]))
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await EdyReader(transport: emptyCommonArea).readBalance()
        }
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await WAONReader(transport: emptyCommonArea).readBalance()
        }
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await NanacoReader(transport: emptyCommonArea).readBalance()
        }
    }

    // MARK: - Helpers

    private static let waonPayment = Data(hexString: "30313233343536373839414243002A00 000499BD91009A400FA0000000000000")!
    private static let waonCharge = Data(hexString: "30313233343536373839414243002B00 000C99C122830B4000004E2000000000")!
    private static let waonPointDownload = Data(hexString: "30313233343536373839414243002900 00189906FD80D8C00000000000000000")!

    private func hex(_ string: String) -> Data {
        Data(hexString: string)!
    }

    private func jst(_ year: Int, _ month: Int, _ day: Int, _ hour: Int = 0, _ minute: Int = 0, _ second: Int = 0) -> Date? {
        var components = DateComponents(year: year, month: month, day: day, hour: hour, minute: minute, second: second)
        components.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return Calendar(identifier: .gregorian).date(from: components)
    }
}

/// Wraps a mock FeliCa transport and loses the tag when one service is read.
private final class SessionLossFeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    let base: MockFeliCaServiceTransport
    let failingService: Data

    init(base: MockFeliCaServiceTransport, failingService: Data) {
        self.base = base
        self.failingService = failingService
    }

    var identifier: Data { base.identifier }
    var systemCode: Data { base.systemCode }

    func send(_ data: Data) async throws -> Data {
        try await base.send(data)
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        try await base.sendAPDU(apdu)
    }

    func readWithoutEncryption(serviceCodeList: [Data], blockList: [Data]) async throws -> [Data] {
        if serviceCodeList.contains(failingService) {
            throw NFCError.tagConnectionLost
        }
        return try await base.readWithoutEncryption(serviceCodeList: serviceCodeList, blockList: blockList)
    }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        try await readWithoutEncryption(serviceCodeList: Array(repeating: serviceCode, count: blockList.count), blockList: blockList)
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        try await base.requestService(nodeCodeList: nodeCodeList)
    }
}
