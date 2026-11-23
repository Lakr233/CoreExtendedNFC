import Foundation
import Testing

@testable import CoreExtendedNFC

struct JapanRegionalTests {
    // ACR122U capture, 2026-10-31. IDm replaced; only the two populated 028F
    // records are retained. The card has eighteen further all-zero history slots.
    private let okicaHistory = [
        "160100023525DC0DDC13FA0000000350",
        "08070000351E00000000F40100000100",
    ]

    @Test
    func `Captured OKICA balance and history replay through automatic detection`() async throws {
        let transport = okicaTransport(history: okicaHistory.map(hex) + Array(repeating: Data(count: 16), count: 18))
        let result = try await CoreExtendedNFC.readTransitBalance(info: felicaInfo, transport: transport)

        #expect(result.cardName == "OKICA")
        #expect(result.currencyCode == "JPY")
        #expect(result.balanceRaw == 250)
        #expect(result.serialNumber == "0123456789ABCDEF")
        try #require(result.transactions.count == 2)
        let trip = result.transactions[0]
        #expect(trip.type == .trip)
        #expect(trip.amount == 250)
        #expect(trip.balanceAfter == 250)
        #expect(trip.entryStation == "DC0D")
        #expect(trip.exitStation == "DC13")
        #expect(trip.recordNumber == 3)
        #expect(trip.rawData == hex(okicaHistory[0]))
        #expect(trip.metadata["usageCode"] == "16010002")
        #expect(trip.metadata["mode"] == "monorail")
        #expect(trip.metadata["entryRegion"] == "3")
        #expect(trip.metadata["exitRegion"] == "3")
        try expectJSTDate(trip.date, year: 2026, month: 9, day: 5)

        let issue = result.transactions[1]
        #expect(issue.type == .topup)
        #expect(issue.amount == nil)
        #expect(issue.balanceAfter == 500)
        #expect(issue.entryStation == nil)
        #expect(issue.exitStation == nil)
        #expect(issue.recordNumber == 1)
        #expect(issue.metadata["operation"] == "New issue")
        try expectJSTDate(issue.date, year: 2026, month: 8, day: 30)
        #expect(transport.readLog.count == OKICAConstants.maxHistoryBlocks)
    }

    @Test
    func `OKICA balance only reads one block and accepts zero`() async throws {
        let transport = okicaTransport(history: okicaHistory.map(hex))
        let result = try await OKICAReader(transport: transport).readBalance()
        #expect(result.balanceRaw == 250)
        #expect(result.transactions.isEmpty)
        #expect(transport.readLog == [["8F02:0"]])

        var zero = hex(okicaHistory[0])
        zero[10] = 0
        zero[11] = 0
        #expect(try await OKICAReader(transport: okicaTransport(history: [zero])).readBalance().balanceRaw == 0)
    }

    @Test
    func `OKICA rejects other systems missing service empty latest and short latest`() async {
        let wrongSystem = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: JapanICConstants.systemCode)
        let missingService = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: OKICAConstants.systemCode)
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await OKICAReader(transport: wrongSystem).readBalance()
        }
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await OKICAReader(transport: missingService).readBalanceAndHistory()
        }
        for invalid in [Data(count: 16), Data(count: 15)] {
            await expectTransitNFCError(.invalidResponse(invalid)) {
                _ = try await OKICAReader(transport: okicaTransport(history: [invalid])).readBalanceAndHistory()
            }
        }
        await expectTransitNFCError(.felicaBlockReadFailed(statusFlag: 0xA1)) {
            _ = try await OKICAReader(transport: okicaTransport(history: [])).readBalanceAndHistory()
        }
    }

    @Test
    func `OKICA parsers accept Data slices and do not infer amounts from unused slots`() throws {
        let block = hex(okicaHistory[0])
        let wrapped = Data([0xFF]) + block
        let tx = try #require(OKICAReader.parseHistoryBlock(wrapped.dropFirst(), previousBlock: Data(count: 16)))
        #expect(tx.balanceAfter == 250)
        #expect(tx.amount == nil)
        #expect(OKICAReader.parseBalance(Data(count: 15)) == nil)
        #expect(OKICAReader.parseHistoryBlock(Data(count: 16)) == nil)
        #expect(OKICAReader.parseHistoryBlock(block, previousBlock: Data(count: 11))?.amount == nil)
    }

    @Test
    func `OKICA types distinguish trips top-ups and unknown operations`() throws {
        let older = hex(okicaHistory[1]) // 500 yen
        for usage: UInt32 in [0x0802_0000, 0x0848_0000, 0x0848_0400, 0x051F_0000, 0x1F1F_0000, 0x0807_0000] {
            let block = okicaBlock(usage: usage, balance: 800)
            let tx = try #require(OKICAReader.parseHistoryBlock(block, previousBlock: older))
            #expect(tx.type == .topup)
            #expect(tx.amount == 300)
            #expect(tx.entryStation == nil)
            #expect(tx.exitStation == nil)
        }
        let bus = try #require(OKICAReader.parseHistoryBlock(okicaBlock(usage: 0x050F_000F, balance: 250), previousBlock: older))
        #expect(bus.type == .trip)
        #expect(bus.amount == 250)
        #expect(bus.entryStation == nil)
        #expect(bus.exitStation == nil)
        #expect(bus.metadata["mode"] == "bus")
        #expect(bus.metadata["entryLocationCode"] == "DC0D")
        #expect(bus.metadata["exitLocationCode"] == "DC13")

        let unknown = try #require(OKICAReader.parseHistoryBlock(okicaBlock(usage: 0xABCD_EF01, balance: 250), previousBlock: older))
        #expect(unknown.type == .unknown)
        #expect(unknown.amount == nil)
        #expect(unknown.metadata["usageCode"] == "ABCDEF01")
        #expect(unknown.rawData != nil)
        #expect(OKICAReader.parseHistoryBlock(okicaBlock(usage: 0x1601_0002, balance: 800), previousBlock: older)?.amount == nil)
        #expect(OKICAReader.parseHistoryBlock(okicaBlock(usage: 0x0802_0000, balance: 250), previousBlock: older)?.amount == nil)
    }

    @Test
    func `OKICA oldest record survives refused later block without an invented amount`() async throws {
        let transport = okicaTransport(history: [hex(okicaHistory[0])])
        let result = try await OKICAReader(transport: transport).readBalanceAndHistory()
        #expect(result.transactions.count == 1)
        #expect(result.transactions.first?.amount == nil)
        #expect(result.balanceRaw == 250)
    }

    @Test
    func `IruCa PASPY and SAPICA route to their own systems and retain history`() async throws {
        for (code, name) in [
            (JapanICConstants.irucaSystemCode, "IruCa"),
            (JapanICConstants.paspySystemCode, "PASPY"),
            (JapanICConstants.sapicaSystemCode, "SAPICA"),
        ] {
            let transport = regionalTransport(systemCode: code)
            let result = try await CoreExtendedNFC.readTransitBalance(info: felicaInfo, transport: transport)
            #expect(result.cardName == name)
            #expect(result.balanceRaw == 1234)
            #expect(result.currencyCode == "JPY")
            #expect(result.transactions.count == 1)
            #expect(result.transactions.first?.balanceAfter == 1234)
            #expect(result.transactions.first?.entryStation == "0123")
            #expect(result.transactions.first?.exitStation == "0456")
            #expect(result.metadata["points"] == nil)
        }
    }

    @Test
    func `Hayakaken is identified by advertised 927A while reading CJRC balance and history`() async throws {
        let base = regionalTransport(systemCode: JapanICConstants.systemCode)
        let transport = AdvertisedSystemsTransport(
            base: base,
            systemCodes: [hex("0003"), hex("FE00"), hex("927A")]
        )
        let result = try await CoreExtendedNFC.readTransitBalance(info: felicaInfo, transport: transport)
        #expect(result.cardName == "Hayakaken")
        #expect(result.balanceRaw == 1234)
        #expect(result.transactions.count == 1)
        #expect(result.transactions.first?.entryStation == "0123")
        #expect(result.transactions.first?.exitStation == "0456")
        #expect(base.readLog.flatMap { $0 }.allSatisfy { $0.hasPrefix("8B00:") || $0.hasPrefix("0F09:") })

        let balanceOnly = try await JapanICReader(transport: transport).readBalance()
        #expect(balanceOnly.cardName == "Hayakaken")
        #expect(balanceOnly.balanceRaw == 1234)
        #expect(balanceOnly.transactions.isEmpty)
    }

    @Test
    func `CJRC keeps its generic name without a valid Hayakaken marker`() async throws {
        for codes: [Data] in [
            [],
            [hex("0003")],
            [hex("0003"), hex("86A7")],
            [hex("0003"), hex("7A92")],
            [hex("0003"), hex("92")],
            [hex("927A"), hex("000300")],
        ] {
            let transport = AdvertisedSystemsTransport(
                base: regionalTransport(systemCode: JapanICConstants.systemCode),
                systemCodes: codes
            )
            #expect(try await JapanICReader(transport: transport).readBalance().cardName == "Japan IC")
        }
    }

    @Test
    func `Optional issuer lookup tolerates refusal but propagates session loss and cancellation`() async throws {
        let base = regionalTransport(systemCode: JapanICConstants.systemCode)
        // Existing conformers inherit unsupported enumeration and keep working.
        #expect(try await JapanICReader(transport: base).readBalance().cardName == "Japan IC")
        for error in [
            NFCError.unsupportedOperation("no system enumeration"),
            NFCError.invalidResponse(Data()),
            NFCError.felicaBlockReadFailed(statusFlag: 0xA1),
        ] {
            let transport = AdvertisedSystemsTransport(base: base, enumerationError: error)
            #expect(try await JapanICReader(transport: transport).readBalanceAndHistory().cardName == "Japan IC")
        }
        for error in [NFCError.tagConnectionLost, .userCanceled] {
            let transport = AdvertisedSystemsTransport(base: base, enumerationError: error)
            await expectTransitNFCError(error) {
                _ = try await JapanICReader(transport: transport).readBalanceAndHistory()
            }
        }
        let cancelled = AdvertisedSystemsTransport(base: base, enumerationError: CancellationError())
        await #expect(throws: CancellationError.self) {
            _ = try await JapanICReader(transport: cancelled).readBalance()
        }
    }

    @Test
    func `Issuer marker is not treated as a balance system and regional names do not enumerate`() async throws {
        let markerOnly = regionalTransport(systemCode: JapanICConstants.hayakakenSystemCode)
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await CoreExtendedNFC.readTransitBalance(info: felicaInfo, transport: markerOnly)
        }
        let iruca = AdvertisedSystemsTransport(
            base: regionalTransport(systemCode: JapanICConstants.irucaSystemCode),
            systemCodes: [JapanICConstants.hayakakenSystemCode],
            enumerationError: CancellationError()
        )
        #expect(try await JapanICReader(transport: iruca).readBalance().cardName == "IruCa")
    }

    @Test
    func `SAPICA points use all three little-endian bytes and preserve zero`() async throws {
        for points in [0, 0x123456] {
            var block = Data(count: 16)
            block[0] = UInt8(points & 0xFF)
            block[1] = UInt8(points >> 8 & 0xFF)
            block[2] = UInt8(points >> 16)
            let transport = regionalTransport(systemCode: JapanICConstants.sapicaSystemCode, pointsBlock: block)
            let result = try await JapanICReader(transport: transport).readBalanceAndHistory()
            #expect(result.metadata["points"] == String(points))
        }
        let balanceOnly = try await JapanICReader(
            transport: regionalTransport(systemCode: JapanICConstants.sapicaSystemCode, pointsBlock: Data(count: 16))
        ).readBalance()
        #expect(balanceOnly.metadata["points"] == "0")
        let short = try await JapanICReader(
            transport: regionalTransport(systemCode: JapanICConstants.sapicaSystemCode, pointsBlock: Data(count: 2))
        ).readBalance()
        #expect(short.metadata.isEmpty)
    }

    @Test
    func `Session loss and cancellation propagate from OKICA history and optional SAPICA points`() async {
        let okica = RegionalFailureTransport(
            base: okicaTransport(history: okicaHistory.map(hex)),
            failingService: OKICAConstants.historyServiceCode,
            failingBlock: 1,
            failure: NFCError.tagConnectionLost
        )
        await expectTransitNFCError(.tagConnectionLost) {
            _ = try await OKICAReader(transport: okica).readBalanceAndHistory()
        }
        let sapica = RegionalFailureTransport(
            base: regionalTransport(systemCode: JapanICConstants.sapicaSystemCode),
            failingService: JapanICConstants.sapicaPointsServiceCode,
            failingBlock: 0,
            failure: NFCError.tagConnectionLost
        )
        await expectTransitNFCError(.tagConnectionLost) {
            _ = try await JapanICReader(transport: sapica).readBalanceAndHistory()
        }
        let cancelled = RegionalFailureTransport(
            base: okicaTransport(history: okicaHistory.map(hex)),
            failingService: OKICAConstants.historyServiceCode,
            failingBlock: 1,
            failure: CancellationError()
        )
        await #expect(throws: CancellationError.self) {
            _ = try await OKICAReader(transport: cancelled).readBalanceAndHistory()
        }
        let cancelledPoints = RegionalFailureTransport(
            base: regionalTransport(systemCode: JapanICConstants.sapicaSystemCode),
            failingService: JapanICConstants.sapicaPointsServiceCode,
            failingBlock: 0,
            failure: CancellationError()
        )
        await #expect(throws: CancellationError.self) {
            _ = try await JapanICReader(transport: cancelledPoints).readBalance()
        }
    }

    private var felicaInfo: CardInfo {
        CardInfo(type: .felicaStandard, uid: hex("0123456789ABCDEF"))
    }

    private func okicaTransport(history: [Data]) -> MockFeliCaServiceTransport {
        MockFeliCaServiceTransport(
            serviceVersions: [OKICAConstants.historyServiceCode: Data([0x00, 0x00])],
            serviceBlocks: [OKICAConstants.historyServiceCode: history],
            systemCode: OKICAConstants.systemCode
        )
    }

    private func regionalTransport(systemCode: Data, pointsBlock: Data? = nil) -> MockFeliCaServiceTransport {
        var services = [
            JapanICConstants.balanceServiceCode: [hex("0000000000000000000000D204000000")],
            JapanICConstants.historyServiceCode: [hex("16010002352501230456D20400000300")],
        ]
        if let pointsBlock { services[JapanICConstants.sapicaPointsServiceCode] = [pointsBlock] }
        return MockFeliCaServiceTransport(
            serviceVersions: [JapanICConstants.balanceServiceCode: Data([0x00, 0x00])],
            serviceBlocks: services,
            systemCode: systemCode
        )
    }

    private func okicaBlock(usage: UInt32, balance: Int) -> Data {
        var block = hex(okicaHistory[0])
        for index in 0 ..< 4 { block[index] = UInt8(usage >> ((3 - index) * 8) & 0xFF) }
        block[10] = UInt8(balance & 0xFF)
        block[11] = UInt8(balance >> 8)
        return block
    }

    private func expectJSTDate(_ date: Date?, year: Int, month: Int, day: Int) throws {
        let components = Calendar(identifier: .gregorian).dateComponents(
            in: try #require(TimeZone(identifier: "Asia/Tokyo")), from: try #require(date)
        )
        #expect(components.year == year)
        #expect(components.month == month)
        #expect(components.day == day)
    }

    private func hex(_ text: String) -> Data {
        Data(
            stride(from: 0, to: text.count, by: 2).map { offset in
                let start = text.index(text.startIndex, offsetBy: offset)
                return UInt8(text[start ..< text.index(start, offsetBy: 2)], radix: 16)!
            })
    }
}

/// Supplies advertised systems independently of the selected balance system.
private struct AdvertisedSystemsTransport: FeliCaTagTransporting {
    let base: MockFeliCaServiceTransport
    var systemCodes: [Data] = []
    var enumerationError: (any Error)?
    var identifier: Data { base.identifier }
    var systemCode: Data { base.systemCode }

    func requestSystemCode() async throws -> [Data] {
        if let enumerationError { throw enumerationError }
        return systemCodes
    }

    func send(_ data: Data) async throws -> Data { try await base.send(data) }
    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU { try await base.sendAPDU(apdu) }
    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        try await base.requestService(nodeCodeList: nodeCodeList)
    }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        try await base.readWithoutEncryption(serviceCode: serviceCode, blockList: blockList)
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}
}

/// Immutable failure injection at a particular service and slot.
private struct RegionalFailureTransport: FeliCaTagTransporting {
    let base: MockFeliCaServiceTransport
    let failingService: Data
    let failingBlock: UInt8
    let failure: any Error
    var identifier: Data { base.identifier }
    var systemCode: Data { base.systemCode }

    func send(_ data: Data) async throws -> Data { try await base.send(data) }
    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU { try await base.sendAPDU(apdu) }
    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        try await base.requestService(nodeCodeList: nodeCodeList)
    }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        if serviceCode == failingService, blockList.first?.last == failingBlock { throw failure }
        return try await base.readWithoutEncryption(serviceCode: serviceCode, blockList: blockList)
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}
}
