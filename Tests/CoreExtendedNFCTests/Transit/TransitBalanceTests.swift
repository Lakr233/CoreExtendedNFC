import Foundation
import Testing

@testable import CoreExtendedNFC

struct TransitBalanceTests {
    @Test
    func `Formats TWD balance`() {
        let balance = TransitBalance(
            serialNumber: "",
            balanceRaw: 245,
            currencyCode: "TWD",
            cardName: "EasyCard"
        )

        #expect(balance.formattedBalance == "NT$245")
    }

    @Test
    func `Balances encoded before tap events decode with none`() throws {
        let oldJSON = Data(
            #"{"serialNumber":"","balanceRaw":5000,"currencyCode":"KRW","cardName":"T-Money","transactions":[{"type":"trip","amount":1250,"metadata":{}}],"metadata":{}}"#.utf8
        )
        let balance = try JSONDecoder().decode(TransitBalance.self, from: oldJSON)
        #expect(balance.tapEvents.isEmpty)
        let transaction = try #require(balance.transactions.first)
        #expect(transaction.amount == 1250)
        #expect(transaction.mode == nil)
        #expect(transaction.event == nil)
        #expect(transaction.distanceMeters == nil)
    }

    @Test
    func `Tap events and transport fields survive a coding round trip`() throws {
        let tap = TransitTransaction(
            type: .trip,
            exitStation: "00000290",
            mode: .rail,
            event: .tapOff,
            distanceMeters: 12900,
            recordNumber: 2
        )
        let balance = TransitBalance(
            serialNumber: "",
            balanceRaw: 5000,
            currencyCode: "KRW",
            cardName: "T-Money",
            transactions: [TransitTransaction(type: .trip, amount: 100, mode: .bus)],
            tapEvents: [tap]
        )
        let data = try JSONEncoder().encode(balance)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains(#""mode":"rail""#))
        #expect(json.contains(#""event":"tapOff""#))
        #expect(try JSONDecoder().decode(TransitBalance.self, from: data) == balance)
    }
    @Test
    func `Automatic detection reaches T-Union after Singapore and Korea reject selection`() async throws {
        let transport = MockTransport()
        let notFound = ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
        transport.apduResponses =
            Array(repeating: notFound, count: 1 + KSX6924Constants.allAIDs.count) + [
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // T-Union SELECT
                ResponseAPDU(data: Data([0, 0, 0x13, 0x88]), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data([0, 0, 0, 0]), sw1: 0x90, sw2: 0x00),
                notFound, // SELECT file 0015
                notFound, // SFI 15
                notFound, // SFI 18 history
                notFound, // SFI 1E history
            ]
        let info = CardInfo(type: .smartMX, uid: transport.identifier)

        let result = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)

        #expect(result.cardName == "T-Union")
        #expect(result.currencyCode == "CNY")
        #expect(result.balanceRaw == 5000)
        #expect(transport.sentAPDUs[1 + KSX6924Constants.allAIDs.count].data == TUnionConstants.tUnionAID)
    }

    @Test
    func `Automatic detection keeps FeliCa on the Japan IC path`() async throws {
        var block = Data(repeating: 0, count: 16)
        block[0x0B] = 0xD2
        block[0x0C] = 0x04
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x8B, 0x00]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x8B, 0x00]): [block]],
            systemCode: Data([0x00, 0x03])
        )
        let info = CardInfo(type: .felicaStandard, uid: transport.identifier)

        let result = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)

        #expect(result.cardName == "Japan IC")
        #expect(result.currencyCode == "JPY")
        #expect(result.balanceRaw == 1234)
    }

    @Test
    func `Automatic detection picks the common area purse by its balance service`() async throws {
        let purses: [(service: Data, name: String)] = [
            (EdyConstants.balanceServiceCode, "Rakuten Edy"),
            (WAONConstants.balanceServiceCode, "WAON"),
            (NanacoConstants.balanceServiceCode, "nanaco"),
        ]
        for purse in purses {
            var block = Data(repeating: 0, count: 16)
            block[0] = 0xE8
            block[1] = 0x03
            let transport = MockFeliCaServiceTransport(
                serviceVersions: [purse.service: Data([0x00, 0x10])],
                serviceBlocks: [purse.service: [block]],
                systemCode: Data([0xFE, 0x00])
            )
            let info = CardInfo(type: .felicaStandard, uid: transport.identifier)

            let result = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)

            #expect(result.cardName == purse.name)
            #expect(result.currencyCode == "JPY")
            #expect(result.balanceRaw == 1000)
        }
    }

    // MARK: - Typed detection errors

    @Test
    func `Readers report a missing AID as applicationNotFound`() async {
        let notFound = ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
        let tUnion = MockTransport()
        tUnion.apduResponses = [notFound]
        await expectTransitNFCError(.applicationNotFound(aid: TUnionConstants.tUnionAID)) {
            _ = try await TUnionReader(transport: tUnion).readBalance()
        }

        let korea = MockTransport()
        korea.apduResponses = Array(repeating: notFound, count: KSX6924Constants.allAIDs.count)
        await expectTransitNFCError(.applicationNotFound(aid: KSX6924Constants.tMoneyAID)) {
            _ = try await KSX6924Reader(transport: korea).readBalance()
        }
    }

    @Test
    func `Automatic detection reports an unknown card as tagNotSupported`() async {
        let transport = MockTransport()
        let notFound = ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
        transport.apduResponses = Array(repeating: notFound, count: 2 + KSX6924Constants.allAIDs.count)
        let info = CardInfo(type: .smartMX, uid: transport.identifier)
        // before: unsupportedOperation("No supported transit card detected")
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
        }
    }

    @Test
    func `Automatic detection does not swallow a reader-level failure on T-Union`() async {
        let transport = MockTransport()
        let notFound = ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
        transport.apduResponses = Array(repeating: notFound, count: 1 + KSX6924Constants.allAIDs.count)
        // T-Union SELECT fails with a mapped CoreNFC error instead of a status word.
        transport.apduFailures = [1 + KSX6924Constants.allAIDs.count: .unsupportedOperation("NFC access was not granted")]
        let info = CardInfo(type: .smartMX, uid: transport.identifier)
        // before: swallowed and reported as "No supported transit card detected"
        await expectTransitNFCError(.unsupportedOperation("NFC access was not granted")) {
            _ = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
        }
    }

    @Test
    func `FeliCa cards outside the supported transit systems report tagNotSupported`() async {
        let unknownSystem = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: Data([0x12, 0xFC]))
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await CoreExtendedNFC.readTransitBalance(
                info: CardInfo(type: .felicaStandard, uid: unknownSystem.identifier),
                transport: unknownSystem
            )
        }
        let noBalanceService = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: Data([0x00, 0x03]))
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await JapanICReader(transport: noBalanceService).readBalance()
        }
        let noPurse = MockFeliCaServiceTransport(serviceVersions: [:], systemCode: Data([0xFE, 0x00]))
        await expectTransitNFCError(.tagNotSupported) {
            _ = try await CoreExtendedNFC.readTransitBalance(
                info: CardInfo(type: .felicaStandard, uid: noPurse.identifier),
                transport: noPurse
            )
        }
    }
}

/// Expect `body` to throw exactly `expected` (compared by case and associated values).
func expectTransitNFCError(
    _ expected: NFCError,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ body: () async throws -> Void
) async {
    let error = await #expect(throws: NFCError.self, sourceLocation: sourceLocation) {
        try await body()
    }
    #expect(error.map { "\($0)" } == "\(expected)", sourceLocation: sourceLocation)
}
