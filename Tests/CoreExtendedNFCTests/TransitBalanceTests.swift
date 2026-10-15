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
}
