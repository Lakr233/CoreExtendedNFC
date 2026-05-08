// Hong Kong Octopus FeliCa transit card tests.
//
// ## References
// - System code: 0x8008
// - Balance service: 0x0117, encoded as 17 01 for CoreNFC
// - Balance block: first 4 bytes big-endian raw value
// - Current balance: (raw - offset) * 10 HKD cents
@testable import CoreExtendedNFC
import Foundation
import Testing

struct OctopusTests {
    @Test
    func `Read Octopus balance defaults to physical card offset`() async throws {
        let transport = octopusTransport(rawValue: 920)

        let result = try await OctopusReader(transport: transport).readBalance()

        #expect(result.balanceRaw == 5700)
        #expect(result.currencyCode == "HKD")
        #expect(result.cardName == "Octopus")
        #expect(result.formattedBalance == "HK$57.00")
    }

    @Test
    func `Logged Octopus card replays physical card balance block`() async throws {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x17, 0x01]): Data([0x07, 0x00])],
            serviceBlocks: [
                Data([0x17, 0x01]): [hexToData("00000398000000000000000000000003")],
            ],
            systemCode: Data([0x80, 0x08]),
            identifier: hexToData("010107015823C200"),
        )

        let result = try await OctopusReader(transport: transport).readBalance()

        #expect(result.serialNumber == "010107015823C200")
        #expect(result.balanceRaw == 5700)
        #expect(result.formattedBalance == "HK$57.00")
    }

    @Test
    func `Read Octopus balance uses Y Mobile and CardBal raw offset`() async throws {
        var block = Data(repeating: 0x00, count: 16)
        block[0] = 0x00
        block[1] = 0x00
        block[2] = 0x12
        block[3] = 0x0B // 4619 raw -> (4619 - 350) * 10 = 42690 cents

        let transport = MockFeliCaServiceTransport(
            serviceVersions: [Data([0x17, 0x01]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x17, 0x01]): [block]],
            systemCode: Data([0x80, 0x08]),
        )

        let result = try await OctopusReader(
            transport: transport,
            balanceOffset: OctopusConstants.defaultBalanceRawOffset,
        ).readBalance()

        #expect(result.balanceRaw == 42690)
        #expect(result.currencyCode == "HKD")
        #expect(result.cardName == "Octopus")
        #expect(result.formattedBalance == "HK$426.90")
    }

    @Test
    func `Octopus pre-2017 offset remains available`() {
        let cents = OctopusReader.balanceCents(
            rawValue: 4557,
            offset: OctopusConstants.legacyBalanceRawOffset,
        )

        #expect(cents == 42070)
    }

    @Test
    func `Octopus system code mismatch throws error`() async {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [:],
            systemCode: Data([0x00, 0x03]),
        )

        await #expect(throws: NFCError.self) {
            _ = try await OctopusReader(transport: transport).readBalance()
        }
    }

    private func octopusTransport(rawValue: UInt32) -> MockFeliCaServiceTransport {
        var block = Data(repeating: 0x00, count: 16)
        block[0] = UInt8((rawValue >> 24) & 0xFF)
        block[1] = UInt8((rawValue >> 16) & 0xFF)
        block[2] = UInt8((rawValue >> 8) & 0xFF)
        block[3] = UInt8(rawValue & 0xFF)

        return MockFeliCaServiceTransport(
            serviceVersions: [Data([0x17, 0x01]): Data([0x00, 0x10])],
            serviceBlocks: [Data([0x17, 0x01]): [block]],
            systemCode: Data([0x80, 0x08]),
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
