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
    func `Read Octopus balance`() async throws {
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
            scanDate: date(year: 2026, month: 5, day: 9),
        ).readBalance()

        #expect(result.balanceRaw == 41190)
        #expect(result.currencyCode == "HKD")
        #expect(result.cardName == "Octopus")
        #expect(result.formattedBalance == "HK$411.90")
    }

    @Test
    func `Octopus offset follows scan date`() {
        #expect(OctopusConstants.balanceRawOffset(for: date(year: 2017, month: 9, day: 30)) == 350)
        #expect(OctopusConstants.balanceRawOffset(for: date(year: 2017, month: 10, day: 1)) == 500)
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

    private func date(year: Int, month: Int, day: Int) -> Date {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(identifier: "Asia/Hong_Kong")
        components.year = year
        components.month = month
        components.day = day
        return components.date!
    }
}
