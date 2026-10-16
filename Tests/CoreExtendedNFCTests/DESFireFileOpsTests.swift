// DESFire file-operation regression tests.
//
// Public provenance:
// - NXP AN11004, "MIFARE DESFire as Type 4 Tag", section 5.1, shows the
//   wrapped native-command APDU form used by these tests.
//   https://www.nxp.com/docs/en/application-note/AN11004.pdf
//
// The 3-byte little-endian offset/length/count payloads here are locked as
// interoperability behavior so oversized UInt32 inputs cannot be truncated
// silently before they reach the card.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DESFireFileOpsTests {
    @Test
    func `READ_DATA encodes 24-bit offset and length little-endian`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0xAA]), sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        _ = try await commands.readData(fileID: 0x09, offset: 0x123456, length: 0xABCDEF)

        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs[0].ins == DESFireCommands.READ_DATA)
        #expect(mock.sentAPDUs[0].data == Data([0x09, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB]))
    }

    @Test
    func `READ_RECORDS encodes 24-bit offset and count little-endian`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0xBB]), sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        _ = try await commands.readRecords(fileID: 0x07, offset: 0x010203, count: 0xA0B0C0)

        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs[0].ins == DESFireCommands.READ_RECORDS)
        #expect(mock.sentAPDUs[0].data == Data([0x07, 0x03, 0x02, 0x01, 0xC0, 0xB0, 0xA0]))
    }

    @Test
    func `READ_DATA rejects offsets larger than 24 bits`() async {
        let mock = MockTransport()
        let commands = DESFireCommands(transport: mock)

        await expectInvalidParameter(
            containing: "offset",
            while: {
                _ = try await commands.readData(fileID: 0x01, offset: 0x0100_0000, length: 0)
            }
        )

        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `READ_RECORDS rejects counts larger than 24 bits`() async {
        let mock = MockTransport()
        let commands = DESFireCommands(transport: mock)

        await expectInvalidParameter(
            containing: "count",
            while: {
                _ = try await commands.readRecords(fileID: 0x01, offset: 0, count: 0x0100_0000)
            }
        )

        #expect(mock.sentAPDUs.isEmpty)
    }

    private func expectInvalidParameter(
        containing fragment: String,
        while operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            #expect(Bool(false), "Expected invalidParameter containing \(fragment)")
        } catch let error as NFCError {
            if case let .invalidParameter(message) = error {
                #expect(message.contains(fragment))
                #expect(message.contains("0xFFFFFF"))
            } else {
                #expect(Bool(false), "Unexpected NFCError: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }
}
