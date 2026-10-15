// DESFire response parsing regression tests.
//
// Public provenance:
// - NXP AN11004, "MIFARE DESFire as Type 4 Tag", section 5.1, shows the
//   wrapped native-command transport used by these response parsers.
//   https://www.nxp.com/docs/en/application-note/AN11004.pdf
//
// These tests lock strict response sizing so malformed DESFire payloads do not
// get truncated or partially accepted by higher-level read flows.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DESFireResponseParsingTests {
    @Test
    func `GET_APPLICATION_IDS rejects trailing partial AID`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x01, 0x00, 0x00, 0x02]), sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        await expectInvalidResponse {
            _ = try await commands.getApplicationIDs()
        }
    }

    @Test
    func `GET_VALUE rejects trailing bytes`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x78, 0x56, 0x34, 0x12, 0x00]), sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        await expectInvalidResponse {
            _ = try await commands.getValue(fileID: 0x01)
        }
    }

    @Test
    func `GET_VALUE decodes exact 4-byte signed little-endian payload`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0xEF, 0xCD, 0xAB, 0x89]), sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let value = try await commands.getValue(fileID: 0x02)

        #expect(value == -1_985_229_329)
        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs[0].ins == DESFireCommands.GET_VALUE)
        #expect(mock.sentAPDUs[0].data == Data([0x02]))
    }

    @Test
    func `GET_VERSION accepts a trailing FabKey ID byte`() throws {
        // NTAG 424 DNA / newer DESFire parts may append an optional FabKey ID
        // byte to the third GetVersion frame, giving 29 bytes in total.
        var data = Data(repeating: 0x00, count: 29)
        data[3] = 0x33
        data[27] = 0x21 // production year
        data[28] = 0x1F // FabKey ID
        let info = try DESFireVersionInfo(data: data)
        #expect(info.productionYear == 0x21)
        #expect(info.cardType == .mifareDesfireEV3)
    }

    @Test
    func `GET_VERSION rejects responses shorter than 28 bytes`() throws {
        let data = Data(repeating: 0x00, count: 27)
        do {
            _ = try DESFireVersionInfo(data: data)
            #expect(Bool(false), "Expected invalidResponse")
        } catch let error as NFCError {
            if case let .invalidResponse(actual) = error {
                #expect(actual == data)
            } else {
                #expect(Bool(false), "Unexpected NFCError: \(error)")
            }
        }
    }

    private func expectInvalidResponse(
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            #expect(Bool(false), "Expected invalidResponse")
        } catch let error as NFCError {
            if case .invalidResponse = error {
                #expect(Bool(true))
            } else {
                #expect(Bool(false), "Unexpected NFCError: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }
}
