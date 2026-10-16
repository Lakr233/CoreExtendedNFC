// Secure Messaging (SM) test suite for 3DES-based BAC channel.
//
// ## References
// - ICAO Doc 9303 Part 11, Section 9.8: Secure Messaging
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - ICAO Doc 9303 Part 11, Section 9.8.6: DO'87 (encrypted data), DO'99 (SW), DO'8E (MAC)
// - ICAO Doc 9303 Part 11, Section 9.8.4: CLA masking to 0x0C
// - ISO/IEC 7816-4: SM structure (DO'87, DO'97, DO'99, DO'8E)
// - JMRTD DESedeSecureMessagingWrapper.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/DESedeSecureMessagingWrapper.java
@testable import CoreExtendedNFC
import Foundation
import Testing

struct SecureMessagingTests {
    @Test
    func `SecureMessaging identifier delegates to underlying transport`() {
        let mockID = Data([0x04, 0x01, 0x02, 0x03])
        let mock = MockTransport(identifier: mockID)
        let ksEnc = Data(repeating: 0x01, count: 16)
        let ksMac = Data(repeating: 0x02, count: 16)
        let ssc = Data(repeating: 0x00, count: 8)

        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc
        )

        #expect(sm.identifier == mockID)
    }

    @Test
    func `SecureMessaging raw send throws unsupportedOperation`() async throws {
        let mock = MockTransport()
        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: Data(repeating: 0x01, count: 16),
            ksMac: Data(repeating: 0x02, count: 16),
            ssc: Data(repeating: 0x00, count: 8)
        )

        await #expect(throws: NFCError.self) {
            _ = try await sm.send(Data([0x01, 0x02]))
        }
    }

    @Test
    func `SecureMessaging protect produces valid APDU with DO'8E MAC`() async throws {
        // Use known session keys to verify the protected APDU contains a DO'8E MAC
        let ksEnc = Data([
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF,
            0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2,
        ])
        let ksMac = Data([
            0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD,
            0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43,
        ])
        let ssc = Data(repeating: 0x00, count: 8)

        let mock = MockTransport()

        // We need the mock to respond with a valid SM response.
        // Build a response that contains DO'99 and DO'8E.
        // For a simple SELECT with success, the response would be:
        // DO'99 = [99 02 90 00] — success status word
        // DO'8E = [8E 08 <mac>] — 8-byte MAC

        // To compute the correct MAC, we need to know the SSC value at response time.
        // SSC after command: 00..01, SSC after response: 00..02
        // The response MAC input = pad(SSC_resp || DO'99)
        var responseSsc = Data(repeating: 0x00, count: 7)
        responseSsc.append(0x02) // SSC incremented twice

        let do99 = Data([0x99, 0x02, 0x90, 0x00])
        var macInput = responseSsc
        macInput.append(do99)
        let paddedMacInput = ISO9797Padding.pad(macInput, blockSize: 8)
        let responseMac = try ISO9797MAC.mac(key: ksMac, message: paddedMacInput)

        var smResponse = do99
        smResponse.append(0x8E)
        smResponse.append(0x08)
        smResponse.append(responseMac)

        mock.apduResponses = [
            ResponseAPDU(data: smResponse, sw1: 0x90, sw2: 0x00),
        ]

        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc
        )

        // Send a simple SELECT APDU
        let selectAPDU = CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
        )

        let response = try await sm.sendAPDU(selectAPDU)

        // The unprotected response should show success
        #expect(response.isSuccess)

        // Verify the sent APDU was a protected version
        let sentAPDU = mock.sentAPDUs[0]
        #expect(sentAPDU.cla == 0x0C) // Masked CLA
        #expect(sentAPDU.ins == 0xA4)
        // Protected data should contain DO'87 (encrypted data) + DO'8E (MAC)
        #expect(sentAPDU.data != nil)
        // The data should contain a 0x8E tag (MAC)
        let sentData = try #require(sentAPDU.data)
        #expect(sentData.contains(0x8E))
    }

    @Test
    func `Cancellation between GET RESPONSE frames ends the secure messaging session`() async throws {
        let chip = CancelOnFirstCommandTransport()
        let sm = SecureMessagingTransport(
            transport: chip,
            ksEnc: Data(repeating: 0x01, count: 16),
            ksMac: Data(repeating: 0x02, count: 16),
            ssc: Data(repeating: 0x00, count: 8)
        )
        let readBinary = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x10)

        // The chip answers 61xx; the task is cancelled before GET RESPONSE, so the chip has
        // consumed the response SSC while the transport has not.
        let first = Task { try await sm.sendAPDU(readBinary) }
        await #expect(throws: CancellationError.self) { _ = try await first.value }
        #expect(chip.commandCount == 1)

        // Any later command would carry a stale SSC: it must be refused, not sent.
        let error = await #expect(throws: NFCError.self) { _ = try await sm.sendAPDU(readBinary) }
        guard case .secureMessagingError? = error else {
            Issue.record("Expected secureMessagingError, got \(String(describing: error))")
            return
        }
        #expect(chip.commandCount == 1)
    }
}

/// Answers the first command with 61 10 (more data) and cancels the calling task.
private final class CancelOnFirstCommandTransport: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x01, 0x02, 0x03])
    private(set) var commandCount = 0

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw transport is not used")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        commandCount += 1
        withUnsafeCurrentTask { $0?.cancel() }
        return ResponseAPDU(data: Data(), sw1: 0x61, sw2: 0x10)
    }
}
