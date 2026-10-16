@testable import CoreExtendedNFC
import Foundation
import Testing

/// The transports log every exchange through `NFCLog.apduCommand` / `apduResponse`
/// / `rawCommand` / `rawResponse`. These tests replay real reader traffic (captured
/// with mock transports) through those functions into a spy logger, passing the
/// logger and payload flag explicitly so no global state is shared between tests.
struct LogRedactionTests {
    // MARK: - Helpers

    private static func replayAPDUs(
        _ transport: MockTransport,
        responses: [ResponseAPDU],
        logPayloads: Bool
    ) -> [String] {
        let spy = SpyNFCLogger()
        for (apdu, response) in zip(transport.sentAPDUs, responses) {
            NFCLog.apduCommand(apdu, source: "Test", logger: spy, logPayloads: logPayloads)
            NFCLog.apduResponse(
                data: response.data,
                sw1: response.sw1,
                sw2: response.sw2,
                for: apdu,
                source: "Test",
                logger: spy,
                logPayloads: logPayloads
            )
        }
        return spy.messages
    }

    private static func replayRaw(
        commands: [Data],
        responses: [Data],
        logPayloads: Bool
    ) -> [String] {
        let spy = SpyNFCLogger()
        for (command, response) in zip(commands, responses) {
            NFCLog.rawCommand(command, family: .mifare, source: "Test", logger: spy, logPayloads: logPayloads)
            NFCLog.rawResponse(
                response,
                command: command,
                family: .mifare,
                source: "Test",
                logger: spy,
                logPayloads: logPayloads
            )
        }
        return spy.messages
    }

    private static func contains(_ messages: [String], _ bytes: Data) -> Bool {
        let joined = messages.joined(separator: "\n")
        return joined.contains(bytes.hexDump) || joined.contains(bytes.hexString)
    }

    // MARK: - My Number VERIFY

    private static func myNumberSession() async throws -> (MockTransport, [ResponseAPDU]) {
        let transport = MockTransport()
        let payload = Data([0x10, 0x01, 0x0C]) + Data("987654321098".utf8) + Data([0x00, 0x00])
        let responses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AP
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0011
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3), // VERIFY (empty)
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // VERIFY PIN
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0001
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00), // READ BINARY
        ]
        transport.apduResponses = responses
        _ = try await MyNumberCardReader(transport: transport)
            .readIndividualNumber(cardInfoInputSupportPIN: "1234")
        return (transport, responses)
    }

    @Test
    func `My Number PIN never appears in logs`() async throws {
        let (transport, responses) = try await Self.myNumberSession()
        let pin = Data([0x31, 0x32, 0x33, 0x34])

        for logPayloads in [false, true] {
            let messages = Self.replayAPDUs(transport, responses: responses, logPayloads: logPayloads)
            #expect(!Self.contains(messages, pin))
            #expect(messages.contains("→ APDU 00 20 00 80 <redacted 4 bytes>"))
        }
    }

    @Test
    func `Non-sensitive payloads appear only when payload logging is on`() async throws {
        let (transport, responses) = try await Self.myNumberSession()
        let individualNumber = Data("987654321098".utf8)

        let quiet = Self.replayAPDUs(transport, responses: responses, logPayloads: false)
        #expect(!Self.contains(quiet, MyNumberCardConstants.cardInfoInputSupportAID))
        #expect(!Self.contains(quiet, individualNumber))
        #expect(quiet.contains("→ APDU 00 A4 04 0C Lc=10"))
        #expect(quiet.contains("← SW:9000 (17 bytes)"))

        let verbose = Self.replayAPDUs(transport, responses: responses, logPayloads: true)
        #expect(Self.contains(verbose, MyNumberCardConstants.cardInfoInputSupportAID))
        #expect(Self.contains(verbose, individualNumber))
        // Still redacted with payload logging on.
        #expect(!Self.contains(verbose, Data([0x31, 0x32, 0x33, 0x34])))
    }

    // MARK: - Ultralight PWD_AUTH

    @Test
    func `Ultralight PWD_AUTH password and PACK never appear in logs`() async throws {
        let transport = MockTransport()
        let pack = Data([0x5A, 0xC3])
        let page = Data([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0x10])
        transport.responses = [pack, page]
        let commands = UltralightCommands(transport: transport)
        _ = try await commands.passwordAuth(password: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        _ = try await commands.readPages(startPage: 4)

        for logPayloads in [false, true] {
            let messages = Self.replayRaw(
                commands: transport.sentCommands,
                responses: transport.responses,
                logPayloads: logPayloads
            )
            #expect(!Self.contains(messages, Data([0xDE, 0xAD, 0xBE, 0xEF])))
            #expect(!Self.contains(messages, pack))
            #expect(messages.contains("→ SEND 1B <redacted 4 bytes>"))
            #expect(messages.contains("← RECV <redacted 2 bytes>"))
            // READ (0x30) is not sensitive: its page data follows the payload flag.
            #expect(Self.contains(messages, page) == logPayloads)
        }
    }

    @Test
    func `Ultralight C authentication frames are redacted`() {
        let ekRndB = Data([0xAF]) + Data(repeating: 0x5C, count: 8)
        let step2 = Data([0xAF]) + Data(repeating: 0x6D, count: 16)
        let messages = Self.replayRaw(
            commands: [Data([0x1A, 0x00]), step2],
            responses: [ekRndB, Data([0x00]) + Data(repeating: 0x7E, count: 8)],
            logPayloads: true
        )
        #expect(!Self.contains(messages, Data(repeating: 0x5C, count: 8)))
        #expect(!Self.contains(messages, Data(repeating: 0x6D, count: 16)))
        #expect(!Self.contains(messages, Data(repeating: 0x7E, count: 8)))
    }

    // MARK: - BAC

    @Test
    func `BAC challenge and EXTERNAL AUTHENTICATE data never appear in logs`() async {
        // ICAO 9303-11 Appendix D.3 inputs.
        let transport = MockTransport()
        let rndICC = Data([0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12])
        let cardResponse = Data([
            0x46, 0xB9, 0x34, 0x2A, 0x41, 0x39, 0x6C, 0xD7, 0x38, 0x6B, 0xF5, 0x80, 0x31, 0x04, 0xD7, 0xCE,
            0xDC, 0x12, 0x2B, 0x91, 0x32, 0x13, 0x9B, 0xAF, 0x2E, 0xED, 0xC9, 0x4E, 0xE1, 0x78, 0x53, 0x4F,
            0x2F, 0x2D, 0x23, 0x5D, 0x07, 0x4D, 0x74, 0x49,
        ])
        let responses = [
            ResponseAPDU(data: rndICC, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: cardResponse, sw1: 0x90, sw2: 0x00),
        ]
        transport.apduResponses = responses
        _ = try? await BACHandler.performBAC(
            mrzKey: "L898902C<369080619406236",
            transport: transport,
            rndIFD: Data([0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26]),
            kIFD: Data([0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B])
        )
        #expect(transport.sentAPDUs.count == 2)
        let authData = transport.sentAPDUs.last?.data ?? Data()
        #expect(authData.count == 40)

        for logPayloads in [false, true] {
            let messages = Self.replayAPDUs(transport, responses: responses, logPayloads: logPayloads)
            #expect(!Self.contains(messages, authData))
            #expect(!Self.contains(messages, authData.prefix(8)))
            #expect(!Self.contains(messages, rndICC))
            #expect(!Self.contains(messages, cardResponse.prefix(8)))
            #expect(messages.contains("→ APDU 00 82 00 00 <redacted 40 bytes> Le=40"))
            #expect(messages.contains("← SW:9000 <redacted 8 bytes>"))
        }
    }

    @Test
    func `Secure-messaging APDUs log header and status word only`() {
        let protected = CommandAPDU(
            cla: 0x0C, ins: 0xB0, p1: 0x00, p2: 0x00,
            data: Data([0x97, 0x01, 0x04, 0x8E, 0x08, 0xED, 0x67, 0x05, 0x41, 0x7E, 0x96, 0xBA, 0x55]),
            le: 0x00
        )
        let spy = SpyNFCLogger()
        NFCLog.apduCommand(protected, source: "Test", logger: spy, logPayloads: true)
        NFCLog.apduResponse(
            data: Data([0x87, 0x09, 0x01, 0x9F, 0xF0, 0xEC, 0x34, 0xF9, 0x92, 0x26, 0x51]),
            sw1: 0x90, sw2: 0x00,
            for: protected,
            source: "Test",
            logger: spy,
            logPayloads: true
        )
        #expect(spy.messages == ["→ APDU 0C B0 00 00 Le=256", "← SW:9000"])
    }

    // MARK: - DESFire

    @Test
    func `DESFire authentication exchanges are redacted`() {
        let challenge = Data(repeating: 0x3C, count: 16)
        let reply = Data(repeating: 0x4D, count: 32)
        let auth = CommandAPDU.desfireWrap(command: 0xAA, data: Data([0x00]))
        let continuation = CommandAPDU.desfireWrap(command: 0xAF, data: reply)
        let spy = SpyNFCLogger()
        NFCLog.apduCommand(auth, source: "Test", logger: spy, logPayloads: true)
        NFCLog.apduResponse(data: challenge, sw1: 0x91, sw2: 0xAF, for: auth, source: "Test", logger: spy, logPayloads: true)
        NFCLog.apduCommand(continuation, source: "Test", logger: spy, logPayloads: true)
        NFCLog.apduResponse(data: challenge, sw1: 0x91, sw2: 0x00, for: continuation, source: "Test", logger: spy, logPayloads: true)
        NFCLog.desfireCommand(0xAF, data: reply, source: "Test", logger: spy, logPayloads: true)
        NFCLog.desfireCommand(0x0A, data: Data([0x01]), source: "Test", logger: spy, logPayloads: true)

        #expect(!Self.contains(spy.messages, challenge))
        #expect(!Self.contains(spy.messages, reply))
        #expect(spy.messages.contains("DESFire CMD 0xAF data=<redacted 32 bytes>"))
        #expect(spy.messages.contains("DESFire CMD 0x0A data=<redacted 1 bytes>"))

        // A data-less AF (read chaining) is not an authentication step.
        let fileData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let readMore = CommandAPDU.desfireWrap(command: 0xAF)
        let readSpy = SpyNFCLogger()
        NFCLog.apduResponse(data: fileData, sw1: 0x91, sw2: 0x00, for: readMore, source: "Test", logger: readSpy, logPayloads: true)
        #expect(Self.contains(readSpy.messages, fileData))
    }

    // MARK: - Identifiers

    @Test
    func `UIDs are shown only when payload logging is on`() {
        let uid = Data([0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0x80])
        #expect(NFCLogRedaction.payload(uid, logPayloads: false) == "<7 bytes>")
        #expect(NFCLogRedaction.payload(uid, logPayloads: true) == "04 A1 B2 C3 D4 E5 80")
    }

    @Test
    func `Payload logging is off by default`() {
        #expect(NFCLogConfiguration.logPayloads == false)
    }
}

private final class SpyNFCLogger: NFCLogger, @unchecked Sendable {
    private let storage = LockedValue<[String]>([])

    var messages: [String] {
        storage.withLock { $0 }
    }

    func log(_: LogLevel, _ message: String, source _: String) {
        storage.withLock { $0.append(message) }
    }
}
