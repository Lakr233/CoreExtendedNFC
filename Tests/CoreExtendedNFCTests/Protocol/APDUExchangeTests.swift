// APDU exchange (status-word handling) test suite.
//
// ## References
// - ISO/IEC 7816-4 §5.1.3: SW1 = 61 (GET RESPONSE with Le = SW2), SW1 = 6C (re-issue with Le = SW2)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct APDUExchangeTests {
    /// Replays canned responses and records every command sent.
    private final class ScriptedCard {
        var responses: [ResponseAPDU]
        var sent: [CommandAPDU] = []

        init(_ responses: [ResponseAPDU]) {
            self.responses = responses
        }

        func send(_ apdu: CommandAPDU) throws -> ResponseAPDU {
            sent.append(apdu)
            guard !responses.isEmpty else { throw NFCError.tagConnectionLost }
            return responses.removeFirst()
        }
    }

    @Test
    func `61xx responses are collected with GET RESPONSE`() async throws {
        let card = ScriptedCard([
            ResponseAPDU(data: Data([0x01, 0x02]), sw1: 0x61, sw2: 0x05),
            ResponseAPDU(data: Data([0x03, 0x04, 0x05, 0x06, 0x07]), sw1: 0x90, sw2: 0x00),
        ])
        let select = CommandAPDU.select(aid: Data([0xA0, 0x00]))
        let response = try await APDUExchange.transmit(select) { try card.send($0) }

        #expect(response == ResponseAPDU(data: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]), sw1: 0x90, sw2: 0x00))
        #expect(card.sent.count == 2)
        #expect(card.sent[1].bytes == Data([0x00, 0xC0, 0x00, 0x00, 0x05]))
    }

    @Test
    func `6Cxx re-issues the command once with the corrected Le`() async throws {
        let card = ScriptedCard([
            ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x10),
            ResponseAPDU(data: Data(repeating: 0xAA, count: 16), sw1: 0x90, sw2: 0x00),
        ])
        let read = CommandAPDU.readBinary(offset: 0, length: 0x00)
        let response = try await APDUExchange.transmit(read) { try card.send($0) }

        #expect(response.data.count == 16)
        #expect(response.isSuccess)
        #expect(card.sent.count == 2)
        #expect(card.sent[1].bytes == Data([0x00, 0xB0, 0x00, 0x00, 0x10]))
    }

    @Test
    func `A second 6Cxx is returned instead of retried`() async throws {
        let card = ScriptedCard([
            ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x10),
            ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x08),
        ])
        let response = try await APDUExchange.transmit(.readBinary(offset: 0, length: 4)) { try card.send($0) }
        #expect(response.sw1 == 0x6C)
        #expect(card.sent.count == 2)
    }

    @Test
    func `Endless 61xx chaining is bounded`() async {
        let card = ScriptedCard(Array(repeating: ResponseAPDU(data: Data([0x00]), sw1: 0x61, sw2: 0x00), count: 100))
        do {
            _ = try await APDUExchange.transmit(.getResponse(length: 0), maxGetResponseFrames: 4) { try card.send($0) }
            Issue.record("Expected responseChainTooLong")
        } catch let NFCError.responseChainTooLong(maxFrames) {
            #expect(maxFrames == 4)
        } catch {
            Issue.record("Unexpected error \(error)")
        }
        #expect(card.sent.count == 5) // the command plus four GET RESPONSEs
    }

    @Test
    func `Retry can be disabled`() async throws {
        let card = ScriptedCard([ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x10)])
        let response = try await APDUExchange.transmit(.readBinary(offset: 0, length: 4), retryOnWrongLength: false) {
            try card.send($0)
        }
        #expect(response.sw1 == 0x6C)
        #expect(card.sent.count == 1)
    }
}
