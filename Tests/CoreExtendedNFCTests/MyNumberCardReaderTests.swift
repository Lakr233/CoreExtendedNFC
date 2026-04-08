@testable import CoreExtendedNFC
import Foundation
import Testing

struct MyNumberCardReaderTests {
    @Test
    func `Read My Number token info`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT JPKI AP
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0006
            ResponseAPDU(data: Data("JPKIAPICCTOKEN2     ".utf8), sw1: 0x90, sw2: 0x00), // READ BINARY(20)
        ]

        let reader = MyNumberCardReader(transport: transport)
        let token = try await reader.readTokenInfo()

        #expect(token == "JPKIAPICCTOKEN2")
        #expect(transport.sentAPDUs.count == 3)
        #expect(transport.sentAPDUs[0].ins == 0xA4)
        #expect(transport.sentAPDUs[0].p1 == 0x04)
        #expect(transport.sentAPDUs[0].p2 == 0x0C)
        #expect(transport.sentAPDUs[0].data == MyNumberCardConstants.jpkiAID)
        #expect(transport.sentAPDUs[1].data == MyNumberCardConstants.jpkiTokenEFID)
        #expect(transport.sentAPDUs[2].ins == 0xB0)
        #expect(transport.sentAPDUs[2].le == MyNumberCardConstants.tokenLength)
    }

    @Test
    func `Read My Number individual number with PIN`() async throws {
        let transport = MockTransport()
        let payload = Data([0x10, 0x01, 0x0C]) + Data("123456789012".utf8) + Data([0x00, 0x00])
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT card-info-input-support AP
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0011
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // VERIFY PIN
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0001
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00), // READ BINARY(17)
        ]

        let reader = MyNumberCardReader(transport: transport)
        let number = try await reader.readIndividualNumber(cardInfoInputSupportPIN: "1234")

        #expect(number == "123456789012")
        #expect(transport.sentAPDUs.count == 5)
        #expect(transport.sentAPDUs[0].data == MyNumberCardConstants.cardInfoInputSupportAID)
        #expect(transport.sentAPDUs[1].data == MyNumberCardConstants.cardInfoInputSupportPINEFID)
        #expect(transport.sentAPDUs[2].ins == 0x20)
        #expect(transport.sentAPDUs[2].data == Data("1234".utf8))
        #expect(transport.sentAPDUs[3].data == MyNumberCardConstants.individualNumberEFID)
        #expect(transport.sentAPDUs[4].le == MyNumberCardConstants.individualNumberLength)
    }

    @Test
    func `Read individual number rejects invalid PIN format`() async {
        let reader = MyNumberCardReader(transport: MockTransport())

        do {
            _ = try await reader.readIndividualNumber(cardInfoInputSupportPIN: "12A4")
            #expect(Bool(false), "Expected invalid PIN format to throw")
        } catch let error as NFCError {
            if case let .unsupportedOperation(message) = error {
                #expect(message.contains("4 digits"))
            } else {
                #expect(Bool(false), "Unexpected error type: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }

    @Test
    func `Lookup remaining PIN attempts from 63Cx status`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT DF
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3), // VERIFY(empty) => 3 attempts
        ]

        let reader = MyNumberCardReader(transport: transport)
        let remaining = try await reader.lookupRemainingPINAttempts(for: .cardInfoInputSupport)

        #expect(remaining == 3)
    }

    @Test
    func `Core top-level My Number read delegates to reader`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data("JPKIAPICCTOKEN2     ".utf8), sw1: 0x90, sw2: 0x00),
        ]

        let info = CardInfo(type: .myNumberCard, uid: transport.identifier)
        let result = try await CoreExtendedNFC.readMyNumberCard(
            info: info,
            transport: transport,
            items: [.tokenInfo]
        )

        #expect(result.tokenInfo == "JPKIAPICCTOKEN2")
        #expect(result.individualNumber == nil)
    }

    @Test
    func `Top-level dump for My Number card captures token info`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data("JPKIAPICCTOKEN2     ".utf8), sw1: 0x90, sw2: 0x00),
        ]

        let info = CardInfo(type: .myNumberCard, uid: transport.identifier)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)

        #expect(dump.files.count == 1)
        #expect(dump.files[0].identifier == MyNumberCardConstants.jpkiTokenEFID)
        #expect(dump.facts.contains(where: { $0.key == "JPKI Token" }))
        #expect(dump.capabilities.contains(.authenticationRequired))
    }
}
