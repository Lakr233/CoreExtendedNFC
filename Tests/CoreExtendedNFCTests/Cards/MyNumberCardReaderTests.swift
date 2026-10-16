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
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3), // VERIFY (empty) -> 3 tries left
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // VERIFY PIN
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0001
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00), // READ BINARY(17)
        ]

        let reader = MyNumberCardReader(transport: transport)
        let number = try await reader.readIndividualNumber(cardInfoInputSupportPIN: "1234")

        #expect(number == "123456789012")
        #expect(transport.sentAPDUs.count == 6)
        #expect(transport.sentAPDUs[0].data == MyNumberCardConstants.cardInfoInputSupportAID)
        #expect(transport.sentAPDUs[1].data == MyNumberCardConstants.cardInfoInputSupportPINEFID)
        #expect(transport.sentAPDUs[2].bytes == Data([0x00, 0x20, 0x00, 0x80]))
        #expect(transport.sentAPDUs[3].ins == 0x20)
        #expect(transport.sentAPDUs[3].data == Data("1234".utf8))
        #expect(transport.sentAPDUs[4].data == MyNumberCardConstants.individualNumberEFID)
        #expect(transport.sentAPDUs[5].le == MyNumberCardConstants.individualNumberLength)
    }

    @Test
    func `Read My Number individual number rejects malformed official payload`() async {
        let transport = MockTransport()
        // Official frame shape but invalid TLV tag (0x02 instead of 0x01).
        let payload = Data([0x10, 0x02, 0x0C]) + Data("123456789012".utf8) + Data([0x00, 0x00])
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00),
        ]

        let reader = MyNumberCardReader(transport: transport)

        do {
            _ = try await reader.readIndividualNumber(cardInfoInputSupportPIN: "1234")
            #expect(Bool(false), "Expected malformed official payload to throw")
        } catch let error as NFCError {
            if case .invalidResponse = error {
                #expect(Bool(true))
            } else {
                #expect(Bool(false), "Unexpected error type: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }

    @Test
    func `Individual number without the official layout is rejected, not regex-scanned`() async {
        // Plain ASCII digits (or digits behind a wrong header) are not the EF 0001
        // layout; a free "any 12 digits" match could return the wrong number.
        for body in [Data("123456789012".utf8), Data([0x30, 0x01, 0x0C]) + Data("123456789012".utf8)] {
            let transport = MockTransport()
            transport.apduResponses = [
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: body, sw1: 0x90, sw2: 0x00),
            ]
            let error = await #expect(throws: NFCError.self) {
                _ = try await MyNumberCardReader(transport: transport)
                    .readIndividualNumber(cardInfoInputSupportPIN: "1234")
            }
            guard case .invalidResponse? = error else {
                Issue.record("expected invalidResponse, got \(String(describing: error))")
                continue
            }
        }
    }

    @Test
    func `Individual number with the official TLV and a short trailer is accepted`() async throws {
        let transport = MockTransport()
        let payload = Data([0x10, 0x01, 0x0C]) + Data("987654321098".utf8)
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00),
        ]
        let number = try await MyNumberCardReader(transport: transport)
            .readIndividualNumber(cardInfoInputSupportPIN: "1234")
        #expect(number == "987654321098")
    }

    @Test(arguments: [(UInt8(0x63), UInt8(0xC0)), (UInt8(0x69), UInt8(0x83)), (UInt8(0x69), UInt8(0x84))])
    func `Blocked PIN is never transmitted`(sw1: UInt8, sw2: UInt8) async {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT AP
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF 0011
            ResponseAPDU(data: Data(), sw1: sw1, sw2: sw2), // VERIFY (empty)
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // would accept a PIN
        ]

        let error = await #expect(throws: NFCError.self) {
            _ = try await MyNumberCardReader(transport: transport)
                .readIndividualNumber(cardInfoInputSupportPIN: "1234")
        }
        #expect(Self.remainingAttempts(error) == .some(0))
        #expect(transport.sentAPDUs.count == 3)
        #expect(!transport.sentAPDUs.contains { $0.data == Data("1234".utf8) })
    }

    @Test
    func `Wrong PIN reports the remaining attempts from 63Cx`() async {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC2),
        ]
        let error = await #expect(throws: NFCError.self) {
            _ = try await MyNumberCardReader(transport: transport)
                .readIndividualNumber(cardInfoInputSupportPIN: "1234")
        }
        #expect(Self.remainingAttempts(error) == .some(2))
    }

    @Test
    func `6300 is not read as zero remaining attempts`() async {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0x00), // no counter: PIN may still be sent
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0x00), // wrong PIN, no counter
        ]
        let error = await #expect(throws: NFCError.self) {
            _ = try await MyNumberCardReader(transport: transport)
                .readIndividualNumber(cardInfoInputSupportPIN: "1234")
        }
        #expect(Self.remainingAttempts(error) == .some(nil))
        #expect(transport.sentAPDUs.count == 4)

        let lookup = MockTransport()
        lookup.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0x00),
        ]
        let lookupError = await #expect(throws: NFCError.self) {
            _ = try await MyNumberCardReader(transport: lookup)
                .lookupRemainingPINAttempts(for: .cardInfoInputSupport)
        }
        guard case .unexpectedStatusWord(0x63, 0x00)? = lookupError else {
            Issue.record("expected unexpectedStatusWord 6300, got \(String(describing: lookupError))")
            return
        }
    }

    @Test
    func `Duplicate requested items send VERIFY only once`() async throws {
        let transport = MockTransport()
        let payload = Data([0x10, 0x01, 0x0C]) + Data("123456789012".utf8) + Data([0x00, 0x00])
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00),
        ]
        let result = try await MyNumberCardReader(transport: transport).read(
            items: [.individualNumber, .individualNumber],
            cardInfoInputSupportPIN: "1234"
        )
        #expect(result.individualNumber == "123456789012")
        #expect(transport.sentAPDUs.filter { $0.data == Data("1234".utf8) }.count == 1)
        #expect(transport.sentAPDUs.count == 6)
    }

    @Test
    func `PIN error descriptions distinguish blocked, counted and unknown`() {
        let blocked = NFCError.pinVerificationFailed(remainingAttempts: 0).errorDescription
        let counted = NFCError.pinVerificationFailed(remainingAttempts: 2).errorDescription
        let unknown = NFCError.pinVerificationFailed(remainingAttempts: nil).errorDescription
        #expect(blocked != nil && counted != nil && unknown != nil)
        #expect(Set([blocked, counted, unknown]).count == 3)
        #expect(counted?.contains("2") == true)
    }

    @Test
    func `Lookup reports zero attempts for a blocked PIN`() async throws {
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x83),
        ]
        let remaining = try await MyNumberCardReader(transport: transport)
            .lookupRemainingPINAttempts(for: .cardInfoInputSupport)
        #expect(remaining == 0)
    }

    @Test
    func `Read individual number rejects invalid PIN format`() async {
        let reader = MyNumberCardReader(transport: MockTransport())

        do {
            _ = try await reader.readIndividualNumber(cardInfoInputSupportPIN: "12A4")
            #expect(Bool(false), "Expected invalid PIN format to throw")
        } catch let error as NFCError {
            if case let .invalidParameter(message) = error {
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

        let result = try await CoreExtendedNFC.readMyNumberCard(
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

    /// `.some(count)` for `.pinVerificationFailed(count)`, `nil` for any other error.
    @Test
    func `Reading the individual number without a PIN reports pinRequired before any APDU`() async {
        let transport = MockTransport()
        // before: unsupportedOperation("Reading My Number requires `cardInfoInputSupportPIN`")
        await #expect(throws: NFCError.pinRequired(.cardInfoInputSupport)) {
            _ = try await MyNumberCardReader(transport: transport).read(items: [.individualNumber])
        }
        #expect(transport.sentAPDUs.isEmpty)
    }

    @Test
    func `Reading no fields is an invalid parameter`() async {
        await #expect(throws: NFCError.invalidParameter("No My Number card fields were requested")) {
            _ = try await MyNumberCardReader(transport: MockTransport()).read(items: [])
        }
    }

    @Test
    func `A card without the JPKI application reports applicationNotFound`() async {
        let transport = MockTransport()
        transport.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)]
        await #expect(throws: NFCError.applicationNotFound(aid: MyNumberCardConstants.jpkiAID)) {
            _ = try await MyNumberCardReader(transport: transport).readTokenInfo()
        }
    }

    private static func remainingAttempts(_ error: NFCError?) -> Int?? {
        guard case let .pinVerificationFailed(remaining)? = error else { return nil }
        return .some(remaining)
    }
}
