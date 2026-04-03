@testable import CoreExtendedNFC
import Foundation

/// Mock transport for unit testing card commands without NFC hardware.
final class MockTransport: ISO7816TagTransporting, @unchecked Sendable {
    let initialAID: String = ""

    let identifier: Data
    var responses: [Data] = []
    var apduResponses: [ResponseAPDU] = []
    var sentCommands: [Data] = []
    var sentAPDUs: [CommandAPDU] = []
    private var responseIndex = 0
    private var apduResponseIndex = 0

    init(identifier: Data = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])) {
        self.identifier = identifier
    }

    func send(_ data: Data) async throws -> Data {
        sentCommands.append(data)
        guard responseIndex < responses.count else {
            throw NFCError.tagConnectionLost
        }
        let response = responses[responseIndex]
        responseIndex += 1
        return response
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        sentAPDUs.append(apdu)
        guard apduResponseIndex < apduResponses.count else {
            throw NFCError.tagConnectionLost
        }
        let response = apduResponses[apduResponseIndex]
        apduResponseIndex += 1
        return response
    }

    func sendAPDUWithChaining(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        try await sendAPDU(apdu)
    }

    func reset() {
        responseIndex = 0
        apduResponseIndex = 0
        sentCommands.removeAll()
        sentAPDUs.removeAll()
    }
}
