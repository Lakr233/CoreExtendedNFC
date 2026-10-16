@testable import CoreExtendedNFC
import Foundation
import Testing

struct MyNumberProgressTests {
    @Test
    func `My Number read reports one progress message per requested field`() async throws {
        let transport = MockTransport()
        let payload = Data([0x10, 0x01, 0x0C]) + Data("123456789012".utf8) + Data([0x00, 0x00])
        transport.apduResponses = [
            // Token info: SELECT DF, SELECT EF, READ BINARY.
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data("JPKIAPICCTOKEN2     ".utf8), sw1: 0x90, sw2: 0x00),
            // Individual number: SELECT DF, SELECT EF, empty VERIFY, VERIFY, SELECT EF, READ BINARY.
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0xC3),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: payload, sw1: 0x90, sw2: 0x00),
        ]
        let progress = ProgressRecorder()

        let result = try await CoreExtendedNFC.readMyNumberCard(
            transport: transport,
            items: [.tokenInfo, .individualNumber],
            cardInfoInputSupportPIN: "1234",
            onProgress: { progress.append($0) }
        )

        #expect(result.tokenInfo == "JPKIAPICCTOKEN2")
        #expect(result.individualNumber == "123456789012")
        let messages = progress.messages
        #expect(messages.count == 2)
        #expect(Set(messages).count == 2)
        #expect(messages.allSatisfy { !$0.isEmpty })
    }

    @Test
    func `My Number read without a PIN reports no progress for the refused field`() async throws {
        let progress = ProgressRecorder()
        await #expect(throws: NFCError.self) {
            _ = try await CoreExtendedNFC.readMyNumberCard(
                transport: MockTransport(),
                items: [.individualNumber],
                onProgress: { progress.append($0) }
            )
        }
        #expect(progress.messages.isEmpty)
    }
}
