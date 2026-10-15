// MIFARE Ultralight / NTAG command test suite.
//
// ## References
// - NXP MF0ICU2 (Ultralight C) datasheet: READ(0x30), WRITE(0xA2)
//   https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf
// - NXP MF0UL21 (Ultralight EV1) datasheet: FAST_READ(0x3A), PWD_AUTH(0x1B), GET_VERSION(0x60)
//   https://www.nxp.com/docs/en/data-sheet/MF0ULx1.pdf
// - libnfc nfc-mfultralight.c:
//   https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-mfultralight.c
@testable import CoreExtendedNFC
import Foundation
import Testing

struct UltralightTests {
    @Test
    func `Restore stops before writing when the task is cancelled`() async {
        let mock = MockTransport()
        mock.responses = Array(repeating: Data([0x0A]), count: 4)
        let info = CardInfo(type: .ntag213, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
        let dump = MemoryDump(
            cardInfo: info,
            pages: (4 ..< 8).map { MemoryDump.Page(number: UInt8($0), data: Data(repeating: UInt8($0), count: 4)) }
        )
        let restore = UltralightDump(commands: UltralightCommands(transport: mock))

        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await restore.restore(dump: dump, map: .forType(.ntag213))
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(mock.sentCommands.isEmpty)
    }

    // MARK: - Command Building

    @Test
    func `READ command sends correct bytes`() async throws {
        let mock = MockTransport()
        mock.responses = [Data(repeating: 0xAA, count: 16)]
        let commands = UltralightCommands(transport: mock)

        let data = try await commands.readPages(startPage: 0x04)
        #expect(mock.sentCommands[0] == Data([0x30, 0x04]))
        #expect(data.count == 16)
    }

    @Test
    func `WRITE command sends correct bytes`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x0A])] // ACK
        let commands = UltralightCommands(transport: mock)

        try await commands.writePage(0x04, data: Data([0x01, 0x02, 0x03, 0x04]))
        #expect(mock.sentCommands[0] == Data([0xA2, 0x04, 0x01, 0x02, 0x03, 0x04]))
    }

    @Test
    func `WRITE rejects non-4-byte data`() async {
        let mock = MockTransport()
        let commands = UltralightCommands(transport: mock)

        await #expect(throws: NFCError.self) {
            try await commands.writePage(0x04, data: Data([0x01, 0x02]))
        }
    }

    @Test
    func `FAST_READ command sends correct bytes`() async throws {
        let mock = MockTransport()
        // 3 pages = 12 bytes
        mock.responses = [Data(repeating: 0xBB, count: 12)]
        let commands = UltralightCommands(transport: mock)

        let data = try await commands.fastRead(from: 4, to: 6)
        #expect(mock.sentCommands[0] == Data([0x3A, 0x04, 0x06]))
        #expect(data.count == 12)
    }

    @Test
    func `GET_VERSION command sends 0x60`() async throws {
        let mock = MockTransport()
        // NTAG213 version response
        mock.responses = [Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03])]
        let commands = UltralightCommands(transport: mock)

        let version = try await commands.getVersion()
        #expect(mock.sentCommands[0] == Data([0x60]))
        #expect(version.cardType == .ntag213)
    }

    // MARK: - Version Parsing

    @Test
    func `Parse NTAG213 version response`() throws {
        let data = Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03])
        let version = try UltralightVersionResponse(data: data)
        #expect(version.vendorID == 0x04) // NXP
        #expect(version.productType == 0x04) // NTAG
        #expect(version.storageSize == 0x0F)
        #expect(version.cardType == .ntag213)
        #expect(version.totalPages == 45)
        #expect(version.userPages == 36)
    }

    @Test
    func `Parse NTAG215 version response`() throws {
        let data = Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03])
        let version = try UltralightVersionResponse(data: data)
        #expect(version.cardType == .ntag215)
        #expect(version.totalPages == 135)
        #expect(version.userPages == 126)
    }

    @Test
    func `Parse NTAG216 version response`() throws {
        let data = Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03])
        let version = try UltralightVersionResponse(data: data)
        #expect(version.cardType == .ntag216)
        #expect(version.totalPages == 231)
        #expect(version.userPages == 222)
    }

    @Test
    func `Parse Ultralight EV1 MF0UL11 version response`() throws {
        let data = Data([0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03])
        let version = try UltralightVersionResponse(data: data)
        #expect(version.productType == 0x03) // Ultralight
        #expect(version.cardType == .mifareUltralightEV1_MF0UL11)
    }

    @Test
    func `Parse Ultralight EV1 MF0UL21 version response`() throws {
        let data = Data([0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03])
        let version = try UltralightVersionResponse(data: data)
        #expect(version.cardType == .mifareUltralightEV1_MF0UL21)
    }

    // MARK: - Memory Map

    @Test
    func `NTAG213 memory map`() {
        let map = UltralightMemoryMap.forType(.ntag213)
        #expect(map.totalPages == 45)
        #expect(map.userDataStart == 4)
        #expect(map.userDataEnd == 39)
        #expect(map.configStart == 41)
        #expect(map.dynamicLockStart == 40)
    }

    @Test
    func `NTAG215 memory map`() {
        let map = UltralightMemoryMap.forType(.ntag215)
        #expect(map.totalPages == 135)
        #expect(map.userDataStart == 4)
        #expect(map.userDataEnd == 129)
        #expect(map.configStart == 131)
    }

    @Test
    func `Ultralight basic memory map`() {
        let map = UltralightMemoryMap.forType(.mifareUltralight)
        #expect(map.totalPages == 16)
        #expect(map.userDataStart == 4)
        #expect(map.userDataEnd == 15)
        #expect(map.configStart == nil)
    }

    @Test
    func `Ultralight C memory map excludes secret key pages from config range`() {
        let map = UltralightMemoryMap.forType(.mifareUltralightC)
        #expect(map.totalPages == 48)
        #expect(map.userDataStart == 4)
        #expect(map.userDataEnd == 39)
        #expect(map.dynamicLockStart == 40)
        #expect(map.configStart == 42)
    }

    // MARK: - PWD_AUTH

    @Test
    func `PWD_AUTH sends correct bytes`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0xAB, 0xCD])] // PACK response
        let commands = UltralightCommands(transport: mock)

        let pack = try await commands.passwordAuth(password: Data([0x01, 0x02, 0x03, 0x04]))
        #expect(mock.sentCommands[0] == Data([0x1B, 0x01, 0x02, 0x03, 0x04]))
        #expect(pack == Data([0xAB, 0xCD]))
    }

    @Test
    func `Ultralight C AUTHENTICATE performs the 3DES challenge flow`() async throws {
        let key = try #require(Data(hexString: "49454D4B41455242214E4143554F5946"))
        let rndA = try #require(Data(hexString: "0011223344556677"))
        let rndB = try #require(Data(hexString: "214E4143554F5946"))

        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let finalResponse = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )

        let mock = MockTransport()
        mock.responses = [
            Data([0xAF]) + encryptedRndB,
            Data([0x00]) + finalResponse,
        ]
        let commands = UltralightCommands(transport: mock)

        let session = try await commands.authenticateUltralightC(key: key, randomA: rndA)

        #expect(session.randomA == rndA)
        #expect(session.randomB == rndB)
        #expect(mock.sentCommands[0] == Data([0x1A, 0x00]))
        #expect(mock.sentCommands[1] == Data([0xAF]) + challengeCiphertext)
    }

    @Test
    func `Ultralight C access configuration parses AUTH0 and AUTH1`() async throws {
        let mock = MockTransport()
        mock.responses = [
            Data([
                0x90, 0x91, 0x92, 0x93,
                0x94, 0x95, 0x96, 0x97,
                0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
            ]),
        ]
        let commands = UltralightCommands(transport: mock)

        let config = try await commands.readUltralightCAccessConfiguration()

        #expect(config.firstProtectedPage == 0x10)
        #expect(config.requiresAuthenticationForWrites)
        #expect(config.requiresAuthenticationForReads)
        #expect(config.protectionDescription == "Read and write")
        #expect(mock.sentCommands[0] == Data([0x30, 0x28]))
    }

    // MARK: - Command framing guards

    @Test
    func `FAST_READ rejects end before start`() async {
        let mock = MockTransport()
        mock.responses = [Data(count: 16)]
        await #expect(throws: NFCError.self) {
            _ = try await UltralightCommands(transport: mock).fastRead(from: 5, to: 4)
        }
        #expect(mock.sentCommands.isEmpty)
    }

    @Test
    func `FAST_READ full 256-page range computes length without overflow`() async throws {
        let mock = MockTransport()
        mock.responses = [Data(repeating: 0xAA, count: 1024)]
        let data = try await UltralightCommands(transport: mock).fastRead(from: 0, to: 255)
        #expect(data.count == 1024)
    }

    @Test
    func `COMPATIBILITY_WRITE uses two frames`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x0A]), Data([0x0A])]
        try await UltralightCommands(transport: mock).compatibilityWrite(5, data: Data([1, 2, 3, 4]))
        #expect(mock.sentCommands == [Data([0xA0, 0x05]), Data([1, 2, 3, 4]) + Data(count: 12)])
    }

    @Test
    func `COMPATIBILITY_WRITE stops when the address phase is NAKed`() async {
        let mock = MockTransport()
        mock.responses = [Data([0x00]), Data([0x0A])]
        do {
            try await UltralightCommands(transport: mock).compatibilityWrite(5, data: Data([1, 2, 3, 4]))
            Issue.record("expected writeFailed")
        } catch NFCError.writeFailed(page: 5) {
        } catch {
            Issue.record("unexpected error \(error)")
        }
        #expect(mock.sentCommands.count == 1)
    }

    // MARK: - Ultralight C detection (NXP AN10833 §3.2)

    @Test
    func `Refiner classifies Ultralight C via AUTHENTICATE probe after GET_VERSION NAK`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x00]), Data([0xAF]) + Data(repeating: 0x5A, count: 8)]
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralightC)
        #expect(mock.sentCommands == [Data([0x60]), Data([0x1A, 0x00])])
    }

    @Test
    func `Refiner keeps plain Ultralight when AUTHENTICATE is also NAKed`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x00]), Data([0x00])]
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralight)
    }

    @Test
    func `Refiner does not probe AUTHENTICATE after a transport error`() async throws {
        let mock = MockTransport()
        mock.responses = []
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralight)
        #expect(mock.sentCommands == [Data([0x60])])
    }

    private static func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return concat(Data(data.dropFirst()), Data([first]))
    }

    private static func concat(_ parts: Data...) -> Data {
        parts.reduce(into: Data()) { result, part in
            result.append(part)
        }
    }
}
