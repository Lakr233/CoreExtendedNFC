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

    // MARK: - Irreversible page protection (MF0ICU1/MF0ICU2/MF0ULx1/NTAG21x memory maps)

    @Test(arguments: [UInt8(0x00), 0x01, 0x02])
    func `WRITE refuses UID and static lock pages without opt-in`(page: UInt8) async {
        let mock = MockTransport()
        mock.responses = [Data([0x0A])]
        await #expect(throws: NFCError.self) {
            try await UltralightCommands(transport: mock).writePage(page, data: Data([0x00, 0x00, 0xFF, 0xFF]))
        }
        #expect(mock.sentCommands.isEmpty)
    }

    /// READ answer starting at page 3 whose first 4 bytes are `page3`.
    private static func page3Read(_ page3: [UInt8]) -> Data {
        Data(page3) + Data(count: 12)
    }

    /// Page 3 bits are OR-ed (MF0ICU2 / NTAG21x "Capability Container"): writing
    /// E1 10 06 00 over E1 10 12 00 would leave E1 10 16 00, a different CC.
    @Test
    func `WRITE refuses a page 3 value that would change the OTP bits`() async {
        let mock = MockTransport()
        mock.responses = [Self.page3Read([0xE1, 0x10, 0x12, 0x00]), Self.page3Read([0xE1, 0x10, 0x12, 0x00])]
        let commands = UltralightCommands(transport: mock)
        do {
            try await commands.writePage(3, data: Data([0xE1, 0x10, 0x06, 0x00]))
            Issue.record("expected irreversibleWriteRefused")
        } catch NFCError.irreversibleWriteRefused(page: 3) {
        } catch {
            Issue.record("unexpected error \(error)")
        }
        // A read-only CC (CC3 = 0Fh) sets new bits too.
        await #expect(throws: NFCError.self) {
            try await commands.writePage(3, data: Data([0xE1, 0x10, 0x12, 0x0F]))
        }
        // Only the two page 3 READs were sent, never a WRITE.
        #expect(mock.sentCommands == [Data([0x30, 0x03]), Data([0x30, 0x03])])
    }

    @Test
    func `WRITE allows a page 3 value that changes nothing and opted-in irreversible writes`() async throws {
        let mock = MockTransport()
        mock.responses = [
            Self.page3Read([0xE1, 0x10, 0x12, 0x00]), Data([0x0A]),
            Self.page3Read([0xE1, 0x10, 0x12, 0x00]), Data([0x0A]),
            Data([0x0A]), Data([0x0A]),
        ]
        let commands = UltralightCommands(transport: mock)
        try await commands.writePage(3, data: Data([0xE1, 0x10, 0x12, 0x00]))
        try await commands.writePage(3, data: Data([0x00, 0x10, 0x02, 0x00])) // subset of the set bits
        try await commands.writePage(3, data: Data([0xE1, 0x10, 0x06, 0x00]), allowIrreversible: true)
        try await commands.writePage(2, data: Data([0x00, 0x00, 0xFF, 0xFF]), allowIrreversible: true)
        let expected: [Data] = [
            Data([0x30, 0x03]), Data([0xA2, 0x03, 0xE1, 0x10, 0x12, 0x00]),
            Data([0x30, 0x03]), Data([0xA2, 0x03, 0x00, 0x10, 0x02, 0x00]),
            Data([0xA2, 0x03, 0xE1, 0x10, 0x06, 0x00]),
            Data([0xA2, 0x02, 0x00, 0x00, 0xFF, 0xFF]),
        ]
        #expect(mock.sentCommands == expected)
    }

    @Test(arguments: [UInt8(0x00), 0x01, 0x02])
    func `Irreversible refusals are typed with the page`(page: UInt8) async {
        let mock = MockTransport()
        do {
            try await UltralightCommands(transport: mock).writePage(page, data: Data(count: 4))
            Issue.record("expected irreversibleWriteRefused")
        } catch let NFCError.irreversibleWriteRefused(refused) {
            #expect(refused == page)
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test
    func `Ultralight argument errors are invalidParameter`() async {
        let commands = UltralightCommands(transport: MockTransport())
        await #expect {
            try await commands.writePage(4, data: Data([0x01]))
        } throws: { error in
            if case NFCError.invalidParameter = error { true } else { false }
        }
        await #expect {
            try await commands.compatibilityWrite(4, data: Data([0x01]))
        } throws: { error in
            if case NFCError.invalidParameter = error { true } else { false }
        }
        await #expect {
            _ = try await commands.passwordAuth(password: Data([0x01]))
        } throws: { error in
            if case NFCError.invalidParameter = error { true } else { false }
        }
        await #expect {
            _ = try await commands.authenticateUltralightC(key: Data(count: 8))
        } throws: { error in
            if case NFCError.invalidParameter = error { true } else { false }
        }
    }

    /// NXP datasheets: WRITE / COMPATIBILITY_WRITE answer with the 4-bit ACK Ah.
    @Test
    func `An empty WRITE response is not an ACK`() async {
        let mock = MockTransport()
        mock.responses = [Data(), Data([0x0A]), Data()]
        let commands = UltralightCommands(transport: mock)
        await #expect(throws: NFCError.self) {
            try await commands.writePage(4, data: Data([1, 2, 3, 4]))
        }
        await #expect(throws: NFCError.self) {
            try await commands.compatibilityWrite(4, data: Data([1, 2, 3, 4]))
        }
    }

    @Test
    func `writeNDEF never writes the OTP page 3`() async throws {
        let mock = MockTransport()
        let cc = Data([0xE1, 0x10, 0x12, 0x00]) + Data(count: 12)
        mock.responses = [cc] + Array(repeating: Data([0x0A]), count: 40)
        try await CoreExtendedNFC.writeNDEF(
            .uri("https://a.b"),
            info: CardInfo(type: .ntag213, uid: mock.identifier),
            transport: mock
        )
        #expect(mock.sentCommands.contains { $0.first == 0xA2 })
        let page3Writes = mock.sentCommands.filter { command in
            let bytes = [UInt8](command)
            return bytes.count >= 2 && (bytes[0] == 0xA2 || bytes[0] == 0xA0) && bytes[1] == 0x03
        }
        #expect(page3Writes.isEmpty)
    }

    @Test
    func `Restore validates every page before the first write`() async {
        let mock = MockTransport()
        mock.responses = Array(repeating: Data([0x0A]), count: 8)
        let info = CardInfo(type: .ntag213, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
        let dump = MemoryDump(
            cardInfo: info,
            pages: [
                MemoryDump.Page(number: 4, data: Data([1, 2, 3, 4])),
                MemoryDump.Page(number: 5, data: Data([1, 2, 3, 4])),
                MemoryDump.Page(number: 6, data: Data([1, 2])),
            ]
        )
        let restore = UltralightDump(commands: UltralightCommands(transport: mock))
        await #expect(throws: NFCError.self) {
            try await restore.restore(dump: dump, map: .forType(.ntag213))
        }
        #expect(mock.sentCommands.isEmpty)
    }

    @Test
    func `Restore refuses a dump from a different card type`() async {
        let mock = MockTransport()
        mock.responses = Array(repeating: Data([0x0A]), count: 8)
        let uid = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .ntag215, uid: uid),
            pages: [MemoryDump.Page(number: 4, data: Data([1, 2, 3, 4]))]
        )
        await #expect {
            try await CoreExtendedNFC.restoreUltralight(
                dump: dump,
                info: CardInfo(type: .ntag213, uid: uid),
                transport: mock
            )
        } throws: { error in
            if case NFCError.invalidParameter = error { true } else { false }
        }
        #expect(mock.sentCommands.isEmpty)
    }

    /// NTAG213 datasheet §8.5: user 04h-27h, dynamic lock 28h, CFG0 29h, CFG1 2Ah,
    /// PWD 2Bh, PACK 2Ch.
    @Test(arguments: [UInt8(0x28), 0x29, 0x2A, 0x2B, 0x2C])
    func `WRITE refuses NTAG213 lock, config, PWD and PACK pages with a memory map`(page: UInt8) async {
        let mock = MockTransport()
        mock.responses = [Data([0x0A])]
        await #expect(throws: NFCError.self) {
            try await UltralightCommands(transport: mock)
                .writePage(page, data: Data([0x00, 0x00, 0x00, 0x00]), memoryMap: .forType(.ntag213))
        }
        #expect(mock.sentCommands.isEmpty)
    }

    /// MF0ICU2 datasheet: lock bytes 28h-29h, AUTH0 2Ah, AUTH1 2Bh, 3DES key 2Ch-2Fh.
    @Test(arguments: [UInt8(0x28), 0x29, 0x2A, 0x2B, 0x2C, 0x2F])
    func `WRITE refuses Ultralight C lock, AUTH and key pages with a memory map`(page: UInt8) async {
        let mock = MockTransport()
        mock.responses = [Data([0x0A])]
        await #expect(throws: NFCError.self) {
            try await UltralightCommands(transport: mock)
                .compatibilityWrite(page, data: Data([0x00, 0x00, 0x00, 0x00]), memoryMap: .forType(.mifareUltralightC))
        }
        #expect(mock.sentCommands.isEmpty)
    }

    /// MF0UL11 datasheet: user 04h-0Fh, CFG0 10h, CFG1 11h, PWD 12h, PACK 13h.
    @Test
    func `WRITE allows the last user page and refuses EV1 CFG0 with a memory map`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x0A]), Data([0x0A])]
        let commands = UltralightCommands(transport: mock)
        let map = UltralightMemoryMap.forType(.mifareUltralightEV1_MF0UL11)
        try await commands.writePage(0x0F, data: Data([1, 2, 3, 4]), memoryMap: map)
        await #expect(throws: NFCError.self) {
            try await commands.writePage(0x10, data: Data([0x00, 0x00, 0x00, 0x04]), memoryMap: map)
        }
        try await commands.writePage(0x10, data: Data([0x00, 0x00, 0x00, 0x04]), memoryMap: map, allowIrreversible: true)
        #expect(mock.sentCommands == [
            Data([0xA2, 0x0F, 1, 2, 3, 4]),
            Data([0xA2, 0x10, 0x00, 0x00, 0x00, 0x04]),
        ])
    }

    @Test
    func `NDEF format still writes the Capability Container to page 3`() async throws {
        let mock = MockTransport()
        let info = CardInfo(type: .ntag213, uid: mock.identifier)
        let userPages = Int(UltralightMemoryMap.forType(.ntag213).userDataEnd) - 3
        mock.responses = Array(repeating: Data([0x0A]), count: userPages + 1)
        try await CoreExtendedNFC.formatNDEF(info: info, transport: mock)
        #expect(mock.sentCommands.last == Data([0xA2, 0x03, 0xE1, 0x10, 0x12, 0x00]))
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

    // MARK: - Ultralight C detection (MF0ICU1 / MF0ICU2 datasheets, READ)

    @Test
    func `Refiner classifies Ultralight C via READ of page 0x2B after GET_VERSION NAK`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x00]), Data(repeating: 0x00, count: 16)]
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralightC)
        // No AUTHENTICATE is ever sent during identification.
        #expect(mock.sentCommands == [Data([0x60]), Data([0x30, 0x2B])])
    }

    @Test
    func `Refiner keeps plain Ultralight when READ of page 0x2B is NAKed`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x00]), Data([0x00])]
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralight)
        #expect(mock.sentCommands == [Data([0x60]), Data([0x30, 0x2B])])
    }

    @Test
    func `Refiner does not probe after a transport error`() async throws {
        let mock = MockTransport()
        mock.responses = []
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .mifareUltralight)
        #expect(mock.sentCommands == [Data([0x60])])
    }

    @Test
    func `Ultralight C is identified and then dumped without a dangling authentication`() async throws {
        // Stateful MF0ICU2 model: after `1A 00` the tag is mid-authentication
        // and NAKs everything except the AF step (then stays IDLE).
        let tag = UltralightCTagModel()
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: tag.identifier),
            transport: tag
        )
        #expect(refined.type == .mifareUltralightC)

        let dump = try await CoreExtendedNFC.dumpCard(info: refined, transport: tag)
        #expect(dump.pages.count == 44)
        #expect(dump.pages.first?.data == Data([0x00, 0x01, 0x02, 0x03]))
        #expect(!tag.sentCommands.contains { $0.first == 0x1A })
    }

    @Test
    func `Ultralight C model applies the same NAK recovery rule to every NAK`() async throws {
        let tag = UltralightCTagModel()
        // GET_VERSION NAK, then the tag is re-activated for the READ.
        #expect(try await tag.send(Data([0x60])) == Data([0x00]))
        #expect(try await tag.send(Data([0x30, 0x00])).count == 16)
        // AUTHENTICATE leaves it mid-authentication: the READ is NAKed, the
        // authentication state is dropped, and the next READ works again.
        #expect(try await tag.send(Data([0x1A, 0x00])).first == 0xAF)
        #expect(try await tag.send(Data([0x30, 0x00])) == Data([0x00]))
        #expect(try await tag.send(Data([0x30, 0x00])).count == 16)
        #expect(tag.reactivations == 2)
    }

    @Test
    func `Ultralight C probe rethrows session loss instead of reporting plain Ultralight`() async {
        let transport = ScriptedUltralightTransport(results: [
            .success(Data([0x00])), // GET_VERSION NAK
            .failure(NFCError.sessionInvalidated("Session invalidated")), // READ 0x2B
        ])
        do {
            _ = try await CoreExtendedNFC.refineCardInfo(
                CardInfo(type: .mifareUltralight, uid: transport.identifier),
                transport: transport
            )
            Issue.record("expected sessionInvalidated")
        } catch NFCError.sessionInvalidated {
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test
    func `Ultralight C probe rethrows cancellation`() async {
        let transport = ScriptedUltralightTransport(results: [.failure(CancellationError())])
        await #expect(throws: CancellationError.self) {
            _ = try await UltralightCommands(transport: transport).probeUltralightCMemory()
        }
    }

    @Test
    func `Ultralight C probe treats a missing answer as plain Ultralight`() async throws {
        let transport = ScriptedUltralightTransport(results: [.failure(NFCError.tagConnectionLost)])
        #expect(try await UltralightCommands(transport: transport).probeUltralightCMemory() == false)
    }

    @Test
    func `Refiner rethrows session loss from GET_VERSION`() async {
        let transport = ScriptedUltralightTransport(results: [.failure(NFCError.userCanceled)])
        do {
            _ = try await CoreExtendedNFC.refineCardInfo(
                CardInfo(type: .mifareUltralight, uid: transport.identifier),
                transport: transport
            )
            Issue.record("expected userCanceled")
        } catch NFCError.userCanceled {
        } catch {
            Issue.record("unexpected error \(error)")
        }
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

/// Minimal MF0ICU2 (Ultralight C) state model for identification tests.
///
/// One rule for every NAK, matching the library's documented assumption
/// (``UltralightCommands/probeUltralightCMemory()``): per the datasheet a NAK
/// sends the tag to IDLE, and CoreNFC is assumed to re-activate it before the
/// next command. The model therefore drops any pending state on a NAK and
/// counts a re-activation when the next command arrives.
/// - GET_VERSION is not implemented: NAK.
/// - READ of 0x00-0x2B returns 4 pages, rolling over to page 0 after 0x2B.
/// - AUTHENTICATE `1A 00` answers `AF ‖ ek(RndB)` and leaves the tag
///   mid-authentication; any next command other than the AF step is NAKed
///   (mid-authentication is lost with the NAK, so the command is not executed).
private final class UltralightCTagModel: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    private(set) var sentCommands: [Data] = []
    /// Number of times the (assumed) CoreNFC re-activation brought the tag back from IDLE.
    private(set) var reactivations = 0
    private var midAuthentication = false
    private var idle = false

    func send(_ data: Data) async throws -> Data {
        sentCommands.append(data)
        if idle {
            idle = false
            reactivations += 1
        }
        if midAuthentication {
            return nak()
        }
        guard let command = data.first else { return nak() }
        switch command {
        case 0x1A:
            midAuthentication = true
            return Data([0xAF]) + Data(repeating: 0x5A, count: 8)
        case 0x30 where data.count == 2 && data[data.startIndex + 1] <= 0x2B:
            let start = Int(data[data.startIndex + 1])
            return Data((0 ..< 16).map { offset in
                let page = (start + offset / 4) % 0x2C
                return UInt8(truncatingIfNeeded: page * 4 + offset % 4)
            })
        default:
            return nak()
        }
    }

    private func nak() -> Data {
        midAuthentication = false
        idle = true
        return Data([0x00])
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("Type 2 tag model")
    }
}

/// Transport that replays a fixed list of results, including thrown errors.
private final class ScriptedUltralightTransport: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    private var results: [Result<Data, any Error>]

    init(results: [Result<Data, any Error>]) {
        self.results = results
    }

    func send(_: Data) async throws -> Data {
        guard !results.isEmpty else { throw NFCError.tagConnectionLost }
        return try results.removeFirst().get()
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("Type 2 tag model")
    }
}

struct TopLevelUltralightWriteGuardTests {
    @Test
    func `Top-level writePage to page 2 needs the irreversible opt-in`() async throws {
        let transport = MockTransport()
        let lockBytes = Data([0x48, 0x00, 0xFF, 0xFF]) // serial byte, internal, static lock bytes

        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.writePage(2, data: lockBytes, transport: transport)
        }
        #expect(transport.sentCommands.isEmpty)

        transport.responses = [Data([0x0A])] // ACK
        try await CoreExtendedNFC.writePage(2, data: lockBytes, allowIrreversible: true, transport: transport)
        #expect(transport.sentCommands == [Data([0xA2, 0x02]) + lockBytes])
    }

    /// NTAG213 CFG0 is page 29h; without a map the facade cannot tell it from user memory.
    @Test(arguments: [UInt8(0x10), 0x28, 0x29, 0xE5])
    func `Top-level writes above page 15 without a memory map need the opt-in`(page: UInt8) async throws {
        let transport = MockTransport()
        do {
            try await CoreExtendedNFC.writePage(page, data: Data(count: 4), transport: transport)
            Issue.record("expected irreversibleWriteRefused")
        } catch NFCError.irreversibleWriteRefused(page: page) {
        }
        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.compatibilityWrite(page, data: Data(count: 4), transport: transport)
        }
        #expect(transport.sentCommands.isEmpty)

        transport.responses = [Data([0x0A]), Data([0x0A])]
        try await CoreExtendedNFC.writePage(page, data: Data(count: 4), allowIrreversible: true, transport: transport)
        // With a map that has `page` in its user area the write is allowed.
        let map = UltralightMemoryMap(totalPages: 0xFF, userDataStart: 4, userDataEnd: 0xF0, configStart: nil, dynamicLockStart: nil)
        try await CoreExtendedNFC.writePage(page, data: Data(count: 4), memoryMap: map, transport: transport)
        #expect(transport.sentCommands.count == 2)
    }

    @Test
    func `Top-level writes to page 15 without a memory map are allowed`() async throws {
        let transport = MockTransport()
        transport.responses = [Data([0x0A])]
        try await CoreExtendedNFC.writePage(0x0F, data: Data([1, 2, 3, 4]), transport: transport)
        #expect(transport.sentCommands == [Data([0xA2, 0x0F, 1, 2, 3, 4])])
    }
}
