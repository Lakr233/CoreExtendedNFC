// NTAG (210/212/213/215/216) test suite.
//
// ## References
// - NXP NTAG213/215/216 datasheet: GET_VERSION response, memory maps
//   https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
// - NXP NTAG210/212 datasheet: GET_VERSION storage size 0x0B (NTAG210, 20 pages)
//   and 0x0E (NTAG212, 41 pages: user 04h-23h, dyn lock 24h, CFG0 25h, CFG1 26h, PWD 27h, PACK 28h)
// - NXP NT3H2111/2211 (NTAG I2C) datasheet
// - NTAG213: 144 bytes user memory (pages 4-39)
// - NTAG215: 504 bytes user memory (pages 4-129)
// - NTAG216: 888 bytes user memory (pages 4-225)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NTAGTests {
    @Test
    func `READ_SIG sends 0x3C 0x00`() async throws {
        let mock = MockTransport()
        mock.responses = [Data(repeating: 0xEE, count: 32)]
        let commands = UltralightCommands(transport: mock)

        let sig = try await commands.readSignature()
        #expect(mock.sentCommands[0] == Data([0x3C, 0x00]))
        #expect(sig.count == 32)
    }

    @Test
    func `READ_CNT sends 0x39 and parses 3-byte LE counter`() async throws {
        let mock = MockTransport()
        // Counter value: 0x01 + 0x02<<8 + 0x03<<16 = 197121
        mock.responses = [Data([0x01, 0x02, 0x03])]
        let commands = UltralightCommands(transport: mock)

        let count = try await commands.readCounter()
        #expect(mock.sentCommands[0] == Data([0x39, 0x02]))
        #expect(count == 197_121)
    }

    @Test
    func `NTAG variant detection from GET_VERSION`() throws {
        let ntag213Data = Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03])
        let version = try UltralightVersionResponse(data: ntag213Data)
        #expect(NTAGVariant.detect(from: version) == .ntag213)
    }

    @Test
    func `NTAG memory map static accessors`() {
        #expect(UltralightMemoryMap.ntag213.totalPages == 45)
        #expect(UltralightMemoryMap.ntag215.totalPages == 135)
        #expect(UltralightMemoryMap.ntag216.totalPages == 231)
    }

    // MARK: - NTAG210 / NTAG212 (NXP NTAG210/212 datasheet)

    @Test
    func `NTAG210 and NTAG212 GET_VERSION storage sizes`() throws {
        let ntag210 = try UltralightVersionResponse(data: Data([0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0B, 0x03]))
        #expect(ntag210.cardType == .ntag210)
        #expect(ntag210.totalPages == 20)
        #expect(ntag210.userPages == 12)

        let ntag212 = try UltralightVersionResponse(data: Data([0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0E, 0x03]))
        #expect(ntag212.cardType == .ntag212)
        #expect(ntag212.totalPages == 41)
        #expect(ntag212.userPages == 32)
    }

    @Test
    func `Unknown NTAG storage size falls back to the generic 16-page map`() throws {
        let version = try UltralightVersionResponse(data: Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x15, 0x03]))
        #expect(version.cardType == .mifareUltralight)
        #expect(UltralightMemoryMap.forType(version.cardType).userDataEnd == 15)
    }

    @Test
    func `NTAG210 and NTAG212 memory maps`() {
        #expect(UltralightMemoryMap.forType(.ntag210) == UltralightMemoryMap(
            totalPages: 20, userDataStart: 4, userDataEnd: 15, configStart: 16, dynamicLockStart: nil
        ))
        #expect(UltralightMemoryMap.forType(.ntag212) == UltralightMemoryMap(
            totalPages: 41, userDataStart: 4, userDataEnd: 35, configStart: 37, dynamicLockStart: 36
        ))
    }

    @Test
    func `User data area never overlaps lock or config pages`() {
        let types: [CardType] = [
            .mifareUltralight, .mifareUltralightC, .mifareUltralightEV1_MF0UL11, .mifareUltralightEV1_MF0UL21,
            .ntag210, .ntag212, .ntag213, .ntag215, .ntag216,
        ]
        for type in types {
            let map = UltralightMemoryMap.forType(type)
            #expect(map.userDataEnd < map.totalPages, "\(type.description)")
            if let configStart = map.configStart {
                #expect(map.userDataEnd < configStart, "\(type.description)")
            }
            if let lockStart = map.dynamicLockStart {
                #expect(map.userDataEnd < lockStart, "\(type.description)")
            }
        }
    }

    @Test
    func `Formatting a refined NTAG212 never writes lock, config or password pages`() async throws {
        let mock = MockTransport()
        mock.responses = [Data([0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0E, 0x03])]
            + Array(repeating: Data([0x0A]), count: 64)
        let refined = try await CoreExtendedNFC.refineCardInfo(
            CardInfo(type: .mifareUltralight, uid: mock.identifier),
            transport: mock
        )
        #expect(refined.type == .ntag212)

        try await CoreExtendedNFC.formatNDEF(info: refined, transport: mock)

        let pagesWritten = mock.sentCommands.filter { $0.first == 0xA2 }.map { $0[1] }
        #expect(pagesWritten.allSatisfy { $0 == 3 || (4 ... 35).contains($0) })
        #expect(pagesWritten.contains(35))
        // CC data area size: 128 bytes / 8 = 0x10.
        #expect(mock.sentCommands.last == Data([0xA2, 0x03, 0xE1, 0x10, 0x10, 0x00]))
    }

    @Test
    func `NTAG212 dump covers all 41 pages`() async throws {
        let mock = MockTransport()
        mock.responses = Array(repeating: Data(repeating: 0x00, count: 16), count: 11)
        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .ntag212, uid: mock.identifier),
            transport: mock
        )
        #expect(dump.pages.count == 41)
        #expect(dump.pages.last?.number == 40)
    }

    @Test
    func `Read-protected NTAG dump keeps the readable pages`() async throws {
        let mock = MockTransport()
        // Pages 0-7 readable, then a NAK (short frame) at AUTH0 = 8.
        mock.responses = [
            Data(repeating: 0x11, count: 16),
            Data(repeating: 0x22, count: 16),
            Data([0x00]),
        ]
        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .ntag213, uid: mock.identifier),
            transport: mock
        )
        #expect(dump.pages.count == 8)
        #expect(dump.capabilities.contains(.partiallyReadable))
        #expect(dump.facts.contains(where: { $0.key == "Unauthenticated Boundary" && $0.value == "Page 8" }))
    }
}
