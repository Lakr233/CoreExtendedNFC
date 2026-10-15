// Dump interoperability tests: export format, page-count verification.
//
// ## References
// - libnfc nfc-mfultralight.c: MFD binary format (raw page concatenation)
//   https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-mfultralight.c
// - Flipper Zero NFC file format (firmware source)
// - Proxmark3 client source: MFU dump header format
// - NXP NTAG213/215/216 datasheet: page counts and memory maps
//   https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DumpInteropTests {
    @Test
    func `Structured dump export includes normalized fields`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .ntag213, uid: Data([0x01, 0x02, 0x03, 0x04])),
            pages: [.init(number: 4, data: Data([0x03, 0x03, 0xD1, 0x01]))],
            ndefMessage: NDEFMessage.text("Hi").data,
            facts: [.init(key: "Write Access", value: "Writable")],
            capabilities: [.readable, .writable]
        )

        let json = try dump.exportStructuredJSON()

        #expect(json.contains("\"cardType\""))
        #expect(json.contains("\"uid\""))
        #expect(json.contains("\"capabilities\""))
        #expect(json.contains("\"parsedNDEF\""))
    }

    @Test
    func `Export artifacts include binary, JSON, and libnfc MFD when supported`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .ntag213, uid: Data([0xDE, 0xAD, 0xBE, 0xEF])),
            pages: [
                .init(number: 4, data: Data([0x01, 0x02, 0x03, 0x04])),
                .init(number: 5, data: Data([0x05, 0x06, 0x07, 0x08])),
            ],
            capabilities: [.readable]
        )

        let artifacts = try dump.exportArtifacts()

        #expect(artifacts.count == 6)
        #expect(artifacts.map(\.suggestedFilename).contains("ntag-deadbeef.json"))
        #expect(artifacts.map(\.suggestedFilename).contains("ntag-deadbeef.bin"))
        #expect(artifacts.map(\.suggestedFilename).contains("ntag-deadbeef.mfd"))
        #expect(artifacts.map(\.suggestedFilename).contains("ntag-deadbeef.nfc"))
        #expect(artifacts.map(\.suggestedFilename).contains("ntag-deadbeef-proxmark3.bin"))
        #expect(try dump.exportLibNFCMFD() == Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
    }

    @Test
    func `Flipper Zero export round-trips page dumps`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(
                type: .ntag213,
                uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]),
                atqa: Data([0x44, 0x00]),
                sak: 0x00
            ),
            pages: [
                .init(number: 0, data: Data([0x04, 0x57, 0x01, 0x84])),
                .init(number: 1, data: Data([0xCA, 0x53, 0x28, 0x80])),
                .init(number: 2, data: Data([0xDB, 0x48, 0x00, 0x00])),
                .init(number: 4, data: Data([0x03, 0x03, 0xD1, 0x01])),
            ]
        )

        let exported = try dump.exportFlipperNFC()
        let imported = try MemoryDump.importFlipperNFC(exported)

        #expect(exported.contains("Filetype: Flipper NFC device"))
        #expect(exported.contains("Device type: NTAG/Ultralight"))
        #expect(exported.contains("Mifare version: 00 04 04 02 01 00 0F 03"))
        #expect(imported.cardInfo.type == .ntag213)
        #expect(imported.cardInfo.uid == dump.cardInfo.uid)
        #expect(imported.pages.first?.data == dump.pages.first?.data)
    }

    @Test
    func `Proxmark3 MFU binary export round-trips page dumps`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(
                type: .ntag213,
                uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80])
            ),
            pages: [
                .init(number: 0, data: Data([0x04, 0x57, 0x01, 0x84])),
                .init(number: 1, data: Data([0xCA, 0x53, 0x28, 0x80])),
                .init(number: 2, data: Data([0xDB, 0x48, 0x00, 0x00])),
                .init(number: 44, data: Data([0x00, 0x00, 0x00, 0x00])),
            ]
        )

        let exported = try dump.exportProxmark3MFU()
        let imported = try MemoryDump.importProxmark3MFU(exported)

        #expect(exported.count == 56 + 45 * 4)
        #expect(imported.cardInfo.type == .ntag213)
        #expect(imported.cardInfo.uid == dump.cardInfo.uid)
        #expect(imported.pages.count == 45)
        #expect(imported.pages[44].data == Data([0x00, 0x00, 0x00, 0x00]))
    }

    @Test
    func `Proxmark3 plain binary import is accepted`() throws {
        let imported = try MemoryDump.importProxmark3MFU(
            Data([
                0x04, 0x57, 0x01, 0x84,
                0xCA, 0x53, 0x28, 0x80,
                0xDB, 0x48, 0x00, 0x00,
                0xE1, 0x10, 0x12, 0x00,
            ])
        )

        #expect(imported.cardInfo.uid == Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]))
        #expect(imported.pages.count == 4)
        #expect(imported.pages[3].data == Data([0xE1, 0x10, 0x12, 0x00]))
    }

    @Test
    func `Dump diff summary reports changed blocks and files`() {
        let lhs = MemoryDump(
            cardInfo: CardInfo(type: .iso15693_generic, uid: Data([0xE0, 0x01, 0x02, 0x03])),
            blocks: [
                .init(number: 0, data: Data([0x01, 0x02, 0x03, 0x04])),
                .init(number: 1, data: Data([0x05, 0x06, 0x07, 0x08])),
            ],
            files: [.init(fileID: 1, data: Data([0xAA]))],
            facts: [.init(key: "AFI", value: "0x00")],
            capabilities: [.readable]
        )

        let rhs = MemoryDump(
            cardInfo: CardInfo(type: .iso15693_generic, uid: Data([0xE0, 0x01, 0x02, 0x03])),
            blocks: [
                .init(number: 0, data: Data([0x01, 0x02, 0x03, 0x04])),
                .init(number: 1, data: Data([0x09, 0x06, 0x07, 0x08])),
            ],
            files: [.init(fileID: 2, data: Data([0xBB]))],
            facts: [.init(key: "AFI", value: "0x07")],
            capabilities: [.readable]
        )

        let diff = lhs.diffSummary(against: rhs)

        #expect(diff.sameUID)
        #expect(diff.blockChanges == 1)
        #expect(diff.fileChanges == 2)
        #expect(diff.factChanges == 1)
        #expect(diff.hasDifferences)
    }

    @Test
    func `libnfc MFD export rejects non page-based dumps`() {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .iso15693_generic, uid: Data([0xE0, 0x01, 0x02, 0x03])),
            blocks: [.init(number: 0, data: Data([0xAA, 0xBB, 0xCC, 0xDD]))]
        )

        #expect(throws: NFCError.self) {
            _ = try dump.exportLibNFCMFD()
        }
    }

    // MARK: - Import / export / diff robustness

    @Test
    func `diffSummary tolerates DESFire files with the same id in different apps`() {
        let info = CardInfo(type: .mifareDesfireEV1, uid: Data(count: 7))
        let lhs = MemoryDump(cardInfo: info, files: [.init(fileID: 1, data: Data([1])), .init(fileID: 1, data: Data([2]))])
        let rhs = MemoryDump(cardInfo: info, files: [.init(fileID: 1, data: Data([1])), .init(fileID: 1, data: Data([3]))])

        #expect(lhs.diffSummary(against: lhs).fileChanges == 0) // before: traps
        // The second occurrence differs and is counted, not silently merged away.
        #expect(lhs.diffSummary(against: rhs).fileChanges == 1)
    }

    @Test
    func `diffSummary tolerates repeated pages and fact keys`() {
        let info = CardInfo(type: .ntag213, uid: Data(count: 7))
        let dump = MemoryDump(
            cardInfo: info,
            pages: [.init(number: 4, data: Data(count: 4)), .init(number: 4, data: Data(count: 4))],
            facts: [.init(key: "K", value: "1"), .init(key: "K", value: "2")]
        )
        let diff = dump.diffSummary(against: dump) // before: traps
        #expect(!diff.hasDifferences)
    }

    @Test
    func `exports tolerate duplicate page numbers`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .ntag213, uid: Data(count: 7)),
            pages: [.init(number: 4, data: Data([1, 1, 1, 1])), .init(number: 4, data: Data([2, 2, 2, 2]))]
        )
        let text = try dump.exportFlipperNFC() // before: traps
        #expect(text.contains("Page 4: 02 02 02 02"))
        _ = try dump.exportProxmark3MFU()
    }

    @Test
    func `Flipper import rejects page numbers outside 0 to 255`() {
        for pageLine in ["Page 300: 00 00 00 00", "Page 256: 00 00 00 00", "Page -1: 00 00 00 00"] {
            let text = "Filetype: Flipper NFC device\nDevice type: NTAG/Ultralight\nUID: 04 01 02 03 04 05 06\nPages total: 1\n\(pageLine)"
            #expect(throws: NFCError.self) { // before: traps
                _ = try MemoryDump.importFlipperNFC(text)
            }
        }
    }

    @Test
    func `Flipper import rejects duplicate page lines`() {
        let text = "Filetype: Flipper NFC device\nDevice type: NTAG/Ultralight\nUID: 04 01 02 03 04 05 06\nPages total: 2\nPage 0: 00 00 00 00\nPage 0: 11 11 11 11"
        #expect(throws: NFCError.self) {
            _ = try MemoryDump.importFlipperNFC(text)
        }
    }

    @Test
    func `Proxmark import keeps plain 16-page binaries intact`() throws {
        let plain = Data((0 ..< 64).map { UInt8($0) })
        let dump = try MemoryDump.importProxmark3MFU(plain)
        #expect(dump.pages.count == 16) // before: 2
        #expect(dump.pages.first?.data == Data([0, 1, 2, 3]))
        #expect(dump.pages.last?.number == 15)
    }

    @Test
    func `Proxmark import synthesises the Type 2 ATQA most-significant byte first`() throws {
        let dump = try MemoryDump.importProxmark3MFU(Data(count: 64))
        #expect(dump.cardInfo.atqa == Data([0x00, 0x44]))
        #expect(CardIdentifier.identify(atqa: try #require(dump.cardInfo.atqa), sak: 0x00) == .mifareUltralight)
    }

    @Test
    func `Proxmark import detects the mfu_dump_t header by its last-page index`() throws {
        // 56-byte header: version[8] tbo[2] tbo1[1] pages[1] signature[32] counters[12].
        var header = Data(count: 56)
        header.replaceSubrange(0 ..< 8, with: Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03]))
        header[11] = 44 // last page index of NTAG213 (45 pages)
        let pages = Data((0 ..< 45 * 4).map { UInt8(truncatingIfNeeded: $0) })

        let dump = try MemoryDump.importProxmark3MFU(header + pages)
        #expect(dump.pages.count == 45)
        #expect(dump.cardInfo.type == .ntag213)
        #expect(dump.pages[0].data == Data([0, 1, 2, 3]))
    }

    @Test
    func `Proxmark import rejects more than 256 pages`() {
        #expect(throws: NFCError.self) { // before: traps
            _ = try MemoryDump.importProxmark3MFU(Data(count: 257 * 4))
        }
    }

    @Test
    func `Flipper and Proxmark export keep pages beyond the inferred memory map`() throws {
        let pages = (0 ..< 20).map { MemoryDump.Page(number: UInt8($0), data: Data(repeating: UInt8($0), count: 4)) }
        let dump = MemoryDump(cardInfo: CardInfo(type: .mifareUltralight, uid: Data(count: 7)), pages: pages)

        let text = try dump.exportFlipperNFC()
        #expect(text.contains("Pages total: 20")) // before: 16
        #expect(text.contains("Page 19: 13 13 13 13"))

        let binary = try dump.exportProxmark3MFU()
        #expect(binary.count == 56 + 20 * 4)
        #expect(binary[11] == 19)
    }

    @Test
    func `Export of a page-255 dump does not overflow the page count`() throws {
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .smartMX, uid: Data(count: 7)),
            pages: [.init(number: 255, data: Data([1, 2, 3, 4]))]
        )
        let text = try dump.exportFlipperNFC() // before: UInt8 overflow trap in inferredPageTotal
        #expect(text.contains("Pages total: 256"))
    }

    // MARK: - Flipper firmware loadability (mf_ultralight_load / iso14443_3a_load)

    @Test
    func `Flipper export writes every key the firmware loader requires, in order`() throws {
        let pages = (0 ..< 45).map { MemoryDump.Page(number: UInt8($0), data: Data([UInt8($0), 0, 0, 0])) }
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .ntag213, uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80])),
            pages: pages
        )

        let lines = try dump.exportFlipperNFC().split(separator: "\n").map(String.init)

        let expectedHeader = [
            "Filetype: Flipper NFC device",
            "Version: 4",
            "Device type: NTAG/Ultralight",
            "UID: 04 57 01 CA 53 28 80",
            "ATQA: 00 44",
            "SAK: 00",
            "Data format version: 2",
            "NTAG/Ultralight type: NTAG213",
            "Signature: " + Array(repeating: "00", count: 32).joined(separator: " "),
            "Mifare version: 00 04 04 02 01 00 0F 03",
            "Counter 0: 0",
            "Tearing 0: 00",
            "Counter 1: 0",
            "Tearing 1: 00",
            "Counter 2: 0",
            "Tearing 2: 00",
            "Pages total: 45",
            "Pages read: 45",
            "Page 0: 00 00 00 00",
        ]
        #expect(Array(lines.prefix(expectedHeader.count)) == expectedHeader)
        #expect(lines.last == "Page 44: 2C 00 00 00")
    }

    @Test
    func `Flipper export of an unread tail reports fewer pages read`() throws {
        // Ultralight C pages 44-47 hold the 3DES key and cannot be read.
        let pages = (0 ..< 44).map { MemoryDump.Page(number: UInt8($0), data: Data(count: 4)) }
        let dump = MemoryDump(cardInfo: CardInfo(type: .mifareUltralightC, uid: Data(count: 7)), pages: pages)

        let text = try dump.exportFlipperNFC()
        #expect(text.contains("NTAG/Ultralight type: Mifare Ultralight C"))
        #expect(text.contains("Mifare version: 00 00 00 00 00 00 00 00"))
        #expect(text.contains("Pages total: 48\nPages read: 44\n"))
        #expect(try MemoryDump.importFlipperNFC(text).cardInfo.type == .mifareUltralightC)
    }

    @Test
    func `NTAG210 and NTAG212 round-trip through Flipper and Proxmark exports`() throws {
        for (type, pageCount, version) in [
            (CardType.ntag210, 20, "00 04 04 01 01 00 0B 03"),
            (CardType.ntag212, 41, "00 04 04 01 01 00 0E 03"),
        ] {
            let pages = (0 ..< pageCount).map { MemoryDump.Page(number: UInt8($0), data: Data(count: 4)) }
            let dump = MemoryDump(cardInfo: CardInfo(type: type, uid: Data(count: 7)), pages: pages)

            let text = try dump.exportFlipperNFC()
            #expect(text.contains("Mifare version: \(version)"))
            #expect(try MemoryDump.importFlipperNFC(text).cardInfo.type == type)
            #expect(try MemoryDump.importProxmark3MFU(dump.exportProxmark3MFU()).cardInfo.type == type)
        }
    }

    @Test
    func `Proxmark import rejects a header whose page count disagrees with the file`() {
        var header = Data(count: 56)
        header.replaceSubrange(0 ..< 8, with: Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03]))
        header[11] = 45 // claims 46 pages, but 45 follow
        let pages = Data(count: 45 * 4)

        #expect(throws: NFCError.self) { // before: imported as 59 plain pages
            _ = try MemoryDump.importProxmark3MFU(header + pages)
        }
        #expect(throws: NFCError.self) { // truncated mid-page
            _ = try MemoryDump.importProxmark3MFU(header + pages.prefix(45 * 4 - 2))
        }
    }
}
