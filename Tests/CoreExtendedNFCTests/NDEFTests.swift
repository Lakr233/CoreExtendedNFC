// NDEF message and record tests: round-trip encoding, URI prefixes, TLV parsing.
//
// ## References
// - NFC Forum NDEF Technical Specification (NFC Data Exchange Format)
// - NFC Forum Type 2 Tag Operation Specification: TLV block format
// - NFC Forum Type 5 Tag Operation Specification
// - NFC Forum URI Record Type Definition: URI prefix table
// - NFC Forum Smart Poster Record Type Definition
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NDEFTests {
    @Test
    func `Text NDEF record round-trips`() throws {
        let message = NDEFMessage(records: [.text("Hello", languageCode: "en")])

        let reparsed = try NDEFMessage(data: message.data)

        #expect(reparsed.records.count == 1)
        #expect(reparsed.records[0].parsedPayload == .text(languageCode: "en", text: "Hello"))
    }

    @Test
    func `URI NDEF record decodes common prefix`() throws {
        let message = NDEFMessage.uri("https://www.example.com/path")

        let reparsed = try NDEFMessage(data: message.data)

        #expect(reparsed.records.count == 1)
        #expect(reparsed.records[0].parsedPayload == .uri("https://www.example.com/path"))
    }

    @Test
    func `Smart Poster decodes nested URI and title`() throws {
        let message = NDEFMessage(records: [.smartPoster(uri: "https://openai.com", title: "OpenAI")])

        let reparsed = try NDEFMessage(data: message.data)

        #expect(reparsed.records.count == 1)
        #expect(reparsed.records[0].parsedPayload == .smartPoster(uri: "https://openai.com", title: "OpenAI"))
    }

    @Test
    func `Type 2 TLV extraction finds NDEF payload`() throws {
        let payload = NDEFMessage.text("Hi").data
        let tlv = Data([0x03, UInt8(payload.count)]) + payload + Data([0xFE, 0x00])
        let pages: [MemoryDump.Page] = [MemoryDump.Page(number: 3, data: Data([0xE1, 0x10, 0x06, 0x00]))]
            + Array(stride(from: 0, to: tlv.count, by: 4)).enumerated().map { pair in
                let (index, byteOffset) = pair
                let chunk = Data((tlv + Data(repeating: 0x00, count: 16))[byteOffset ..< byteOffset + 4])
                return MemoryDump.Page(number: UInt8(index + 4), data: chunk)
            }

        let extracted = NDEFTagMapping.extractType2Message(from: pages)

        #expect(extracted == payload)
        #expect(try NDEFMessage(data: extracted ?? Data()).records.first?.parsedPayload == .text(languageCode: "en", text: "Hi"))
    }

    @Test
    func `Type 5 TLV extraction finds NDEF payload`() {
        let payload = NDEFMessage.uri("https://example.com").data
        let bytes = Data([0xE1, 0x40, 0x40, 0x01, 0x03, UInt8(payload.count)]) + payload + Data([0xFE, 0x00])
        let blocks: [MemoryDump.Block] = Array(stride(from: 0, to: bytes.count, by: 4)).enumerated().map { pair in
            let (index, offset) = pair
            let slice = Data((bytes + Data(repeating: 0x00, count: 16))[offset ..< offset + 4])
            return MemoryDump.Block(number: index, data: slice)
        }

        let extracted = NDEFTagMapping.extractType5Message(from: blocks)

        #expect(extracted == payload)
    }

    @Test
    func `MemoryDump summary exposes parsed NDEF and capabilities`() {
        let message = NDEFMessage.text("Summary")
        let dump = MemoryDump(
            cardInfo: CardInfo(type: .type4NDEF, uid: Data([0x01, 0x02, 0x03, 0x04])),
            files: [.init(identifier: Type4Constants.ndefFileID, data: message.data, name: "NDEF File")],
            ndefMessage: message.data,
            facts: [.init(key: "Write Access", value: "Writable")],
            capabilities: [.readable, .writable]
        )

        #expect(dump.parsedNDEFMessage?.records.count == 1)
        #expect(dump.summary.capabilities == [.readable, .writable])
        #expect(dump.exportHex().contains("Parsed NDEF"))
    }

    @Test
    func `Format Type 2 writes CC page and clears user data`() async throws {
        let transport = MockTransport()
        // 12 user page writes (pages 4–15) + 1 CC write (page 3) = 13
        transport.responses = Array(repeating: Data([0x0A]), count: 13)
        let memory = UltralightMemoryMap.forType(.mifareUltralight)

        try await CoreExtendedNFC.formatNDEF(
            info: CardInfo(type: .mifareUltralight, uid: Data([0x01, 0x02, 0x03, 0x04])),
            transport: transport
        )

        #expect(transport.sentCommands.count == 13)

        // User pages are written first (pages 4–15), all via WRITE command (0xA2)
        let expectedArea = try NDEFTagMapping.buildType2Area(message: Data(), capacity: 48)
        for i in 0 ..< 12 {
            let page = memory.userDataStart + UInt8(i)
            #expect(transport.sentCommands[i].prefix(2) == Data([0xA2, page]))
            let expected = Data(expectedArea[i * 4 ..< i * 4 + 4])
            #expect(Data(transport.sentCommands[i].dropFirst(2)) == expected)
        }

        // CC is written last to page 3 — avoids half-formatted state on failure
        #expect(transport.sentCommands[12] == Data([0xA2, 0x03, 0xE1, 0x10, 0x06, 0x00]))
    }

    @Test
    func `Type 2 CC uses the NXP data area sizes`() {
        // NTAG213/215/216 and NTAG210/212 datasheets §8.5.6; Ultralight / Ultralight C use
        // their whole user area (48 and 144 bytes).
        #expect(NDEFTagMapping.buildType2CC(for: .ntag210) == Data([0xE1, 0x10, 0x06, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .ntag212) == Data([0xE1, 0x10, 0x10, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .ntag213) == Data([0xE1, 0x10, 0x12, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .ntag215) == Data([0xE1, 0x10, 0x3E, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .ntag216) == Data([0xE1, 0x10, 0x6D, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .mifareUltralight) == Data([0xE1, 0x10, 0x06, 0x00]))
        #expect(NDEFTagMapping.buildType2CC(for: .mifareUltralightC) == Data([0xE1, 0x10, 0x12, 0x00]))
    }

    @Test
    func `Type 2 write refuses a message larger than the CC data area before writing`() async {
        let transport = MockTransport()
        // NTAG215: page 3 = E1 10 3E 00, so the NDEF area is 0x3E × 8 = 496 bytes.
        transport.responses = [Data([0xE1, 0x10, 0x3E, 0x00]) + Data(count: 12)]
            + Array(repeating: Data([0x0A]), count: 200)
        // 498-byte payload: TLV = 03 FF 01 F2 + 498 = 502 bytes (plus an optional FE).
        // It fits the 504 user bytes but not the 496-byte data area readers scan.
        // Record: header, type length, 4-byte payload length, "a/b", payload = 9 + 489 bytes.
        let message = NDEFMessage(records: [.mime(type: "a/b", data: Data(count: 489))])
        #expect(message.data.count == 498)

        await #expect(throws: NFCError.ndefCapacityExceeded(required: 502, capacity: 496)) {
            try await CoreExtendedNFC.writeNDEF(
                message,
                info: CardInfo(type: .ntag215, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
                transport: transport
            )
        }
        #expect(transport.sentCommands == [Data([0x30, 0x03])]) // before: 126 page writes
    }

    @Test
    func `Type 2 write refuses a tag without a Capability Container`() async {
        let transport = MockTransport()
        transport.responses = [Data(count: 16)] + Array(repeating: Data([0x0A]), count: 12)

        await #expect(throws: NFCError.tagNotNDEFFormatted) {
            try await CoreExtendedNFC.writeNDEF(
                .text("Hi"),
                info: CardInfo(type: .mifareUltralight, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
                transport: transport
            )
        }
        #expect(transport.sentCommands == [Data([0x30, 0x03])])
    }

    @Test
    func `Writing an empty NDEF message erases the tag to 03 00 FE`() async throws {
        let transport = MockTransport()
        transport.responses = [Data([0xE1, 0x10, 0x06, 0x00]) + Data(count: 12)]
            + Array(repeating: Data([0x0A]), count: 12)

        try await CoreExtendedNFC.writeNDEF( // before: threw unsupportedOperation
            NDEFMessage(records: []),
            info: CardInfo(type: .mifareUltralight, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            transport: transport
        )

        #expect(transport.sentCommands.count == 13)
        #expect(transport.sentCommands[1] == Data([0xA2, 0x04, 0x03, 0x00, 0xFE, 0x00]))
        #expect(transport.sentCommands[2] == Data([0xA2, 0x05, 0x00, 0x00, 0x00, 0x00]))
    }

    @Test
    func `Deeply nested Smart Posters parse in linear time`() {
        // 24 nested Sp records around a URI record D1 01 01 55 00 (Smart Poster RTD 1.0).
        var payload = Data([0xD1, 0x01, 0x01, 0x55, 0x00])
        for _ in 0 ..< 24 {
            let header: UInt8 = payload.count < 256 ? 0xD1 : 0xC1
            var record = Data([header, 0x02])
            if payload.count < 256 {
                record.append(UInt8(payload.count))
            } else {
                record.append(contentsOf: withUnsafeBytes(of: UInt32(payload.count).bigEndian, Array.init))
            }
            record.append(contentsOf: [0x53, 0x70])
            payload = record + payload
        }
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x53, 0x70]), payload: payload)

        let start = Date()
        _ = record.displayValue
        _ = record.displayType
        #expect(Date().timeIntervalSince(start) < 0.5) // before: 2^24 nested parses
        // Only direct URI / Text children are decoded; the outer poster has neither.
        #expect(record.parsedPayload == .smartPoster(uri: nil, title: nil))
    }

    @Test
    func `URI abbreviation picks the longest matching prefix`() {
        // URI RTD 1.0 Table 3 identifier codes.
        #expect(NDEFRecord.uri("http://www.example.com").payload == Data([0x01]) + Data("example.com".utf8))
        #expect(NDEFRecord.uri("https://www.example.com").payload.first == 0x02)
        #expect(NDEFRecord.uri("http://example.com").payload.first == 0x03)
        #expect(NDEFRecord.uri("https://example.com").payload.first == 0x04)
        #expect(NDEFRecord.uri("urn:epc:id:sgtin:1").payload == Data([0x1E]) + Data("sgtin:1".utf8))
        #expect(NDEFRecord.uri("urn:epc:x").payload.first == 0x22)
        #expect(NDEFRecord.uri("urn:x").payload.first == 0x13)
        #expect(NDEFRecord.uri("ftp://ftp.example.com").payload.first == 0x08)
        #expect(NDEFRecord.uri("example").payload == Data("\0example".utf8))
    }

    @Test
    func `Format Type 5 writes CC and empty NDEF blocks`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 5,
                icReference: 0x01
            )
        )

        try await CoreExtendedNFC.formatNDEF(
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        #expect(transport.writtenBlocks.count == 5)
        // Block 0 is CC
        #expect(transport.writtenBlocks[0].data.prefix(2) == Data([0xE1, 0x40]))
        // Block 1 starts with empty NDEF TLV (03 00 FE)
        #expect(transport.writtenBlocks[1].data[0] == 0x03)
        #expect(transport.writtenBlocks[1].data[1] == 0x00)
        #expect(transport.writtenBlocks[1].data[2] == 0xFE)
    }

    @Test
    func `Format NDEF throws for unsupported card families`() async throws {
        let transport = MockTransport()
        await #expect(throws: NFCError.tagNotSupported) {
            try await CoreExtendedNFC.formatNDEF(
                info: CardInfo(type: .type4NDEF, uid: Data([0x01, 0x02, 0x03, 0x04])),
                transport: transport
            )
        }
    }

    @Test
    func `Unified Type 2 NDEF write lays out TLV pages`() async throws {
        let transport = MockTransport()
        transport.responses = [Data([0xE1, 0x10, 0x06, 0x00]) + Data(count: 12)]
            + Array(repeating: Data([0x0A]), count: 13)

        let message = NDEFMessage.text("Hi")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .mifareUltralight, uid: Data([0x01, 0x02, 0x03, 0x04])),
            transport: transport
        )

        // READ page 3 (CC), page 4 with L = 0, pages 5-15, then page 4 with the real L.
        #expect(transport.sentCommands.count == 14)
        #expect(transport.sentCommands[0] == Data([0x30, 0x03]))

        let expectedArea = try NDEFTagMapping.buildType2Area(message: message.data, capacity: 48)
        var interim = expectedArea.prefix(4)
        interim[interim.startIndex + 1] = 0x00
        #expect(transport.sentCommands[1] == Data([0xA2, 0x04]) + interim)
        #expect(transport.sentCommands[2] == Data([0xA2, 0x05]) + expectedArea[4 ..< 8])
        #expect(transport.sentCommands[12] == Data([0xA2, 0x0F]) + expectedArea[44 ..< 48])
        #expect(transport.sentCommands[13] == Data([0xA2, 0x04]) + expectedArea.prefix(4))
    }

    @Test
    func `Unified NDEF write rejects an unencodable record before touching the tag`() async {
        let transport = MockTransport()
        let oversizedType = NDEFRecord(typeNameFormat: .mimeMedia, type: Data(repeating: 0x61, count: 256), payload: Data([0x01]))

        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.writeNDEF(
                NDEFMessage(records: [oversizedType]),
                info: CardInfo(type: .mifareUltralight, uid: Data([0x01, 0x02, 0x03, 0x04])),
                transport: transport
            )
        }
        #expect(transport.sentCommands.isEmpty)
    }

    @Test
    func `Type 3 NDEF write updates attribute block and message blocks`() async throws {
        let transport = MockFeliCaWriteTransport()
        transport.readResponses = [makeAttributeInfoBlock(nbr: 4, nbw: 2, nmaxb: 4, rwFlag: 0x01, ndefLength: 0)]

        let message = NDEFMessage.text("FeliCa")
        try await FeliCaType3Reader(transport: transport).writeNDEF(message.data)

        #expect(transport.writeCalls.count == 3)
        let firstAttributeWrite = transport.writeCalls[0].blocks[0]
        let finalAttributeWrite = transport.writeCalls[2].blocks[0]
        #expect(firstAttributeWrite[9] == 0x0F)
        #expect(finalAttributeWrite[9] == 0x00)
        #expect(finalAttributeWrite[11] == 0x00)
        #expect(finalAttributeWrite[12] == 0x00)
        #expect(finalAttributeWrite[13] == UInt8(message.data.count))
        #expect(transport.writeCalls[1].blocks[0].prefix(message.data.count) == message.data.prefix(message.data.count))
    }

    @Test
    func `Unified Type 5 NDEF write keeps the CC and writes only the TLV blocks`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 5,
                icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x40, 0x02, 0x00]), 4: Data([0xAA, 0xBB, 0xCC, 0xDD])]
        )

        let message = NDEFMessage.text("A")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        // Text record "A"/en (NFC Forum RTD Text): D1 01 04 54 02 65 6E 41.
        // TLV 03 08 <record> FE fills bytes 4-14; block 4 is past the terminator.
        // before: CC rewritten and all 5 blocks written (block 4 zero-filled).
        // Block 1 is written with L = 0 first and with the real L last.
        #expect(transport.readBlockNumbers.first == 0)
        #expect(transport.writtenBlocks.map(\.number) == [1, 2, 3, 1])
        #expect(transport.writtenBlocks[0].data == Data([0x03, 0x00, 0xD1, 0x01]))
        #expect(transport.writtenBlocks[1].data == Data([0x04, 0x54, 0x02, 0x65]))
        #expect(transport.writtenBlocks[2].data == Data([0x6E, 0x41, 0xFE, 0x00]))
        #expect(transport.writtenBlocks[3].data == Data([0x03, 0x08, 0xD1, 0x01]))
        #expect(transport.storedBlocks[4] == Data([0xAA, 0xBB, 0xCC, 0xDD]))
    }

    @Test
    func `Type 5 NDEF write refuses an unformatted tag without writing`() async {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            ),
            storedBlocks: [0: Data([0x00, 0x00, 0x00, 0x00])]
        )

        do {
            try await CoreExtendedNFC.writeNDEF(
                .uri("https://a.b"),
                info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
                transport: transport
            )
            Issue.record("Expected an unformatted tag to be refused")
        } catch NFCError.tagNotNDEFFormatted {
            // expected
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(transport.writtenBlocks.isEmpty) // before: CC + 7 blocks written
    }

    @Test
    func `Type 5 NDEF write refuses a CC without write access`() async {
        // CC byte 1 = 43h: version 1.0, write access 11b (no write access).
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x43, 0x03, 0x00])]
        )

        do {
            try await CoreExtendedNFC.writeNDEF(
                .uri("https://a.b"),
                info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
                transport: transport
            )
            Issue.record("Expected a write-protected tag to be refused")
        } catch NFCError.tagLocked {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(transport.writtenBlocks.isEmpty)
    }

    @Test
    func `Type 5 NDEF write honours MLEN of the existing CC`() async {
        // MLEN = 1 × 8 bytes; the 11-byte TLV does not fit even though memory is larger.
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 64, icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x40, 0x01, 0x00])]
        )

        // TLV 03 08 + 8-byte URI record + FE = 11 bytes; MLEN area = 8 bytes.
        await #expect(throws: NFCError.ndefCapacityExceeded(required: 11, capacity: 8)) {
            try await CoreExtendedNFC.writeNDEF(
                .uri("https://a.b"),
                info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
                transport: transport
            )
        }
        #expect(transport.writtenBlocks.isEmpty)
    }

    @Test
    func `Type 5 NDEF write after an 8-byte CC starts at block 2`() async throws {
        // E2h magic, MLEN byte 2 = 00h, 16-bit MLEN 0010h in bytes 6-7 (block 1).
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 40, icReference: 0x01
            ),
            storedBlocks: [
                0: Data([0xE2, 0x40, 0x00, 0x01]),
                1: Data([0x00, 0x00, 0x00, 0x10]),
            ]
        )

        try await CoreExtendedNFC.writeNDEF(
            .text("A"),
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        #expect(transport.readBlockNumbers == [0, 1])
        #expect(transport.writtenBlocks.map(\.number) == [2, 3, 4, 2])
        #expect(transport.writtenBlocks[0].data == Data([0x03, 0x00, 0xD1, 0x01]))
        #expect(transport.writtenBlocks[2].data == Data([0x6E, 0x41, 0xFE, 0x00]))
        #expect(transport.writtenBlocks[3].data == Data([0x03, 0x08, 0xD1, 0x01]))
    }

    // MARK: - NDEF write procedure (T2T 1.0 §6.4.3, T5T 1.0 §7.5.1, nfcpy tt2.py)

    @Test
    func `Type 2 write zeroes the 3-byte TLV length first and sets it last`() async throws {
        // NTAG215: CC2 3Eh → 496-byte area (124 pages). A 300-byte message needs the
        // 3-byte length form: page 4 = 03 FF 01 2C.
        let transport = MockTransport()
        transport.responses = [Data([0xE1, 0x10, 0x3E, 0x00]) + Data(count: 12)]
            + Array(repeating: Data([0x0A]), count: 125)
        let message = NDEFMessage(records: [.mime(type: "a/b", data: Data(repeating: 0x5A, count: 291))])
        #expect(message.data.count == 300)

        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .ntag215, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            transport: transport
        )

        let writes = Array(transport.sentCommands.dropFirst())
        // before: page 4 written once, first, with its final length.
        #expect(writes.count == 125)
        #expect(writes.first == Data([0xA2, 0x04, 0x03, 0x00, 0x00, 0x00]))
        #expect(writes.last == Data([0xA2, 0x04, 0x03, 0xFF, 0x01, 0x2C]))
        #expect(writes.dropFirst().dropLast().allSatisfy { $0[1] != 0x04 })
    }

    @Test
    func `Write order helper zeroes a 3-byte length spread over two blocks`() {
        // TLV at byte 2 of block 0: 03 FF | 01 2C ...
        let writes: [(block: Int, data: Data)] = [
            (0, Data([0xE1, 0x40, 0x03, 0xFF])),
            (1, Data([0x01, 0x2C, 0xAA, 0xAA])),
            (2, Data([0xAA, 0xAA, 0xAA, 0xAA])),
        ]
        let ordered = NDEFTagMapping.lengthLastWriteOrder(writes, blockSize: 4, tlvOffset: 2)
        // The block holding the first length byte is finalised last, so the switch
        // from length 0 to the real length is a single block write.
        #expect(ordered.map(\.block) == [0, 1, 2, 1, 0])
        #expect(ordered[0].data == Data([0xE1, 0x40, 0x03, 0x00]))
        #expect(ordered[1].data == Data([0x00, 0x00, 0xAA, 0xAA]))
        #expect(ordered[3].data == writes[1].data)
        #expect(ordered[4].data == writes[0].data)
    }

    @Test
    func `Type 2 message that fills the data area exactly is written without a terminator`() async throws {
        // Ultralight: 48-byte area. TLV 03 2E + 46-byte message = 48 bytes; no room for FE.
        let message = NDEFMessage(records: [.mime(type: "a/b", data: Data(repeating: 0x11, count: 40))])
        #expect(message.data.count == 46)
        // before: ndefCapacityExceeded(required: 49, capacity: 48)
        let area = try NDEFTagMapping.buildType2Area(message: message.data, capacity: 48)
        #expect(area == Data([0x03, 0x2E]) + message.data)
        #expect(throws: NFCError.ndefCapacityExceeded(required: 49, capacity: 48)) {
            _ = try NDEFTagMapping.buildType2Area(message: message.data + Data([0x00]), capacity: 48)
        }

        let transport = MockTransport()
        transport.responses = [Data([0xE1, 0x10, 0x06, 0x00]) + Data(count: 12)]
            + Array(repeating: Data([0x0A]), count: 13)
        let info = CardInfo(type: .mifareUltralight, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
        try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)

        // Replay the page writes (last one wins) and read the message back.
        var memory: [UInt8: Data] = [3: Data([0xE1, 0x10, 0x06, 0x00])]
        for command in transport.sentCommands.dropFirst() {
            memory[command[1]] = Data(command.dropFirst(2))
        }
        var pages: [MemoryDump.Page] = []
        for (number, data) in memory {
            pages.append(MemoryDump.Page(number: number, data: data))
        }
        #expect(memory[0x0F] == Data(area.suffix(4)))
        #expect(NDEFTagMapping.extractType2Message(from: pages) == message.data)
    }

    // MARK: - Erased tags read as ndefMessageNotFound on every family

    @Test
    func `Erased Type 5 tag reads back as ndefMessageNotFound`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x40, 0x03, 0x00])]
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        try await CoreExtendedNFC.writeNDEF(.text("A"), info: info, transport: transport)
        #expect(try await CoreExtendedNFC.readNDEF(info: info, transport: transport).records.count == 1)

        try await CoreExtendedNFC.writeNDEF(NDEFMessage(records: []), info: info, transport: transport)
        #expect(transport.storedBlocks[1]?.prefix(3) == Data([0x03, 0x00, 0xFE]))
        // before: invalidResponse from parsing an empty message
        await #expect(throws: NFCError.ndefMessageNotFound) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
        }
    }

    @Test
    func `Erased Type 3 tag reads back as ndefMessageNotFound`() async {
        let transport = MockFeliCaWriteTransport()
        transport.readResponses = [makeAttributeInfoBlock(nbr: 4, nbw: 1, nmaxb: 4, rwFlag: 0x01, ndefLength: 0)]
        let info = CardInfo(type: .felicaLiteS, uid: transport.identifier)
        await #expect(throws: NFCError.ndefMessageNotFound) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
        }
    }

    // MARK: - T5T special frame (CC byte 3 b4)

    @Test
    func `Type 5 write refuses a CC that requires special frames`() async {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x40, 0x03, 0x10])]
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        // before: written with plain frames
        await #expect(throws: NFCError.unsupportedOperation("Type 5 tag requires special frame writes, which are not supported")) {
            try await CoreExtendedNFC.writeNDEF(.text("A"), info: info, transport: transport)
        }
        #expect(transport.writtenBlocks.isEmpty)
        // Reading is unaffected.
        #expect(throws: Never.self) {
            _ = try NDEFTagMapping.type5CCLength(firstBlock: Data([0xE1, 0x40, 0x03, 0x01]))
        }
    }

    // MARK: - T2T NDEF detection (NFC Forum T2T 1.0 §6.4.1)

    @Test
    func `Type 2 extraction requires the E1 capability container`() {
        let tlvPage = MemoryDump.Page(number: 4, data: Data([0x03, 0x01, 0xD0, 0xFE]))
        let blank = [MemoryDump.Page(number: 3, data: Data([0x00, 0x00, 0x00, 0x00])), tlvPage]
        #expect(NDEFTagMapping.extractType2Message(from: blank) == nil)

        let missingCC = [tlvPage]
        #expect(NDEFTagMapping.extractType2Message(from: missingCC) == nil)

        let futureMajor = [MemoryDump.Page(number: 3, data: Data([0xE1, 0x20, 0x06, 0x00])), tlvPage]
        #expect(NDEFTagMapping.extractType2Message(from: futureMajor) == nil)

        let formatted = [MemoryDump.Page(number: 3, data: Data([0xE1, 0x10, 0x06, 0x00])), tlvPage]
        #expect(NDEFTagMapping.extractType2Message(from: formatted) == Data([0xD0]))
    }

    @Test
    func `Type 2 extraction stops at the CC data area size`() {
        // CC2 = 1 → 8-byte data area; the NDEF TLV starts after it.
        let pages = [
            MemoryDump.Page(number: 3, data: Data([0xE1, 0x10, 0x01, 0x00])),
            MemoryDump.Page(number: 4, data: Data([0x00, 0x00, 0x00, 0x00])),
            MemoryDump.Page(number: 5, data: Data([0x00, 0x00, 0x00, 0x00])),
            MemoryDump.Page(number: 6, data: Data([0x03, 0x01, 0xD0, 0xFE])),
        ]
        #expect(NDEFTagMapping.extractType2Message(from: pages) == nil)
    }

    // MARK: - T5T capability container (NFC Forum T5T 1.0 §4.3.1)

    @Test
    func `Type 5 8-byte CC is skipped before TLV parsing`() {
        // ST25DV64K-style CC: MLEN byte 2 = 00h, 16-bit MLEN 03FFh in bytes 6-7.
        let cc = Data([0xE2, 0x40, 0x00, 0x01, 0x00, 0x00, 0x03, 0xFF])
        let tlv = Data([0x03, 0x03, 0xD0, 0x00, 0x00, 0xFE])
        let bytes = cc + tlv + Data(repeating: 0x00, count: 2)
        let blocks = stride(from: 0, to: bytes.count, by: 4).enumerated().map {
            MemoryDump.Block(number: $0.offset, data: Data(bytes[$0.element ..< $0.element + 4]))
        }
        #expect(NDEFTagMapping.extractType5Message(from: blocks) == Data([0xD0, 0x00, 0x00]))
    }

    @Test
    func `Read-only Type 5 CC uses byte 1 write-access bits`() throws {
        let blocks = try NDEFTagMapping.buildType5Blocks(message: Data(), blockSize: 4, blockCount: 8, writeable: false)
        #expect(blocks[0] == Data([0xE1, 0x43, 0x03, 0x00]))
        let writable = try NDEFTagMapping.buildType5Blocks(message: Data(), blockSize: 4, blockCount: 8)
        #expect(writable[0] == Data([0xE1, 0x40, 0x03, 0x00]))
    }

    @Test
    func `Type 5 large data area uses the 8-byte CC`() throws {
        // 256 blocks × 32 bytes: 255 × 32 / 8 = 1020 units, too large for one MLEN byte.
        let blocks = try NDEFTagMapping.buildType5Blocks(message: Data([0xD0, 0x00, 0x00]), blockSize: 32, blockCount: 256)
        #expect(blocks.count == 256)
        // The T5T_Area runs from byte 8: (8192 - 8) / 8 = 1023 units (was 1020 when the
        // TLV started at the next block).
        #expect(blocks[0].prefix(8) == Data([0xE1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFF]))
        let extracted = NDEFTagMapping.extractType5Message(
            from: blocks.enumerated().map { MemoryDump.Block(number: $0.offset, data: $0.element) }
        )
        #expect(extracted == Data([0xD0, 0x00, 0x00]))
    }

    @Test
    func `Type 5 format on a tag with more than 256 blocks stays within single-byte addresses`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 512,
                icReference: 0x01
            )
        )

        try await CoreExtendedNFC.formatNDEF(
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        #expect(transport.writtenBlocks.count == 256)
        #expect(transport.writtenBlocks.last?.number == 255)
        // NDEF area = 255 blocks × 4 bytes = 1020 bytes → MLEN 127.
        #expect(transport.writtenBlocks[0].data == Data([0xE1, 0x40, 0x7F, 0x00]))
    }

    @Test
    func `Type 5 NDEF reads back on a tag with more than 256 blocks`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 300, icReference: 0x01
            )
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)
        try await CoreExtendedNFC.writeNDEF(.text("hello"), info: info, transport: transport)

        transport.readBlockNumbers = []
        // before: threw from the 256-block dump guard
        #expect(try await CoreExtendedNFC.readNDEF(info: info, transport: transport) == .text("hello"))
        #expect(transport.readBlockNumbers.allSatisfy { $0 <= 255 })

        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        #expect(dump.blocks.count == 256)
        #expect(dump.facts.contains { $0.key == "Blocks Read" })
        #expect(dump.capabilities == [.partiallyReadable])
        #expect(dump.parsedNDEFMessage == .text("hello"))
    }

    @Test
    func `Type 5 NDEF read stops at the MLEN data area`() async throws {
        // MLEN = 1 → 8-byte area (blocks 1-2); the NDEF TLV starts in block 3.
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            ),
            storedBlocks: [0: Data([0xE1, 0x40, 0x01, 0x00]), 3: Data([0x03, 0x01, 0xD0, 0xFE])]
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        await #expect(throws: NFCError.ndefMessageNotFound) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
        }
        #expect(transport.readBlockNumbers == [0, 1, 2])
    }

    @Test
    func `Type 5 build keeps the TLV inside the advertised MLEN area`() throws {
        // ICODE SLIX: 28 blocks × 4 bytes → 108 user bytes, MLEN 13 → 104-byte area.
        for size in 100 ... 110 {
            let message = Data(repeating: 0xAA, count: size)
            guard let blocks = try? NDEFTagMapping.buildType5Blocks(message: message, blockSize: 4, blockCount: 28) else {
                continue
            }
            // before: messages up to 105 bytes were accepted past MLEN × 8
            #expect(2 + size <= Int(blocks[0][2]) * 8)
            let extracted = NDEFTagMapping.extractType5Message(
                from: blocks.enumerated().map { MemoryDump.Block(number: $0.offset, data: $0.element) }
            )
            #expect(extracted == message)
        }
    }

    @Test
    func `Type 5 write respects the tag's existing MLEN`() throws {
        // CC advertises MLEN = 2 (16 bytes) on a 64-block tag.
        let cc = Data([0xE1, 0x40, 0x02, 0x00])
        #expect(throws: NFCError.self) {
            _ = try NDEFTagMapping.type5NDEFWrites(
                message: Data(repeating: 0xAA, count: 14), leadingBytes: cc, blockSize: 4, blockCount: 64
            )
        }
        let writes = try NDEFTagMapping.type5NDEFWrites(
            message: Data(repeating: 0xAA, count: 13), leadingBytes: cc, blockSize: 4, blockCount: 64
        )
        #expect(writes.last?.block == 4)
    }

    // MARK: - T5T extended addressing (blocks above 255)

    private static func type5SystemInfo(blockSize: Int, blockCount: Int) -> ISO15693SystemInfo {
        ISO15693SystemInfo(
            uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            dsfid: 0x00, afi: 0x00, blockSize: blockSize, blockCount: blockCount, icReference: 0x01
        )
    }

    @Test
    func `Type 5 format covers the whole memory with extended commands`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: Self.type5SystemInfo(blockSize: 4, blockCount: 512),
            supportsExtended: true
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)

        // Probed with a read of the last block before anything was written.
        #expect(transport.extendedReadBlockNumbers == [511])
        #expect(transport.writtenBlocks.map(\.number) == Array(0 ... 255))
        #expect(transport.extendedWrittenBlockNumbers == Array(256 ... 511))
        // NDEF area = 511 blocks × 4 bytes = 2044 bytes → MLEN 255, two-byte addressing magic.
        #expect(transport.writtenBlocks[0].data == Data([0xE2, 0x40, 0xFF, 0x00]))
        #expect(transport.writtenBlocks[1].data == Data([0x03, 0x00, 0xFE, 0x00]))

        // A message past block 255 now fits and reads back.
        let message = NDEFMessage(records: [
            NDEFRecord(typeNameFormat: .mimeMedia, type: Data("text/plain".utf8), payload: Data(repeating: 0x5A, count: 1500)),
        ])
        try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
        // TLV 1520 bytes + FE terminator after the 4-byte CC → blocks 1-381.
        #expect(Array(transport.extendedWrittenBlockNumbers.dropFirst(256)) == Array(256 ... 381))
        #expect(try await CoreExtendedNFC.readNDEF(info: info, transport: transport).data == message.data)
    }

    @Test
    func `Type 5 extended format uses the 8-byte CC for a large area`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: Self.type5SystemInfo(blockSize: 4, blockCount: 1024),
            supportsExtended: true
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)

        #expect(transport.writtenBlocks.count == 256)
        #expect(transport.extendedWrittenBlockNumbers == Array(256 ... 1023))
        // 1022 data blocks × 4 bytes = 4088 bytes → MLEN 511 (01FFh) in CC bytes 6-7.
        #expect(transport.writtenBlocks[0].data == Data([0xE2, 0x40, 0x00, 0x00]))
        #expect(transport.writtenBlocks[1].data == Data([0x00, 0x00, 0x01, 0xFF]))
        #expect(transport.writtenBlocks[2].data == Data([0x03, 0x00, 0xFE, 0x00]))
        try await CoreExtendedNFC.writeNDEF(.uri("https://a.b"), info: info, transport: transport)
        // The CC is kept as read: the 11-byte TLV goes in blocks 2-4, after the 8-byte CC,
        // with block 2 (the TLV length) written first as L = 0 and last with the real L.
        #expect(transport.writtenBlocks.suffix(4).map(\.number) == [2, 3, 4, 2])
        #expect(transport.storedBlocks[1] == Data([0x00, 0x00, 0x01, 0xFF]))
        #expect(try await CoreExtendedNFC.readNDEF(info: info, transport: transport) == .uri("https://a.b"))
    }

    @Test
    func `Type 5 format falls back to blocks 0-255 when extended commands are unsupported`() async throws {
        let transport = MockISO15693WriteTransport(
            systemInfo: Self.type5SystemInfo(blockSize: 4, blockCount: 512),
            supportsExtended: false
        )
        try await CoreExtendedNFC.formatNDEF(
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )
        #expect(transport.writtenBlocks.map(\.number) == Array(0 ... 255))
        #expect(transport.extendedWrittenBlockNumbers.isEmpty)
        #expect(transport.writtenBlocks[0].data == Data([0xE1, 0x40, 0x7F, 0x00]))
    }

    @Test
    func `Type 5 build caps MLEN at FFFFh on the largest tags`() throws {
        // 65536 blocks × 32 bytes would be 262 140 units; the 16-bit MLEN stops at FFFFh.
        let blocks = try NDEFTagMapping.buildType5Blocks(
            message: Data(),
            blockSize: 32,
            blockCount: 65536,
            addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
        )
        #expect(blocks[0].prefix(8) == Data([0xE2, 0x40, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]))
        // ceil((8-byte CC + FFFFh × 8) / 32) blocks.
        #expect(blocks.count == 16384)
    }

    @Test
    func `Type 5 write plan is the same with either addressing bound inside blocks 0-255`() throws {
        let cc = Data([0xE1, 0x40, 0x02, 0x00])
        let message = Data(repeating: 0xAA, count: 13)
        let single = try NDEFTagMapping.type5NDEFWrites(message: message, leadingBytes: cc, blockSize: 4, blockCount: 64)
        let extended = try NDEFTagMapping.type5NDEFWrites(
            message: message,
            leadingBytes: cc,
            blockSize: 4,
            blockCount: 64,
            addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
        )
        #expect(single.map(\.block) == [1, 2, 3, 4])
        #expect(single.map(\.block) == extended.map(\.block))
        #expect(single.map(\.data) == extended.map(\.data))
        #expect(single[0].data == Data([0x03, 0x0D, 0xAA, 0xAA]))
        #expect(single[3].data == Data([0xAA, 0xAA, 0xAA, 0xFE]))
    }

    @Test
    func `Type 5 write plan reaches past block 255 only with the extended bound`() throws {
        // 300 blocks × 4 bytes, MLEN 149 → 1192-byte area; a 1100-byte TLV ends in block 275.
        let cc = Data([0xE1, 0x40, 149, 0x00])
        let message = Data(repeating: 0x5A, count: 1095)
        #expect(throws: NFCError.ndefCapacityExceeded(required: 1100, capacity: 1020)) {
            _ = try NDEFTagMapping.type5NDEFWrites(message: message, leadingBytes: cc, blockSize: 4, blockCount: 300)
        }
        let writes = try NDEFTagMapping.type5NDEFWrites(
            message: message,
            leadingBytes: cc,
            blockSize: 4,
            blockCount: 300,
            addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
        )
        #expect(writes.map(\.block) == Array(1 ... 275))
        #expect(writes[0].data == Data([0x03, 0xFF, 0x04, 0x47]))
        #expect(writes.last?.data == Data([0x5A, 0x5A, 0x5A, 0xFE]))
    }

    @Test
    func `Type 5 format refuses a tag with less than 8 bytes of NDEF memory`() {
        // before: CC byte 2 = 00h, which readers take as an 8-byte CC
        #expect(throws: NFCError.self) {
            _ = try NDEFTagMapping.buildType5Blocks(message: Data(), blockSize: 4, blockCount: 2)
        }
    }

    // MARK: - Typed NDEF errors

    @Test
    func `Type 5 NDEF read of a blank tag reports not formatted`() async {
        let transport = MockISO15693WriteTransport(
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: 8, icReference: 0x01
            )
        )
        let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
        // before: unsupportedOperation("No NDEF message detected on the ISO 15693 tag")
        await #expect(throws: NFCError.tagNotNDEFFormatted) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
        }
    }

    @Test
    func `Type 2 NDEF read tells a blank tag from an empty NDEF area`() async {
        let info = CardInfo(type: .mifareUltralight, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
        let header = Data([0x04, 0x01, 0x02, 0x8F, 0x03, 0x04, 0x05, 0x06, 0x04, 0x48, 0x00, 0x00])

        let blank = MockTransport()
        blank.responses = [header + Data(count: 4)] + Array(repeating: Data(count: 16), count: 3)
        await #expect(throws: NFCError.tagNotNDEFFormatted) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: blank)
        }

        let formatted = MockTransport()
        formatted.responses = [header + Data([0xE1, 0x10, 0x06, 0x00])] + Array(repeating: Data(count: 16), count: 3)
        await #expect(throws: NFCError.ndefMessageNotFound) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: formatted)
        }
    }

    @Test
    func `Type 3 NDEF read reports a blank attribute block as not formatted`() async {
        let transport = MockFeliCaWriteTransport()
        transport.readResponses = [Data(count: 16)]
        // before: unsupportedOperation("Unsupported Type 3 mapping version 0.0")
        await #expect(throws: NFCError.tagNotNDEFFormatted) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 NDEF read reports a card without the NDEF service as not formatted`() async {
        // No 0x000B service: the read fails and Request Service answers FFFF.
        let transport = MockFeliCaServiceTransport(serviceVersions: [:])
        await #expect(throws: NFCError.tagNotNDEFFormatted) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 read failure on an existing NDEF service is not reported as unformatted`() async {
        let transport = MockFeliCaServiceTransport(serviceVersions: [FeliCaType3Reader.readServiceCode: Data([0x00, 0x00])])
        await #expect(throws: NFCError.felicaBlockReadFailed(statusFlag: 0xA1)) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 NDEF write over capacity reports both sizes`() async {
        let transport = MockFeliCaWriteTransport()
        transport.readResponses = [makeAttributeInfoBlock(nbr: 4, nbw: 1, nmaxb: 1, rwFlag: 0x01, ndefLength: 0)]
        await #expect(throws: NFCError.ndefCapacityExceeded(required: 17, capacity: 16)) {
            try await FeliCaType3Reader(transport: transport).writeNDEF(Data(count: 17))
        }
        #expect(transport.writeCalls.isEmpty)
    }

    @Test
    func `Type 3 attribute checksum mismatch is not reported as a CRC error`() {
        var block = makeAttributeInfoBlock(nbr: 4, nbw: 1, nmaxb: 4, rwFlag: 0x01, ndefLength: 0)
        block[15] ^= 0x01
        #expect(throws: NFCError.checksumMismatch) {
            _ = try FeliCaAttributeInfo(data: block)
        }
    }

    @Test
    func `Unsupported families are reported as tagNotSupported`() async {
        let info = CardInfo(type: .mifareClassic1K, uid: Data([0x01, 0x02, 0x03, 0x04]))
        await #expect(throws: NFCError.tagNotSupported) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: MockTransport())
        }
        await #expect(throws: NFCError.tagNotSupported) {
            try await CoreExtendedNFC.writeNDEF(.text("x"), info: info, transport: MockTransport())
        }
    }

    @Test
    func `Unencodable NDEF records are an invalid parameter`() {
        let record = NDEFRecord(typeNameFormat: .external, type: Data(count: 256), payload: Data())
        #expect(throws: NFCError.invalidParameter("NDEF record type is 256 bytes; the limit is 255")) {
            _ = try NDEFMessage(records: [record]).validatedData()
        }
        #expect(throws: NFCError.invalidParameter("An NDEF message needs at least one record")) {
            _ = try NDEFMessage(records: []).validatedData()
        }
    }

    private func makeAttributeInfoBlock(
        nbr: UInt8,
        nbw: UInt8,
        nmaxb: UInt16,
        rwFlag: UInt8,
        ndefLength: UInt32
    ) -> Data {
        var block = Data(repeating: 0x00, count: 16)
        block[0] = 0x10
        block[1] = nbr
        block[2] = nbw
        block[3] = UInt8((nmaxb >> 8) & 0xFF)
        block[4] = UInt8(nmaxb & 0xFF)
        block[9] = 0x00
        block[10] = rwFlag
        block[11] = UInt8((ndefLength >> 16) & 0xFF)
        block[12] = UInt8((ndefLength >> 8) & 0xFF)
        block[13] = UInt8(ndefLength & 0xFF)

        var checksum: UInt16 = 0
        for index in 0 ..< 14 {
            checksum = checksum &+ UInt16(block[index])
        }
        block[14] = UInt8((checksum >> 8) & 0xFF)
        block[15] = UInt8(checksum & 0xFF)
        return block
    }
}

private final class MockFeliCaWriteTransport: FeliCaTagTransporting, @unchecked Sendable {
    struct WriteCall {
        let serviceCode: Data
        let blockList: [Data]
        let blocks: [Data]
    }

    let identifier = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    let systemCode = Data([0x12, 0xFC])

    var readResponses: [Data] = []
    var writeCalls: [WriteCall] = []

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readWithoutEncryption(serviceCode _: Data, blockList _: [Data]) async throws -> [Data] {
        guard !readResponses.isEmpty else {
            throw NFCError.tagConnectionLost
        }
        return [readResponses.removeFirst()]
    }

    func writeWithoutEncryption(serviceCode: Data, blockList: [Data], blockData: [Data]) async throws {
        writeCalls.append(.init(serviceCode: serviceCode, blockList: blockList, blocks: blockData))
    }

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        Array(repeating: Data([0xFF, 0xFF]), count: nodeCodeList.count)
    }
}

private final class MockISO15693WriteTransport: ISO15693TagTransporting, @unchecked Sendable {
    struct WriteBlock {
        let number: UInt8
        let data: Data
    }

    let identifier = Data([0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    let icManufacturerCode = 0x04
    let systemInfo: ISO15693SystemInfo
    var writtenBlocks: [WriteBlock] = []
    /// Tag memory; unset blocks read as zeros.
    var storedBlocks: [UInt8: Data]
    var readBlockNumbers: [UInt8] = []
    /// When `false`, the extended commands fall back to the protocol's default,
    /// which throws like a tag without them.
    let supportsExtended: Bool
    /// Blocks from 256 on, reached only through the extended commands.
    var extendedStoredBlocks: [Int: Data] = [:]
    var extendedReadBlockNumbers: [Int] = []
    var extendedWrittenBlockNumbers: [Int] = []

    init(systemInfo: ISO15693SystemInfo, storedBlocks: [UInt8: Data] = [:], supportsExtended: Bool = false) {
        self.systemInfo = systemInfo
        self.storedBlocks = storedBlocks
        self.supportsExtended = supportsExtended
    }

    func extendedReadBlock(_ number: UInt16) async throws -> Data {
        guard supportsExtended else {
            throw NFCError.unsupportedOperation("ISO 15693 extended block reads are not supported by this transport")
        }
        extendedReadBlockNumbers.append(Int(number))
        if let single = UInt8(exactly: number) {
            return storedBlocks[single] ?? Data(repeating: 0x00, count: systemInfo.blockSize)
        }
        return extendedStoredBlocks[Int(number)] ?? Data(repeating: 0x00, count: systemInfo.blockSize)
    }

    func extendedWriteBlock(_ number: UInt16, data: Data) async throws {
        guard supportsExtended else {
            throw NFCError.unsupportedOperation("ISO 15693 extended block writes are not supported by this transport")
        }
        extendedWrittenBlockNumbers.append(Int(number))
        if let single = UInt8(exactly: number) {
            storedBlocks[single] = data
        } else {
            extendedStoredBlocks[Int(number)] = data
        }
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readBlock(_ number: UInt8) async throws -> Data {
        readBlockNumbers.append(number)
        return storedBlocks[number] ?? Data(repeating: 0x00, count: systemInfo.blockSize)
    }

    func writeBlock(_ number: UInt8, data: Data) async throws {
        writtenBlocks.append(.init(number: number, data: data))
        storedBlocks[number] = data
    }

    func readBlocks(range _: NSRange) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        systemInfo
    }

    func getBlockSecurityStatus(range _: NSRange) async throws -> [Bool] {
        []
    }
}
