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
        let expectedCC = NDEFTagMapping.buildType2CC(memoryMap: memory)
        #expect(transport.sentCommands[12].prefix(2) == Data([0xA2, 0x03]))
        #expect(Data(transport.sentCommands[12].dropFirst(2)) == expectedCC)
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
        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.formatNDEF(
                info: CardInfo(type: .type4NDEF, uid: Data([0x01, 0x02, 0x03, 0x04])),
                transport: transport
            )
        }
    }

    @Test
    func `Unified Type 2 NDEF write lays out TLV pages`() async throws {
        let transport = MockTransport()
        transport.responses = Array(repeating: Data([0x0A]), count: 12)

        let message = NDEFMessage.text("Hi")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .mifareUltralight, uid: Data([0x01, 0x02, 0x03, 0x04])),
            transport: transport
        )

        #expect(transport.sentCommands.count == 12)
        #expect(transport.sentCommands[0].prefix(2) == Data([0xA2, 0x04]))

        let expectedArea = try NDEFTagMapping.buildType2Area(message: message.data, capacity: 48)
        #expect(Data(transport.sentCommands[0].dropFirst(2)) == expectedArea.prefix(4))
        #expect(Data(transport.sentCommands[1].dropFirst(2)) == Data(expectedArea[4 ..< 8]))
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
    func `Unified Type 5 NDEF write emits CC and user blocks`() async throws {
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

        let message = NDEFMessage.text("A")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        #expect(transport.writtenBlocks.count == 5)
        #expect(transport.writtenBlocks[0].number == 0)
        #expect(transport.writtenBlocks[0].data == Data([0xE1, 0x40, 0x02, 0x00]))
        #expect(transport.writtenBlocks[1].data[0] == 0x03)
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
        #expect(blocks[0].prefix(8) == Data([0xE1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFC]))
        let extracted = NDEFTagMapping.extractType5Message(
            from: blocks.enumerated().map { MemoryDump.Block(number: $0.offset, data: $0.element) }
        )
        #expect(extracted == Data([0xD0, 0x00, 0x00]))
    }

    @Test
    func `Type 5 write on a tag with more than 256 blocks stays within single-byte addresses`() async throws {
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

        try await CoreExtendedNFC.writeNDEF(
            NDEFMessage.uri("https://a.b"),
            info: CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04),
            transport: transport
        )

        #expect(transport.writtenBlocks.count == 256)
        #expect(transport.writtenBlocks.last?.number == 255)
        // NDEF area = 255 blocks × 4 bytes = 1020 bytes → MLEN 127.
        #expect(transport.writtenBlocks[0].data == Data([0xE1, 0x40, 0x7F, 0x00]))
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

    init(systemInfo: ISO15693SystemInfo) {
        self.systemInfo = systemInfo
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readBlock(_: UInt8) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func writeBlock(_ number: UInt8, data: Data) async throws {
        writtenBlocks.append(.init(number: number, data: data))
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
