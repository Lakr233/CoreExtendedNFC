// NTAG 424 DNA plain file-operation and GetFileSettings parser tests.
//
// Layouts follow the NXP NT4H2421Gx (NTAG 424 DNA) datasheet: GetFileSettings
// (F5h) and WriteData (8Dh) in the ISO/IEC 7816-4 wrapped native form.
// https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf
//
// The byte strings below are constructed for these tests from that layout; they
// are not NXP-published test vectors. The three SDM-disabled responses use the
// factory file settings the datasheet describes for the CC (file 01h),
// NDEF (file 02h) and proprietary (file 03h) files.
// The NXP AN12196 published vectors are in Vectors/NTAG424VectorTests.swift.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NTAG424FileSettingsTests {
    // MARK: SDM disabled

    @Test
    func `NDEF file factory settings parse as plain free access`() throws {
        let settings = try NTAG424FileSettings(data: Data([0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00]))

        #expect(settings.fileType == 0x00)
        #expect(settings.communicationMode == .plain)
        #expect(settings.accessRights.rawValue == 0xEEE0)
        #expect(settings.accessRights.read == 0x0E)
        #expect(settings.accessRights.write == 0x0E)
        #expect(settings.accessRights.readWrite == 0x0E)
        #expect(settings.accessRights.change == 0x00)
        #expect(settings.accessRights.readCondition == .free)
        #expect(settings.accessRights.changeCondition == .key(0))
        #expect(settings.fileSize == 256)
        #expect(settings.isSDMEnabled == false)
        #expect(settings.sdm == nil)
    }

    @Test
    func `CC file factory settings parse`() throws {
        let settings = try NTAG424FileSettings(data: Data([0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00]))

        #expect(settings.accessRights.read == 0x0E)
        #expect(settings.accessRights.write == 0x00)
        #expect(settings.accessRights.readWrite == 0x00)
        #expect(settings.accessRights.change == 0x00)
        #expect(settings.fileSize == 32)
    }

    @Test
    func `Proprietary file factory settings parse as full mode`() throws {
        let settings = try NTAG424FileSettings(data: Data([0x00, 0x03, 0x30, 0x23, 0x80, 0x00, 0x00]))

        #expect(settings.communicationMode == .full)
        #expect(settings.accessRights.readCondition == .key(2))
        #expect(settings.accessRights.writeCondition == .key(3))
        #expect(settings.accessRights.readWriteCondition == .key(3))
        #expect(settings.accessRights.changeCondition == .key(0))
        #expect(settings.fileSize == 128)
    }

    @Test
    func `File size decodes 24-bit little-endian`() throws {
        let settings = try NTAG424FileSettings(data: Data([0x00, 0x01, 0xEE, 0xEE, 0x56, 0x34, 0x12]))

        #expect(settings.communicationMode == .mac)
        #expect(settings.fileSize == 0x123456)
    }

    @Test
    func `Communication mode decodes FileOption bits 1-0`() {
        #expect(NTAG424FileSettings.CommunicationMode(fileOption: 0x00) == .plain)
        #expect(NTAG424FileSettings.CommunicationMode(fileOption: 0x01) == .mac)
        #expect(NTAG424FileSettings.CommunicationMode(fileOption: 0x02) == .plain)
        #expect(NTAG424FileSettings.CommunicationMode(fileOption: 0x43) == .full)
    }

    @Test
    func `Access condition nibbles decode`() {
        #expect(NTAG424FileSettings.AccessCondition(nibble: 0x04) == .key(4))
        #expect(NTAG424FileSettings.AccessCondition(nibble: 0x05) == .reserved(5))
        #expect(NTAG424FileSettings.AccessCondition(nibble: 0x0E) == .free)
        #expect(NTAG424FileSettings.AccessCondition(nibble: 0x0F) == .never)
    }

    // MARK: SDM enabled

    @Test
    func `Plain UID and counter mirroring with SUN MAC`() throws {
        // SDMOptions C1h (UID, ReadCtr, ASCII); SDMAccessRights E1FEh:
        // MetaRead Eh (plain), FileRead 1h, RFU Fh, CtrRet Eh.
        let data = Data([
            0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00,
            0xC1, 0xFE, 0xE1,
            0x20, 0x00, 0x00, // UIDOffset
            0x33, 0x00, 0x00, // SDMReadCtrOffset
            0x20, 0x00, 0x00, // SDMMACInputOffset
            0x3A, 0x00, 0x00, // SDMMACOffset
        ])
        let settings = try NTAG424FileSettings(data: data)
        let sdm = try #require(settings.sdm)

        #expect(settings.isSDMEnabled)
        #expect(settings.communicationMode == .plain)
        #expect(sdm.options == [.uid, .readCounter, .asciiEncoding])
        #expect(sdm.accessRights.rawValue == 0xE1FE)
        #expect(sdm.accessRights.reserved == 0x0F)
        #expect(sdm.accessRights.metaRead == 0x0E)
        #expect(sdm.accessRights.fileRead == 0x01)
        #expect(sdm.accessRights.counterRetrieval == 0x0E)
        #expect(sdm.accessRights.counterRetrievalCondition == .free)
        #expect(sdm.uidOffset == 0x20)
        #expect(sdm.readCounterOffset == 0x33)
        #expect(sdm.piccDataOffset == nil)
        #expect(sdm.macInputOffset == 0x20)
        #expect(sdm.encryptedDataOffset == nil)
        #expect(sdm.encryptedDataLength == nil)
        #expect(sdm.macOffset == 0x3A)
        #expect(sdm.readCounterLimit == nil)
    }

    @Test
    func `Encrypted PICC data, encrypted file data and counter limit`() throws {
        // SDMOptions F1h (UID, ReadCtr, ReadCtrLimit, ENCFileData, ASCII);
        // SDMAccessRights 21FFh: MetaRead 2h (encrypted), FileRead 1h, RFU Fh, CtrRet Fh.
        let data = Data([
            0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00,
            0xF1, 0xFF, 0x21,
            0x20, 0x00, 0x00, // PICCDataOffset
            0x43, 0x00, 0x00, // SDMMACInputOffset
            0x43, 0x00, 0x00, // SDMENCOffset
            0x20, 0x00, 0x00, // SDMENCLength
            0x68, 0x00, 0x00, // SDMMACOffset
            0x10, 0x27, 0x00, // SDMReadCtrLimit
        ])
        let sdm = try #require(try NTAG424FileSettings(data: data).sdm)

        #expect(sdm.accessRights.metaRead == 0x02)
        #expect(sdm.uidOffset == nil)
        #expect(sdm.readCounterOffset == nil)
        #expect(sdm.piccDataOffset == 0x20)
        #expect(sdm.macInputOffset == 0x43)
        #expect(sdm.encryptedDataOffset == 0x43)
        #expect(sdm.encryptedDataLength == 0x20)
        #expect(sdm.macOffset == 0x68)
        #expect(sdm.readCounterLimit == 10000)
    }

    @Test
    func `SDM without mirroring or MAC carries no offsets`() throws {
        // SDMAccessRights FFFFh: MetaRead Fh, FileRead Fh. The ENCFileData bit
        // has no fields without an SDM file read key.
        let data = Data([0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00, 0xD1, 0xFF, 0xFF])
        let sdm = try #require(try NTAG424FileSettings(data: data).sdm)

        #expect(sdm.uidOffset == nil)
        #expect(sdm.readCounterOffset == nil)
        #expect(sdm.piccDataOffset == nil)
        #expect(sdm.macInputOffset == nil)
        #expect(sdm.encryptedDataOffset == nil)
        #expect(sdm.macOffset == nil)
    }

    @Test
    func `Read counter limit alone is parsed`() throws {
        let data = Data([0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00, 0x20, 0xFF, 0xFF, 0x01, 0x02, 0x03])
        let sdm = try #require(try NTAG424FileSettings(data: data).sdm)

        #expect(sdm.readCounterLimit == 0x030201)
    }

    // MARK: Malformed

    @Test
    func `Every truncation of a valid response is rejected`() {
        let full = Data([
            0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00,
            0xF1, 0xFF, 0x21,
            0x20, 0x00, 0x00, 0x43, 0x00, 0x00, 0x43, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x68, 0x00, 0x00, 0x10, 0x27, 0x00,
        ])
        for length in 0 ..< full.count {
            let truncated = Data(full.prefix(length))
            #expect(throws: NFCError.invalidResponse(truncated)) {
                try NTAG424FileSettings(data: truncated)
            }
        }
    }

    @Test
    func `Trailing bytes are rejected`() {
        // SDM disabled plus an 8-byte response MAC.
        let withMAC = Data([0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00] + [UInt8](repeating: 0xAA, count: 8))
        #expect(throws: NFCError.invalidResponse(withMAC)) {
            try NTAG424FileSettings(data: withMAC)
        }

        // SDM enabled without MAC fields, plus one stray byte.
        let stray = Data([0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0x00])
        #expect(throws: NFCError.invalidResponse(stray)) {
            try NTAG424FileSettings(data: stray)
        }
    }

    @Test
    func `Non-StandardData file type is rejected`() {
        let data = Data([0x01, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00])
        #expect(throws: NFCError.invalidResponse(data)) {
            try NTAG424FileSettings(data: data)
        }
    }

    @Test
    func `Reserved SDMMetaRead value is rejected`() {
        // SDMAccessRights 71FFh: MetaRead 7h is RFU.
        let data = Data([0x00, 0x40, 0xE0, 0xEE, 0x00, 0x01, 0x00, 0x01, 0xFF, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        #expect(throws: NFCError.invalidResponse(data)) {
            try NTAG424FileSettings(data: data)
        }
    }
}

struct NTAG424CommandsTests {
    // MARK: GetFileSettings

    @Test
    func `GetFileSettings sends the wrapped F5 command`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00]), sw1: 0x91, sw2: 0x00),
        ]

        let settings = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x02)

        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs[0].bytes == Data([0x90, 0xF5, 0x00, 0x00, 0x01, 0x02, 0x00]))
        #expect(settings.fileSize == 256)
    }

    @Test
    func `GetFileSettings maps native error status`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0xF0)]

        await #expect(throws: NFCError.desfireError(.fileNotFound)) {
            _ = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x05)
        }
    }

    @Test
    func `GetFileSettings reports ISO status words as-is`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)]

        await #expect(throws: NFCError.unexpectedStatusWord(0x6A, 0x82)) {
            _ = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x02)
        }
    }

    @Test
    func `GetFileSettings rejects a malformed payload`() async {
        let mock = MockTransport()
        let short = Data([0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01])
        mock.apduResponses = [ResponseAPDU(data: short, sw1: 0x91, sw2: 0x00)]

        await #expect(throws: NFCError.invalidResponse(short)) {
            _ = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x02)
        }
    }

    @Test
    func `GetFileSettings rejects file numbers above 1F before sending`() async {
        let mock = MockTransport()

        await expectInvalidParameter(containing: "file number") {
            _ = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x20)
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    // MARK: WriteData

    @Test
    func `WriteData sends 8D with 24-bit little-endian offset and length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00)]

        try await NTAG424Commands(transport: mock)
            .writeDataPlain(fileID: 0x02, offset: 0x123456, data: Data([0xAA, 0xBB, 0xCC]))

        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs[0].ins == 0x8D)
        #expect(mock.sentAPDUs[0].bytes == Data([
            0x90, 0x8D, 0x00, 0x00, 0x0A,
            0x02, 0x56, 0x34, 0x12, 0x03, 0x00, 0x00, 0xAA, 0xBB, 0xCC,
            0x00,
        ]))
    }

    @Test
    func `WriteData splits data into chunks with advancing offsets`() async throws {
        let mock = MockTransport()
        mock.apduResponses = Array(repeating: ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00), count: 3)
        let data = Data((0 ..< 300).map { UInt8(truncatingIfNeeded: $0) })

        try await NTAG424Commands(transport: mock).writeDataPlain(fileID: 0x02, offset: 10, data: data)

        #expect(mock.sentAPDUs.count == 3)
        let payloads = mock.sentAPDUs.map { $0.data ?? Data() }
        #expect(payloads[0].prefix(7) == Data([0x02, 0x0A, 0x00, 0x00, 0x6F, 0x00, 0x00]))
        #expect(payloads[1].prefix(7) == Data([0x02, 0x79, 0x00, 0x00, 0x6F, 0x00, 0x00]))
        #expect(payloads[2].prefix(7) == Data([0x02, 0xE8, 0x00, 0x00, 0x4E, 0x00, 0x00]))
        #expect(payloads.map(\.count) == [118, 118, 85])
        #expect(Data(payloads.flatMap { $0.dropFirst(7) }) == data)
        #expect(mock.sentAPDUs.allSatisfy { $0.cla == 0x90 && $0.ins == 0x8D && !$0.isExtendedLength })
    }

    @Test
    func `WriteData honours a custom chunk size up to a short APDU`() throws {
        let data = Data(repeating: 0x5A, count: 500)
        let payloads = try NTAG424Commands.writeDataPlainPayloads(
            fileID: 0x03,
            offset: 0,
            data: data,
            chunkSize: NTAG424Commands.maxWriteChunkSize
        )

        #expect(NTAG424Commands.maxWriteChunkSize == 248)
        #expect(payloads.map(\.count) == [255, 255, 11])
        #expect(payloads[2].prefix(7) == Data([0x03, 0xF0, 0x01, 0x00, 0x04, 0x00, 0x00]))
    }

    @Test
    func `Default WriteData chunks each fit one ISO 14443-4 frame`() throws {
        // NT4H2421Gx Table 4: FSC is 128 bytes; TC(1) 02h: CID supported. Section 10.8.2:
        // only data sent within one frame is tearing protected. A frame carries
        // PCB (1) ‖ CID (1) ‖ INF ‖ CRC (2).
        let payloads = try NTAG424Commands.writeDataPlainPayloads(
            fileID: 0x02,
            offset: 0,
            data: Data(repeating: 0x5A, count: 256)
        )

        for payload in payloads {
            let apdu = CommandAPDU.desfireWrap(command: NTAG424Commands.WRITE_DATA, data: payload)
            #expect(1 + 1 + apdu.bytes.count + 2 <= 128)
        }
        #expect(payloads.count == 3)
    }

    @Test
    func `WriteData accepts the last addressable byte`() throws {
        let payloads = try NTAG424Commands.writeDataPlainPayloads(fileID: 0x02, offset: 0xFF_FFFF, data: Data([0x01]))

        #expect(payloads == [Data([0x02, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x01])])
    }

    @Test
    func `WriteData stops at the first error status`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x9D),
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00),
        ]

        await #expect(throws: NFCError.desfireError(.permissionDenied)) {
            try await NTAG424Commands(transport: mock)
                .writeDataPlain(fileID: 0x02, offset: 0, data: Data(repeating: 0x00, count: 200))
        }
        #expect(mock.sentAPDUs.count == 2)
    }

    @Test
    func `WriteData does not chain on an Additional Frame answer`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0xAF)]

        await #expect(throws: NFCError.desfireError(.additionalFrame)) {
            try await NTAG424Commands(transport: mock)
                .writeDataPlain(fileID: 0x02, offset: 0, data: Data([0x01]))
        }
        #expect(mock.sentAPDUs.count == 1)
    }

    @Test
    func `WriteData reports ISO status words as-is`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6E, sw2: 0x00)]

        await #expect(throws: NFCError.unexpectedStatusWord(0x6E, 0x00)) {
            try await NTAG424Commands(transport: mock)
                .writeDataPlain(fileID: 0x02, offset: 0, data: Data([0x01]))
        }
    }

    @Test
    func `WriteData validates arguments before sending`() async {
        let mock = MockTransport()
        let commands = NTAG424Commands(transport: mock)

        await expectInvalidParameter(containing: "file number") {
            try await commands.writeDataPlain(fileID: 0x20, offset: 0, data: Data([0x01]))
        }
        await expectInvalidParameter(containing: "at least one byte") {
            try await commands.writeDataPlain(fileID: 0x02, offset: 0, data: Data())
        }
        await expectInvalidParameter(containing: "offset must fit") {
            try await commands.writeDataPlain(fileID: 0x02, offset: 0x0100_0000, data: Data([0x01]))
        }
        await expectInvalidParameter(containing: "offset + length") {
            try await commands.writeDataPlain(fileID: 0x02, offset: 0xFF_FFFF, data: Data([0x01, 0x02]))
        }
        await expectInvalidParameter(containing: "chunk size") {
            try await commands.writeDataPlain(fileID: 0x02, offset: 0, data: Data([0x01]), chunkSize: 0)
        }
        await expectInvalidParameter(containing: "chunk size") {
            try await commands.writeDataPlain(fileID: 0x02, offset: 0, data: Data([0x01]), chunkSize: 249)
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    // MARK: Facades

    @Test
    func `Facades forward to NTAG424Commands`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00]), sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00),
        ]

        let settings = try await CoreExtendedNFC.getNTAG424FileSettings(fileID: 0x01, transport: mock)
        try await CoreExtendedNFC.writeNTAG424DataPlain(fileID: 0x02, data: Data([0xD1]), transport: mock)

        #expect(settings.fileSize == 32)
        #expect(mock.sentAPDUs.map(\.ins) == [0xF5, 0x8D])
        #expect(mock.sentAPDUs[1].data == Data([0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xD1]))
    }

    private func expectInvalidParameter(
        containing fragment: String,
        while operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected invalidParameter containing \(fragment)")
        } catch let NFCError.invalidParameter(message) {
            #expect(message.contains(fragment))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}
