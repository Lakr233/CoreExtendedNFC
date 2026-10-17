// ISO 15693 memory configuration test suite.
//
// ## References
// - ISO/IEC 15693-3: Vicinity cards — anticollision and transmission
// - NXP ICODE SLIX (SL2S2002) datasheet: 32 blocks × 4 bytes = 128 bytes
//   https://www.nxp.com/docs/en/data-sheet/SL2S2002_SL2S2102.pdf
// - NXP ICODE SLIX2 (SL2S2602) datasheet: 80 blocks × 4 bytes = 320 bytes
//   https://www.nxp.com/docs/en/data-sheet/SL2S2602.pdf
// - ST ST25TV512 datasheet: 16 blocks × 4 bytes = 64 bytes
//   https://www.st.com/resource/en/datasheet/st25tv512.pdf
// - ST ST25TV02K datasheet: 64 blocks × 4 bytes = 256 bytes
//   https://www.st.com/resource/en/datasheet/st25tv02k.pdf
@testable import CoreExtendedNFC
import Foundation
import Testing

struct ISO15693Tests {
    @Test
    func `ICODE SLIX configuration`() {
        let config = ISO15693Memory.icodeSLIX
        #expect(config.blockSize == 4)
        #expect(config.blockCount == 32)
        #expect(config.totalBytes == 128)
    }

    @Test
    func `ICODE SLIX2 configuration`() {
        let config = ISO15693Memory.icodeSLIX2
        #expect(config.blockSize == 4)
        #expect(config.blockCount == 80)
        #expect(config.totalBytes == 320)
    }

    @Test
    func `ST25TV512 configuration`() {
        let config = ISO15693Memory.st25tv512
        #expect(config.blockSize == 4)
        #expect(config.blockCount == 16)
        #expect(config.totalBytes == 64)
    }

    @Test
    func `ST25TV02K configuration`() {
        let config = ISO15693Memory.st25tv02K
        #expect(config.blockSize == 4)
        #expect(config.blockCount == 64)
        #expect(config.totalBytes == 256)
    }

    @Test
    func `ISO 15693 security manager writes and locks AFI / DSFID`() async throws {
        let transport = MockISO15693SecurityTransport()
        let manager = ISO15693SecurityManager(transport: transport)

        try await manager.configureAFI(0xA1, permanentlyLock: true)
        try await manager.configureDSFID(0x07, permanentlyLock: true)

        #expect(transport.operations == [
            "writeAFI:A1",
            "lockAFI",
            "writeDSFID:07",
            "lockDSFID",
        ])
    }

    @Test
    func `Security manager AFI and DSFID updates never lock by default`() async throws {
        let transport = MockISO15693SecurityTransport()
        let manager = ISO15693SecurityManager(transport: transport)

        try await manager.configureAFI(0xA1)
        try await manager.configureDSFID(0x07)

        #expect(transport.operations == ["writeAFI:A1", "writeDSFID:07"])
    }

    @Test
    func `Top-level AFI and DSFID updates never lock unless permanentlyLock is set`() async throws {
        let transport = MockISO15693SecurityTransport()

        try await CoreExtendedNFC.configureISO15693AFI(0xA1, transport: transport)
        try await CoreExtendedNFC.configureISO15693DSFID(0x07, transport: transport)
        #expect(transport.operations == ["writeAFI:A1", "writeDSFID:07"])

        try await CoreExtendedNFC.configureISO15693AFI(0xA2, permanentlyLock: true, transport: transport)
        try await CoreExtendedNFC.configureISO15693DSFID(0x08, permanentlyLock: true, transport: transport)
        #expect(transport.operations == [
            "writeAFI:A1", "writeDSFID:07",
            "writeAFI:A2", "lockAFI",
            "writeDSFID:08", "lockDSFID",
        ])
    }

    @Test
    func `ISO 15693 security manager forwards custom command and auth primitives`() async throws {
        let transport = MockISO15693SecurityTransport(
            customCommandResponse: Data([0xDE, 0xAD]),
            authenticateResponse: .init(responseFlags: 0x01, data: Data([0xAA, 0xBB])),
            keyUpdateResponse: .init(responseFlags: 0x02, data: Data([0xCC]))
        )
        let manager = ISO15693SecurityManager(transport: transport)

        let custom = try await manager.customCommand(code: 0xA2, parameters: Data([0x01, 0x02]))
        try await manager.challenge(cryptoSuiteIdentifier: 0x10, message: Data([0x03]))
        let auth = try await manager.authenticate(
            cryptoSuiteIdentifier: 0x11,
            message: Data([0x04, 0x05])
        )
        let keyUpdate = try await manager.keyUpdate(
            keyIdentifier: 0x12,
            message: Data([0x06, 0x07])
        )

        #expect(custom == Data([0xDE, 0xAD]))
        #expect(auth == .init(responseFlags: 0x01, data: Data([0xAA, 0xBB])))
        #expect(keyUpdate == .init(responseFlags: 0x02, data: Data([0xCC])))
        #expect(transport.operations == [
            "custom:A2:0102",
            "challenge:10:03",
            "authenticate:11:0405",
            "keyUpdate:12:0607",
        ])
    }

    @Test
    func `readAllBlocks truncates at block 255 when extended commands are unsupported`() async throws {
        // MockISO15693Transport inherits the default extendedReadBlock, which throws.
        let transport = MockISO15693Transport(
            identifier: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            icManufacturerCode: 0x04,
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 300,
                icReference: 0x01
            ),
            blocks: Array(repeating: Data(count: 4), count: 300),
            locked: Array(repeating: false, count: 300)
        )
        let dump = try await ISO15693Reader(transport: transport).readAllBlocks()
        #expect(dump.blocks.count == 256)
        #expect(dump.capabilities == [.partiallyReadable])
        #expect(dump.facts.contains { $0.key == "Blocks Read" && $0.value.hasPrefix("256 of 300") })
        #expect(dump.cardInfo.type == .iso15693_generic)
    }

    // MARK: - Extended addressing (ISO/IEC 15693-3 commands 30h / 31h)

    private static let largeTagUID = Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])

    /// 300 blocks × 4 bytes with a 4-byte CC: MLEN = 149 (1192-byte T5T_Area).
    private static func largeTag(extended: Bool) -> MemoryISO15693Transport {
        let transport = MemoryISO15693Transport(blockCount: 300, supportsExtended: extended)
        transport.memory[0] = Data([0xE1, 0x40, 149, 0x00])
        return transport
    }

    /// A message whose NDEF TLV runs past block 260 (byte 1044).
    private static let longMessage = NDEFMessage(records: [
        NDEFRecord(typeNameFormat: .mimeMedia, type: Data("text/plain".utf8), payload: Data(repeating: 0x5A, count: 1100)),
    ])

    @Test
    func `Dump reads blocks above 255 with extended commands`() async throws {
        let transport = Self.largeTag(extended: true)
        for block in 0 ..< 300 where block > 0 {
            transport.memory[block] = Data(repeating: UInt8(truncatingIfNeeded: block), count: 4)
        }
        let info = CardInfo(type: .iso15693_generic, uid: Self.largeTagUID)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        #expect(dump.blocks.count == 300)
        #expect(dump.blocks[299].data == Data(repeating: UInt8(299 & 0xFF), count: 4))
        #expect(dump.capabilities == [.readable])
        #expect(transport.extendedReads.first == 256)
        #expect(!dump.facts.contains { $0.key == "Blocks Read" })
    }

    @Test
    func `NDEF spanning block 260 round-trips with extended commands`() async throws {
        let transport = Self.largeTag(extended: true)
        let info = CardInfo(type: .iso15693_generic, uid: Self.largeTagUID)
        try await CoreExtendedNFC.writeNDEF(Self.longMessage, info: info, transport: transport)
        #expect(transport.extendedWrites.contains(260))
        #expect(transport.memory[0] == Data([0xE1, 0x40, 149, 0x00]))

        let read = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
        #expect(read.data == Self.longMessage.data)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        #expect(dump.parsedNDEFMessage?.data == Self.longMessage.data)
    }

    @Test
    func `NDEF beyond block 255 stays bounded when extended commands are rejected`() async throws {
        let info = CardInfo(type: .iso15693_generic, uid: Self.largeTagUID)

        // Write: refused before any block is written.
        let rejecting = Self.largeTag(extended: false)
        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.writeNDEF(Self.longMessage, info: info, transport: rejecting)
        }
        #expect(rejecting.writes.isEmpty)
        #expect(rejecting.extendedWrites.isEmpty)

        // Read: a message ending past block 255 is not found, and the dump is partial.
        let written = Self.largeTag(extended: true)
        try await CoreExtendedNFC.writeNDEF(Self.longMessage, info: info, transport: written)
        written.supportsExtended = false
        await #expect(throws: NFCError.self) {
            _ = try await CoreExtendedNFC.readNDEF(info: info, transport: written)
        }
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: written)
        #expect(dump.blocks.count == 256)
        #expect(dump.capabilities == [.partiallyReadable])

        // A short message on the same tag still works without extended commands.
        let short = Self.largeTag(extended: false)
        try await CoreExtendedNFC.writeNDEF(.uri("https://a.b"), info: info, transport: short)
        let shortRead = try await CoreExtendedNFC.readNDEF(info: info, transport: short)
        #expect(shortRead.data == NDEFMessage.uri("https://a.b").data)
    }

    @Test
    func `Reader block helpers route by block number`() async throws {
        let transport = Self.largeTag(extended: true)
        let reader = ISO15693Reader(transport: transport)
        try await reader.writeBlock(at: 255, data: Data([1, 2, 3, 4]))
        try await reader.writeBlock(at: 256, data: Data([5, 6, 7, 8]))
        #expect(transport.writes == [255])
        #expect(transport.extendedWrites == [256])
        #expect(try await reader.readBlock(at: 256) == Data([5, 6, 7, 8]))
        await #expect(throws: NFCError.self) {
            _ = try await reader.readBlock(at: 70000)
        }
    }

    @Test
    func `ISO15693SystemInfo has a public memberwise initializer`() {
        let info = ISO15693SystemInfo(uid: Data([0xE0]), dsfid: nil, afi: 1, blockSize: 4, blockCount: 8, icReference: nil)
        #expect(info.blockCount == 8)
        #expect(info.dsfid == nil)
    }

    @Test
    func `readAllBlocks reads a 256-block tag`() async throws {
        let transport = MockISO15693Transport(
            identifier: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            icManufacturerCode: 0x04,
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 256,
                icReference: 0x01
            ),
            blocks: (0 ..< 256).map { Data(repeating: UInt8($0), count: 4) },
            locked: Array(repeating: false, count: 256)
        )
        let dump = try await ISO15693Reader(transport: transport).readAllBlocks()
        #expect(dump.blocks.count == 256)
        #expect(dump.blocks.last?.data == Data(repeating: 0xFF, count: 4))
    }

    @Test
    func `Top-level block range reads take a closed range`() async throws {
        let transport = MockISO15693Transport(
            identifier: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            icManufacturerCode: 0x04,
            systemInfo: ISO15693SystemInfo(
                uid: Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: 256,
                icReference: 0x01
            ),
            blocks: (0 ..< 256).map { Data(repeating: UInt8($0), count: 4) },
            locked: (0 ..< 256).map { $0 % 2 == 1 }
        )

        let blocks = try await CoreExtendedNFC.readISO15693Blocks(range: 2 ... 4, transport: transport)
        #expect(blocks == [2, 3, 4].map { Data(repeating: $0, count: 4) })

        let single = try await CoreExtendedNFC.readISO15693Blocks(range: 255 ... 255, transport: transport)
        #expect(single == [Data(repeating: 0xFF, count: 4)])

        let locked = try await CoreExtendedNFC.getISO15693BlockSecurityStatus(range: 0 ... 3, transport: transport)
        #expect(locked == [false, true, false, true])
    }

    @Test
    func `Top-level block range reads reject ranges outside 0 through 255`() async throws {
        let transport = MockISO15693SecurityTransport()

        for range in [-1 ... 2, 0 ... 256, 300 ... 310] {
            await #expect(throws: NFCError.self) {
                _ = try await CoreExtendedNFC.readISO15693Blocks(range: range, transport: transport)
            }
            await #expect(throws: NFCError.self) {
                _ = try await CoreExtendedNFC.getISO15693BlockSecurityStatus(range: range, transport: transport)
            }
        }
        do {
            _ = try await CoreExtendedNFC.readISO15693Blocks(range: 0 ... 256, transport: transport)
            Issue.record("Expected invalidParameter")
        } catch let NFCError.invalidParameter(message) {
            #expect(message.contains("0...255"))
        }
    }

    @Test
    func `Top-level ISO 15693 security calls forward to the transport`() async throws {
        let transport = MockISO15693SecurityTransport(
            customCommandResponse: Data([0xDE, 0xAD]),
            authenticateResponse: .init(responseFlags: 0x01, data: Data([0xAA])),
            keyUpdateResponse: .init(responseFlags: 0x02, data: Data([0xBB]))
        )

        let custom = try await CoreExtendedNFC.sendISO15693CustomCommand(
            code: 0xA2,
            parameters: Data([0x01]),
            transport: transport
        )
        try await CoreExtendedNFC.challengeISO15693(cryptoSuiteIdentifier: 0x10, transport: transport)
        let auth = try await CoreExtendedNFC.authenticateISO15693(
            cryptoSuiteIdentifier: 0x11,
            message: Data([0x02]),
            transport: transport
        )
        let keyUpdate = try await CoreExtendedNFC.updateISO15693Key(
            keyIdentifier: 0x12,
            message: Data([0x03]),
            transport: transport
        )

        #expect(custom == Data([0xDE, 0xAD]))
        #expect(auth == .init(responseFlags: 0x01, data: Data([0xAA])))
        #expect(keyUpdate == .init(responseFlags: 0x02, data: Data([0xBB])))
        #expect(transport.operations == [
            "custom:A2:01",
            "challenge:10:",
            "authenticate:11:02",
            "keyUpdate:12:03",
        ])
    }

    // MARK: Extended Get System Information (3Bh)

    /// 3Bh response payload (after the response flags) of an ST25DV64K-like tag:
    /// Info flags 0Fh, UID, DSFID 00h, AFI 00h, memory size FF 07 03 (2048 blocks of
    /// 4 bytes, both value - 1), IC reference 26h.
    static let extended2048Payload = Data([0x0F]) + Data([0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0xE0])
        + Data([0x00, 0x00, 0xFF, 0x07, 0x03, 0x26])

    // ISO/IEC 15693-3:2019 Extended Get System Information response: Info flags, UID
    // (8 bytes), then DSFID (b1), AFI (b2), VICC memory size (b3: number of blocks in
    // 2 bytes LSB first, value - 1; block size in b5-b1, value - 1), IC reference (b4).
    @Test
    func `Extended system info parser reads a 2-byte block count`() throws {
        let info = try ISO15693ExtendedSystemInfo.parse(Self.extended2048Payload)
        #expect(info.blockCount == 2048)
        #expect(info.blockSize == 4)
        #expect(info.uid == Data([0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0xE0]))
        #expect(info.dsfid == 0x00)
        #expect(info.afi == 0x00)
        #expect(info.icReference == 0x26)
    }

    // ISO/IEC 15693-3:2019: only the fields whose Info flag is set are present; the
    // VICC command list (b6, 4 bytes) follows the IC reference; b5 (MOI) has no field.
    @Test
    func `Extended system info parser follows the Info flags`() throws {
        let uid = Data(repeating: 0xAA, count: 8)
        let memoryOnly = try ISO15693ExtendedSystemInfo.parse(Data([0x04]) + uid + Data([0x2F, 0x01, 0x1F]))
        #expect(memoryOnly.blockCount == 0x0130)
        #expect(memoryOnly.blockSize == 32)
        #expect(memoryOnly.dsfid == nil)
        #expect(memoryOnly.afi == nil)
        #expect(memoryOnly.icReference == nil)

        let withCommandList = try ISO15693ExtendedSystemInfo.parse(
            Data([0x3C]) + uid + Data([0xFF, 0x07, 0x03, 0x26, 0x3F, 0xF1, 0x0F, 0x00])
        )
        #expect(withCommandList.blockCount == 2048)
        #expect(withCommandList.icReference == 0x26)

        let noMemory = try ISO15693ExtendedSystemInfo.parse(Data([0x00]) + uid)
        #expect(noMemory.blockCount == -1)
        #expect(noMemory.blockSize == -1)
    }

    @Test
    func `Extended system info parser rejects short or extended-flag payloads`() {
        let uid = Data(repeating: 0xAA, count: 8)
        #expect(throws: NFCError.self) { _ = try ISO15693ExtendedSystemInfo.parse(Data()) }
        #expect(throws: NFCError.self) { _ = try ISO15693ExtendedSystemInfo.parse(Data([0x04]) + uid.prefix(7)) }
        #expect(throws: NFCError.self) { _ = try ISO15693ExtendedSystemInfo.parse(Data([0x04]) + uid + Data([0xFF, 0x07])) }
        // b8: the Info flag field continues in further bytes of unknown layout.
        #expect(throws: NFCError.self) {
            _ = try ISO15693ExtendedSystemInfo.parse(Data([0x84]) + uid + Data([0xFF, 0x07, 0x03]))
        }
    }

    // ISO/IEC 15693-3 Get System Information (2Bh) reports the number of blocks in one
    // byte (value - 1), so a 2048-block tag can report at most 256. The dump must then
    // ask Extended Get System Information (3Bh) for the real size.
    @Test
    func `Dump uses Extended Get System Information when 2Bh reports 256 blocks`() async throws {
        let transport = MemoryISO15693Transport(blockCount: 2048, supportsExtended: true)
        transport.reportedBlockCount = 256
        transport.extendedSystemInfo = Self.extended2048Payload
        transport.memory[2047] = Data([0xDE, 0xAD, 0xBE, 0xEF])

        let dump = try await ISO15693Reader(transport: transport).readAllBlocks()

        #expect(transport.extendedSystemInfoRequests == [ISO15693ExtendedSystemInfo.memorySizeRequest])
        #expect(dump.blocks.count == 2048)
        #expect(dump.blocks.last?.data == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(dump.facts.contains { $0.key == "Blocks" && $0.value == "2048" })
        let systemInfo = try await CoreExtendedNFC.getISO15693SystemInfo(transport: transport)
        #expect(systemInfo.blockCount == 2048)
        #expect(systemInfo.uid == transport.identifier)
    }

    // 3Bh is optional (ISO/IEC 15693-3:2019); a tag that rejects it keeps the 2Bh size.
    @Test
    func `Dump keeps the 2Bh size when Extended Get System Information is rejected`() async throws {
        let transport = MemoryISO15693Transport(blockCount: 256, supportsExtended: false)
        transport.extendedSystemInfo = nil

        let dump = try await ISO15693Reader(transport: transport).readAllBlocks()

        #expect(transport.extendedSystemInfoRequests == [ISO15693ExtendedSystemInfo.memorySizeRequest])
        #expect(dump.blocks.count == 256)
        #expect(dump.capabilities == [.readable])
    }

    @Test
    func `Extended Get System Information is only asked when 2Bh may under-report`() async throws {
        let transport = MemoryISO15693Transport(blockCount: 32, supportsExtended: false)
        transport.extendedSystemInfo = Self.extended2048Payload

        let dump = try await ISO15693Reader(transport: transport).readAllBlocks()

        #expect(transport.extendedSystemInfoRequests.isEmpty)
        #expect(dump.blocks.count == 32)
    }

    // A 3Bh answer that contradicts a reported 2Bh size (other block size, or fewer
    // blocks) is not trusted.
    @Test
    func `Extended memory size is only taken when consistent with 2Bh`() {
        let standard = ISO15693SystemInfo(uid: Data([0x01]), dsfid: 0x10, afi: nil, blockSize: 4, blockCount: 256, icReference: nil)
        let larger = ISO15693SystemInfo(uid: Data([0x02]), dsfid: 0x20, afi: 0x30, blockSize: 4, blockCount: 2048, icReference: 0x26)
        let merged = ISO15693ExtendedSystemInfo.merge(standard: standard, extended: larger)
        #expect(merged.blockCount == 2048)
        #expect(merged.uid == Data([0x01]))
        #expect(merged.dsfid == 0x10)
        #expect(merged.afi == 0x30)
        #expect(merged.icReference == 0x26)

        let otherSize = ISO15693SystemInfo(uid: Data(), dsfid: nil, afi: nil, blockSize: 8, blockCount: 2048, icReference: nil)
        #expect(ISO15693ExtendedSystemInfo.merge(standard: standard, extended: otherSize).blockCount == 256)
        let smaller = ISO15693SystemInfo(uid: Data(), dsfid: nil, afi: nil, blockSize: 4, blockCount: 128, icReference: nil)
        #expect(ISO15693ExtendedSystemInfo.merge(standard: standard, extended: smaller).blockCount == 256)

        let unknown = ISO15693SystemInfo(uid: Data([0x01]), dsfid: nil, afi: nil, blockSize: -1, blockCount: -1, icReference: nil)
        #expect(ISO15693ExtendedSystemInfo.merge(standard: unknown, extended: larger).blockCount == 2048)
        #expect(ISO15693ExtendedSystemInfo.needsExtendedQuery(unknown))
        #expect(ISO15693ExtendedSystemInfo.needsExtendedQuery(standard))
        #expect(!ISO15693ExtendedSystemInfo.needsExtendedQuery(smaller))
    }

    // ISO/IEC 15693-3, GET MULTIPLE BLOCK SECURITY STATUS (2Ch) response: each block
    // security status byte carries Lock_flag in b1; b2-b8 are RFU. Some ST tags set
    // RFU bits for password protection, and ST25 SDK / NFC TagInfo mask with `& 1`.
    @Test
    func `Block security status uses only the Lock_flag bit`() {
        #expect(ISO15693BlockSecurityStatus.lockFlags(from: [0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF]) == [
            false, true, false, true, false, true,
        ])
        #expect(ISO15693BlockSecurityStatus.isLocked(0x06) == false)
        #expect(ISO15693BlockSecurityStatus.isLocked(0x81) == true)
    }
}

private final class MockISO15693SecurityTransport: ISO15693TagTransporting, @unchecked Sendable {
    let identifier = Data([0xE0, 0x04, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])
    let icManufacturerCode = 0x04
    var operations: [String] = []
    let customCommandResponse: Data
    let authenticateResponse: ISO15693SecurityResponse
    let keyUpdateResponse: ISO15693SecurityResponse

    init(
        customCommandResponse: Data = Data(),
        authenticateResponse: ISO15693SecurityResponse = .init(responseFlags: 0, data: Data()),
        keyUpdateResponse: ISO15693SecurityResponse = .init(responseFlags: 0, data: Data())
    ) {
        self.customCommandResponse = customCommandResponse
        self.authenticateResponse = authenticateResponse
        self.keyUpdateResponse = keyUpdateResponse
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

    func writeBlock(_: UInt8, data _: Data) async throws {
        throw NFCError.unsupportedOperation("unused")
    }

    func readBlocks(range _: NSRange) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        ISO15693SystemInfo(
            uid: identifier,
            dsfid: 0x00,
            afi: 0x00,
            blockSize: 4,
            blockCount: 32,
            icReference: 0x01
        )
    }

    func getBlockSecurityStatus(range _: NSRange) async throws -> [Bool] {
        []
    }

    func writeAFI(_ afi: UInt8) async throws {
        operations.append("writeAFI:\(String(format: "%02X", afi))")
    }

    func lockAFI() async throws {
        operations.append("lockAFI")
    }

    func writeDSFID(_ dsfid: UInt8) async throws {
        operations.append("writeDSFID:\(String(format: "%02X", dsfid))")
    }

    func lockDSFID() async throws {
        operations.append("lockDSFID")
    }

    func customCommand(code: Int, parameters: Data) async throws -> Data {
        operations.append("custom:\(String(format: "%02X", code)):\(parameters.hexString)")
        return customCommandResponse
    }

    func challenge(cryptoSuiteIdentifier: Int, message: Data) async throws {
        operations.append("challenge:\(String(format: "%02X", cryptoSuiteIdentifier)):\(message.hexString)")
    }

    func authenticate(cryptoSuiteIdentifier: Int, message: Data) async throws -> ISO15693SecurityResponse {
        operations.append("authenticate:\(String(format: "%02X", cryptoSuiteIdentifier)):\(message.hexString)")
        return authenticateResponse
    }

    func keyUpdate(keyIdentifier: Int, message: Data) async throws -> ISO15693SecurityResponse {
        operations.append("keyUpdate:\(String(format: "%02X", keyIdentifier)):\(message.hexString)")
        return keyUpdateResponse
    }
}

/// ISO 15693 tag with real memory: blocks 0-255 through READ/WRITE SINGLE BLOCK,
/// all blocks through the extended commands when `supportsExtended` is `true`.
private final class MemoryISO15693Transport: ISO15693TagTransporting, @unchecked Sendable {
    let identifier = Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    let icManufacturerCode = 0x04
    let blockCount: Int
    var supportsExtended: Bool
    var memory: [Int: Data] = [:]
    var writes: [Int] = []
    var extendedReads: [Int] = []
    var extendedWrites: [Int] = []
    /// Block count GET SYSTEM INFORMATION (2Bh) reports; `blockCount` when `nil`.
    var reportedBlockCount: Int?
    /// EXTENDED GET SYSTEM INFORMATION (3Bh) payload after the response flags;
    /// `nil` answers with ISO 15693 error 01h (command not supported).
    var extendedSystemInfo: Data?
    var extendedSystemInfoRequests: [UInt8] = []

    init(blockCount: Int, supportsExtended: Bool) {
        self.blockCount = blockCount
        self.supportsExtended = supportsExtended
    }

    func extendedGetSystemInfo(infoFlags: UInt8) async throws -> Data {
        extendedSystemInfoRequests.append(infoFlags)
        guard let extendedSystemInfo else { throw NFCError.iso15693Error(code: 0x01) }
        return extendedSystemInfo
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    private func block(_ number: Int) -> Data {
        memory[number] ?? Data(count: 4)
    }

    func readBlock(_ number: UInt8) async throws -> Data {
        block(Int(number))
    }

    func writeBlock(_ number: UInt8, data: Data) async throws {
        writes.append(Int(number))
        memory[Int(number)] = data
    }

    func extendedReadBlock(_ number: UInt16) async throws -> Data {
        // A tag without the extended commands answers with an error flag.
        guard supportsExtended else { throw NFCError.invalidResponse(Data([0x01, 0x01])) }
        guard Int(number) < blockCount else { throw NFCError.invalidResponse(Data([0x01, 0x10])) }
        extendedReads.append(Int(number))
        return block(Int(number))
    }

    func extendedWriteBlock(_ number: UInt16, data: Data) async throws {
        guard supportsExtended else { throw NFCError.invalidResponse(Data([0x01, 0x01])) }
        extendedWrites.append(Int(number))
        memory[Int(number)] = data
    }

    func readBlocks(range _: NSRange) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        ISO15693SystemInfo(
            uid: identifier,
            dsfid: 0,
            afi: 0,
            blockSize: 4,
            blockCount: reportedBlockCount ?? blockCount,
            icReference: 1
        )
    }

    func getBlockSecurityStatus(range: NSRange) async throws -> [Bool] {
        Array(repeating: false, count: range.length)
    }
}
