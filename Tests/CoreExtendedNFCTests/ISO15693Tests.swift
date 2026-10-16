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
    func `readAllBlocks rejects more than 256 blocks instead of trapping`() async {
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
        await #expect(throws: NFCError.self) {
            _ = try await ISO15693Reader(transport: transport).readAllBlocks(transport: transport)
        }
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
        let dump = try await ISO15693Reader(transport: transport).readAllBlocks(transport: transport)
        #expect(dump.blocks.count == 256)
        #expect(dump.blocks.last?.data == Data(repeating: 0xFF, count: 4))
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
