// Top-level integration tests: full dump flows for Ultralight C, Type 4, ISO 15693, FeliCa.
//
// ## References
// - NXP MF0ICU2 (Ultralight C) datasheet
//   https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf
// - NFC Forum Type 4 Tag Operation Specification v2.0
// - ISO/IEC 15693-3: vicinity card block read/write
// - NFC Forum Type 3 Tag Operation Specification
// - NXP AN10833: MIFARE type identification by ATQA+SAK
//   https://www.nxp.com/docs/en/application-note/AN10833.pdf
@testable import CoreExtendedNFC
import Foundation
import Testing

struct TopLevelIntegrationTests {
    @Test
    func `Top-level Ultralight C dump keeps readable pages and reports unreadable key tail`() async throws {
        let mock = MockTransport()
        mock.responses = stride(from: 0, through: 40, by: 4).map { startPage in
            Data((0 ..< 16).map { UInt8(startPage + $0) })
        }

        let info = CardInfo(type: .mifareUltralightC, uid: mock.identifier)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: mock)

        #expect(dump.pages.count == 44)
        #expect(dump.pages.last?.number == 43)
        #expect(dump.capabilities == [.partiallyReadable])
        #expect(dump.facts.contains(where: { $0.key == "Secret Key Pages" && $0.value == "44-47" }))
        #expect(mock.sentCommands.count == 11)
        #expect(mock.sentCommands.last == Data([0x30, 0x28]))
    }

    @Test
    func `Top-level Ultralight C dump reports auth boundary when later pages are protected`() async throws {
        let mock = MockTransport()
        mock.responses = stride(from: 0, through: 36, by: 4).map { startPage in
            Data((0 ..< 16).map { UInt8(startPage + $0) })
        } + [Data([0x00])]

        let info = CardInfo(type: .mifareUltralightC, uid: mock.identifier)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: mock)

        #expect(dump.pages.count == 40)
        #expect(dump.capabilities == [.authenticationRequired, .partiallyReadable])
        #expect(dump.facts.contains(where: { $0.key == "Unauthenticated Boundary" && $0.value == "Page 40" }))
    }

    @Test
    func `Top-level Type 4 dump captures NDEF and file metadata`() async throws {
        let mock = MockTransport()
        let ndefMessage = Data([0xD1, 0x01, 0x05, 0x54, 0x02, 0x65, 0x6E, 0x48, 0x69])

        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: validType4CC(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: validType4CC(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(
                data: Data([0x00, UInt8(ndefMessage.count)]),
                sw1: 0x90,
                sw2: 0x00
            ),
            ResponseAPDU(data: ndefMessage, sw1: 0x90, sw2: 0x00),
        ]

        let info = CardInfo(type: .type4NDEF, uid: mock.identifier, initialSelectedAID: Type4Constants.ndefAID.hexString)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: mock)

        #expect(dump.ndefMessage == ndefMessage)
        #expect(dump.files.count == 2)
        #expect(dump.files[0].identifier == Type4Constants.ccFileID)
        #expect(dump.files[1].identifier == Type4Constants.ndefFileID)
        #expect(dump.facts.contains(where: { $0.key == "NDEF Bytes" && $0.value == "\(ndefMessage.count)" }))
    }

    @Test
    func `Top-level ISO 15693 dump reads blocks and lock state`() async throws {
        let uid = Data([0xE0, 0x04, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])
        let blocks = [
            Data([0x10, 0x11, 0x12, 0x13]),
            Data([0x20, 0x21, 0x22, 0x23]),
            Data([0x30, 0x31, 0x32, 0x33]),
        ]
        let transport = MockISO15693Transport(
            identifier: uid,
            icManufacturerCode: 0x04,
            systemInfo: ISO15693SystemInfo(
                uid: uid,
                dsfid: 0x00,
                afi: 0x00,
                blockSize: 4,
                blockCount: blocks.count,
                icReference: 0x01
            ),
            blocks: blocks,
            locked: [false, true, false]
        )

        let info = CardInfo(type: .iso15693_generic, uid: uid, icManufacturer: 0x04)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)

        #expect(dump.blocks.count == blocks.count)
        #expect(dump.blocks[1].locked)
        #expect(dump.blocks[2].data == blocks[2])
        #expect(dump.facts.contains(where: { $0.key == "Blocks" && $0.value == "\(blocks.count)" }))
    }

    @Test
    func `Top-level FeliCa dump reads Type 3 NDEF blocks`() async throws {
        let idm = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let systemCode = Data([0x12, 0xFC])
        let ndef = Data([
            0xD1, 0x01, 0x0E, 0x54, 0x02, 0x65, 0x6E, 0x43,
            0x6F, 0x72, 0x65, 0x45, 0x78, 0x74, 0x65, 0x6E,
            0x64, 0x65, 0x64, 0x4E, 0x46, 0x43,
        ])
        let transport = MockFeliCaTransport(
            identifier: idm,
            systemCode: systemCode,
            attributeBlock: makeFeliCaAttributeBlock(ndefLength: ndef.count),
            ndefMessage: ndef
        )

        let info = CardInfo(type: .felicaStandard, uid: idm, systemCode: systemCode, idm: idm)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)

        #expect(dump.ndefMessage == ndef)
        #expect(dump.blocks.count == 3)
        #expect(dump.blocks[0].number == 0)
        #expect(dump.facts.contains(where: { $0.key == "System Code" && $0.value == systemCode.hexString }))
    }

    @Test
    func `Top-level FeliCa dump captures additional plain service snapshots`() async throws {
        let idm = Data([0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28])
        let systemCode = Data([0x88, 0xB4])
        let extraServiceCode = Data([0x8B, 0x00])
        let transport = MockFeliCaTransport(
            identifier: idm,
            systemCode: systemCode,
            attributeBlock: nil,
            ndefMessage: Data(),
            serviceVersions: [
                extraServiceCode: Data([0x00, 0x21]),
            ],
            serviceBlocks: [
                extraServiceCode: [
                    Data(repeating: 0xAB, count: FeliCaMemory.blockSize),
                    Data(repeating: 0xCD, count: FeliCaMemory.blockSize),
                ],
            ]
        )

        let info = CardInfo(type: .felicaLite, uid: idm, systemCode: systemCode, idm: idm)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)

        #expect(dump.ndefMessage == nil)
        #expect(dump.blocks.isEmpty)
        #expect(dump.files.count == 1)
        #expect(dump.files[0].identifier == extraServiceCode)
        #expect(dump.files[0].data.count == FeliCaMemory.blockSize * 2)
        #expect(dump.facts.contains(where: { $0.key == "Plain Service Snapshots" && $0.value == "1" }))
    }

    @Test
    func `ISO 7816 refiner classifies passport from initial AID`() async throws {
        let transport = QueuedISO7816Transport(initialAID: PassportConstants.eMRTDAID.hexString)
        let info = CardInfo(
            type: .smartMX,
            uid: transport.identifier,
            initialSelectedAID: PassportConstants.eMRTDAID.hexString
        )

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .ePassport)
        #expect(transport.sentAPDUs.isEmpty)
    }

    @Test
    func `ISO 7816 refiner classifies My Number card from initial AID`() async throws {
        let aid = "D3921000310001010408"
        let transport = QueuedISO7816Transport(initialAID: aid)
        let info = CardInfo(
            type: .smartMX,
            uid: transport.identifier,
            initialSelectedAID: aid
        )

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .myNumberCard)
        #expect(transport.sentAPDUs.isEmpty)
    }

    @Test
    func `ISO 7816 refiner probes Type 4 when metadata is absent`() async throws {
        let transport = QueuedISO7816Transport(
            responses: [
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: validType4CC(), sw1: 0x90, sw2: 0x00),
            ]
        )
        let info = CardInfo(type: .smartMX, uid: transport.identifier)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .type4NDEF)
        #expect(transport.sentAPDUs.count == 4)
    }

    @Test
    func `ISO 7816 refiner does not trust permissive passport SELECT over Type 4 CC`() async throws {
        let transport = QueuedISO7816Transport(
            responses: [
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: validType4CC(), sw1: 0x90, sw2: 0x00),
            ]
        )
        let info = CardInfo(type: .smartMX, uid: transport.identifier)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .type4NDEF)
        #expect(transport.sentAPDUs.count == 4)
    }

    @Test
    func `ISO 7816 refiner falls back to DESFire probe`() async throws {
        let transport = QueuedISO7816Transport(
            responses: [
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // eMRTD SELECT
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // NDEF AID D2760000850101
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // NDEF mapping 1.0 AID D2760000850100
                // HW frame: NXP, DESFire, HW major 0x12 = EV2 (MF3D(H)x2 datasheet).
                ResponseAPDU(data: Data([0x04, 0x01, 0x01, 0x12, 0x00, 0x18, 0x05]), sw1: 0x91, sw2: 0xAF),
                // SW frame: EV2 software major 0x02.
                ResponseAPDU(data: Data([0x04, 0x01, 0x01, 0x02, 0x00, 0x18, 0x05]), sw1: 0x91, sw2: 0xAF),
                ResponseAPDU(
                    data: Data([
                        0x04, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
                        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0x15, 0x26,
                    ]),
                    sw1: 0x91,
                    sw2: 0x00
                ),
            ]
        )
        let info = CardInfo(type: .smartMX, uid: transport.identifier)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .mifareDesfireEV2)
        #expect(transport.sentAPDUs.count == 6)
    }

    @Test
    func `MIFARE Classic refiner corrects Type 2 tag with GET VERSION`() async throws {
        let uid = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        let transport = MockTransport(identifier: uid)
        transport.responses = [
            type2ManufacturerPages(uid: uid),
            Data([0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03]),
        ]
        let info = CardInfo(type: .mifareClassic1K, uid: uid)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .mifareUltralightEV1_MF0UL21)
        #expect(transport.sentCommands == [Data([0x30, 0x00]), Data([0x60])])
    }

    @Test
    func `MIFARE Classic refiner corrects legacy Type 2 tag without GET VERSION`() async throws {
        let uid = Data([0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let transport = MockTransport(identifier: uid)
        transport.responses = [type2ManufacturerPages(uid: uid)]
        let info = CardInfo(type: .mifareClassic1K, uid: uid)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .mifareUltralight)
        // GET_VERSION and the READ 2Bh Ultralight C probe both go unanswered.
        #expect(transport.sentCommands == [Data([0x30, 0x00]), Data([0x60]), Data([0x30, 0x2B])])
    }

    @Test
    func `MIFARE Classic refiner keeps Classic when Type 2 manufacturer page check fails`() async throws {
        let uid = Data([0x04, 0x01, 0x02, 0x03])
        let transport = MockTransport(identifier: uid)
        transport.responses = [Data(repeating: 0x00, count: 16)]
        let info = CardInfo(type: .mifareClassic1K, uid: uid)

        let refined = try await CardInfoRefiner.refine(info, transport: transport)

        #expect(refined.type == .mifareClassic1K)
        #expect(transport.sentCommands == [Data([0x30, 0x00])])
    }
}

private func validType4CC() -> Data {
    Data([
        0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x34,
        0x04, 0x06, 0xE1, 0x04, 0x00, 0xFE, 0x00, 0x00,
    ])
}

private func makeFeliCaAttributeBlock(ndefLength: Int, nbr: UInt8 = 4, nbw: UInt8 = 1, rwFlag: UInt8 = 1) -> Data {
    var block = Data(repeating: 0x00, count: 16)
    block[0] = 0x10
    block[1] = nbr
    block[2] = nbw
    block[3] = 0x00
    block[4] = 0x20
    block[9] = 0x00
    block[10] = rwFlag
    block[11] = UInt8((ndefLength >> 16) & 0xFF)
    block[12] = UInt8((ndefLength >> 8) & 0xFF)
    block[13] = UInt8(ndefLength & 0xFF)

    var checksum: UInt16 = 0
    for index in 0 ..< 14 {
        checksum &+= UInt16(block[index])
    }
    block[14] = UInt8((checksum >> 8) & 0xFF)
    block[15] = UInt8(checksum & 0xFF)
    return block
}

private func type2ManufacturerPages(uid: Data) -> Data {
    let uidBytes = [UInt8](uid)
    let bcc0 = 0x88 ^ uidBytes[0] ^ uidBytes[1] ^ uidBytes[2]
    let bcc1 = uidBytes[3] ^ uidBytes[4] ^ uidBytes[5] ^ uidBytes[6]
    return Data([
        uidBytes[0], uidBytes[1], uidBytes[2], bcc0,
        uidBytes[3], uidBytes[4], uidBytes[5], uidBytes[6],
        bcc1, 0x48, 0x00, 0x00,
        0xE1, 0x10, 0x06, 0x00,
    ])
}

final class MockISO15693Transport: ISO15693TagTransporting, @unchecked Sendable {
    let identifier: Data
    let icManufacturerCode: Int
    let systemInfo: ISO15693SystemInfo
    let blocks: [Data]
    let locked: [Bool]

    init(
        identifier: Data,
        icManufacturerCode: Int,
        systemInfo: ISO15693SystemInfo,
        blocks: [Data],
        locked: [Bool]
    ) {
        self.identifier = identifier
        self.icManufacturerCode = icManufacturerCode
        self.systemInfo = systemInfo
        self.blocks = blocks
        self.locked = locked
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw commands are not used in this test transport")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("APDUs are not used in this test transport")
    }

    func readBlock(_ number: UInt8) async throws -> Data {
        blocks[Int(number)]
    }

    func writeBlock(_: UInt8, data _: Data) async throws {
        throw NFCError.unsupportedOperation("Block writes are not used in this test transport")
    }

    func readBlocks(range: NSRange) async throws -> [Data] {
        Array(blocks[range.location ..< range.location + range.length])
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        systemInfo
    }

    func getBlockSecurityStatus(range: NSRange) async throws -> [Bool] {
        Array(locked[range.location ..< range.location + range.length])
    }
}

final class MockFeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier: Data
    let systemCode: Data
    let attributeBlock: Data?
    let ndefMessage: Data
    let serviceVersions: [Data: Data]
    let serviceBlocks: [Data: [Data]]

    init(
        identifier: Data,
        systemCode: Data,
        attributeBlock: Data?,
        ndefMessage: Data,
        serviceVersions: [Data: Data] = [:],
        serviceBlocks: [Data: [Data]] = [:]
    ) {
        self.identifier = identifier
        self.systemCode = systemCode
        self.attributeBlock = attributeBlock
        self.ndefMessage = ndefMessage
        self.serviceVersions = serviceVersions
        self.serviceBlocks = serviceBlocks
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw commands are not used in this test transport")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("APDUs are not used in this test transport")
    }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        try blockList.map { element in
            let blockNumber = try parseFeliCaBlockNumber(element)
            if serviceCode == FeliCaType3Reader.readServiceCode, blockNumber == 0, let attributeBlock {
                return attributeBlock
            }

            if serviceCode == FeliCaType3Reader.readServiceCode {
                guard blockNumber > 0 else {
                    throw NFCError.felicaBlockReadFailed(statusFlag: 0xA1)
                }
                let start = (blockNumber - 1) * FeliCaMemory.blockSize
                let end = min(start + FeliCaMemory.blockSize, ndefMessage.count)
                var chunk = start < end ? Data(ndefMessage[start ..< end]) : Data()
                if chunk.count < FeliCaMemory.blockSize {
                    chunk.append(Data(repeating: 0x00, count: FeliCaMemory.blockSize - chunk.count))
                }
                return chunk
            }

            guard let blocks = serviceBlocks[serviceCode], blockNumber < blocks.count else {
                throw NFCError.felicaBlockReadFailed(statusFlag: 0xA1)
            }
            return blocks[blockNumber]
        }
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        nodeCodeList.map { code in
            if let version = serviceVersions[code] {
                return version
            }
            if code == FeliCaType3Reader.readServiceCode, attributeBlock != nil {
                return Data([0x00, 0x10])
            }
            if code == FeliCaType3Reader.writeServiceCode, attributeBlock != nil {
                return Data([0x00, 0x11])
            }
            return Data([0xFF, 0xFF])
        }
    }

    private func parseFeliCaBlockNumber(_ element: Data) throws -> Int {
        switch element.count {
        case 2:
            return Int(element[1])
        case 3:
            // 3-byte block list element: block number is little-endian (JIS X 6319-4).
            return Int(element[1]) | Int(element[2]) << 8
        default:
            throw NFCError.invalidResponse(element)
        }
    }
}

final class QueuedISO7816Transport: ISO7816TagTransporting, @unchecked Sendable {
    let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])
    let initialAID: String
    var responses: [ResponseAPDU]
    var sentAPDUs: [CommandAPDU] = []
    private var responseIndex = 0

    init(initialAID: String = "", responses: [ResponseAPDU] = []) {
        self.initialAID = initialAID
        self.responses = responses
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw commands are not used in this test transport")
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        sentAPDUs.append(apdu)
        guard responseIndex < responses.count else {
            throw NFCError.tagConnectionLost
        }
        defer { responseIndex += 1 }
        return responses[responseIndex]
    }

    func sendAPDUWithChaining(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        try await sendAPDU(apdu)
    }
}

struct TopLevelRobustnessTests {
    private static let uid = Data([0xE0, 0x04, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])

    private static func systemInfo(blockSize: Int, blockCount: Int) -> ISO15693SystemInfo {
        ISO15693SystemInfo(uid: uid, dsfid: 0, afi: 0, blockSize: blockSize, blockCount: blockCount, icReference: 0)
    }

    @Test
    func `ISO 15693 dump with unknown memory size throws`() async {
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: -1, blockCount: -1))
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        await #expect(throws: NFCError.self) { // before: traps on 0 ..< -1
            _ = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        }
    }

    @Test
    func `ISO 15693 NDEF write with unknown memory size throws before writing`() async {
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: -1, blockCount: -1))
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        await #expect(throws: NFCError.self) {
            try await CoreExtendedNFC.writeNDEF(.uri("https://a.b"), info: info, transport: transport)
        }
        #expect(transport.writtenBlocks.isEmpty)
    }

    @Test
    func `ISO 15693 NDEF write on a tag with more than 256 blocks stays single-byte addressable`() async throws {
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: 4, blockCount: 512))
        transport.ccBlock = Data([0xE1, 0x40, 0x7F, 0x00])
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        // before: traps on UInt8(256) after 256 writes
        try await CoreExtendedNFC.writeNDEF(.uri("https://a.b"), info: info, transport: transport)
        #expect(!transport.writtenBlocks.isEmpty)
        #expect(transport.writtenBlocks.count <= 256)
    }

    @Test
    func `ISO 15693 dump omits system info fields the tag did not report`() async throws {
        let transport = RecordingISO15693Transport(systemInfo: ISO15693SystemInfo(
            uid: Self.uid, dsfid: nil, afi: 0x07, blockSize: 4, blockCount: 2, icReference: nil
        ))
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        let dump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        #expect(!dump.facts.contains(where: { $0.key == "DSFID" }))
        #expect(!dump.facts.contains(where: { $0.key == "IC Reference" }))
        #expect(dump.facts.contains(where: { $0.key == "AFI" && $0.value == "0x07" }))
    }

    @Test
    func `ISO 15693 dump stops when its task is cancelled`() async {
        let transport = RecordingISO15693Transport(
            systemInfo: Self.systemInfo(blockSize: 4, blockCount: 16),
            cancelAfterReadingBlock: 0
        )
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        let task = Task {
            try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        }
        await #expect(throws: CancellationError.self) {
            _ = try await task.value
        }
        #expect(transport.readBlocks == [0]) // before: all 16 blocks read
    }

    @Test
    func `dumpCard refuses to start in a cancelled task`() async {
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: 4, blockCount: 4))
        let info = CardInfo(type: .iso15693_generic, uid: Self.uid)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        }
        await #expect(throws: CancellationError.self) {
            _ = try await task.value
        }
        #expect(transport.readBlocks.isEmpty)
    }

    @Test
    func `ISO 15693 dump survives a silent optional security-status command`() async throws {
        // Get Multiple Block Security Status is optional (ISO/IEC 15693-3); CoreNFC
        // reports a silent tag as 100/101, i.e. tagConnectionLost.
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: 4, blockCount: 4))
        transport.securityStatusError = .tagConnectionLost
        let dump = try await CoreExtendedNFC.dumpCard( // before: threw tagConnectionLost
            info: CardInfo(type: .iso15693_generic, uid: Self.uid),
            transport: transport
        )
        #expect(dump.blocks.count == 4)
        #expect(dump.blocks.allSatisfy { !$0.locked })
    }

    @Test
    func `ISO 15693 dump still fails when the tag is really gone`() async {
        let transport = RecordingISO15693Transport(systemInfo: Self.systemInfo(blockSize: 4, blockCount: 4))
        transport.securityStatusError = .tagConnectionLost
        transport.readBlockError = .tagConnectionLost
        await #expect(throws: NFCError.self) {
            _ = try await CoreExtendedNFC.dumpCard(info: CardInfo(type: .iso15693_generic, uid: Self.uid), transport: transport)
        }
        #expect(transport.readBlocks == [0])
    }

    @Test
    func `FeliCa dump fails when the tag is lost during service probing`() async {
        let transport = SessionLossFeliCaTransport()
        let info = CardInfo(type: .felicaStandard, uid: transport.identifier, systemCode: transport.systemCode, idm: transport.identifier)
        await #expect(throws: NFCError.self) { // before: returns an empty "successful" dump
            _ = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        }
    }

    @Test
    func `FeliCa dump fails when the tag is lost reading the Type 3 attribute block`() async {
        let transport = SessionLossFeliCaTransport(failRequestService: false)
        let info = CardInfo(type: .felicaStandard, uid: transport.identifier, systemCode: transport.systemCode, idm: transport.identifier)
        await #expect(throws: NFCError.self) { // before: error swallowed by catch {}
            _ = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
        }
    }
}

private final class RecordingISO15693Transport: ISO15693TagTransporting, @unchecked Sendable {
    let identifier = Data([0xE0, 0x04, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])
    let icManufacturerCode = 0x04
    let systemInfo: ISO15693SystemInfo
    let cancelAfterReadingBlock: UInt8?
    var securityStatusError: NFCError?
    var readBlockError: NFCError?
    var readBlocks: [UInt8] = []
    var writtenBlocks: [UInt8] = []
    /// Block 0 contents; `nil` reads as the filler pattern (not NDEF formatted).
    var ccBlock: Data?

    init(systemInfo: ISO15693SystemInfo, cancelAfterReadingBlock: UInt8? = nil) {
        self.systemInfo = systemInfo
        self.cancelAfterReadingBlock = cancelAfterReadingBlock
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readBlock(_ number: UInt8) async throws -> Data {
        readBlocks.append(number)
        if let readBlockError { throw readBlockError }
        if number == cancelAfterReadingBlock {
            withUnsafeCurrentTask { $0?.cancel() }
        }
        if number == 0, let ccBlock { return ccBlock }
        return Data(repeating: number, count: max(systemInfo.blockSize, 0))
    }

    func writeBlock(_ number: UInt8, data _: Data) async throws {
        writtenBlocks.append(number)
    }

    func readBlocks(range _: NSRange) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        systemInfo
    }

    func getBlockSecurityStatus(range: NSRange) async throws -> [Bool] {
        if let securityStatusError { throw securityStatusError }
        return Array(repeating: false, count: range.length)
    }
}

/// A FeliCa tag that is removed mid-dump: CoreNFC errors arrive as `tagConnectionLost`.
private final class SessionLossFeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    let systemCode = Data([0x12, 0xFC])
    let failRequestService: Bool

    init(failRequestService: Bool = true) {
        self.failRequestService = failRequestService
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.tagConnectionLost
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readWithoutEncryption(serviceCode _: Data, blockList _: [Data]) async throws -> [Data] {
        throw NFCError.tagConnectionLost
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {
        throw NFCError.tagConnectionLost
    }

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        if failRequestService {
            throw NFCError.tagConnectionLost
        }
        // Only the NDEF read service exists.
        return nodeCodeList.map { $0 == FeliCaType3Reader.readServiceCode ? Data([0x00, 0x10]) : Data([0xFF, 0xFF]) }
    }
}
