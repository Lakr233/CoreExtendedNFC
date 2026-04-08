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
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
                ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82),
                ResponseAPDU(data: Data([0x04, 0x01, 0x01, 0x02, 0x00, 0x18, 0x05]), sw1: 0x91, sw2: 0xAF),
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
        #expect(transport.sentAPDUs.count == 5)
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
            return Int(element[1]) << 8 | Int(element[2])
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
