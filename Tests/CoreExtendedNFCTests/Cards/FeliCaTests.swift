// FeliCa / NFC Forum Type 3 Tag test suite.
//
// ## References
// - JIS X 6319-4: FeliCa interface specification
// - NFC Forum Type 3 Tag Operation Specification v1.0
//   https://nfc-forum.org/build/specifications
// - Sony FeliCa Lite-S User's Manual: command codes POLLING(0x04), CHECK(0x06), UPDATE(0x08)
// - NFC Forum Type 3: Attribute Information Block (16 bytes with 2-byte checksum)
// - libnfc nfc-read-forum-tag3.c:
//   https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-read-forum-tag3.c
// - Block list element: 2-byte format (0x80|blk) for blocks <256, 3-byte (LE block number) for >=256
@testable import CoreExtendedNFC
import Foundation
import Testing

struct FeliCaTests {
    // MARK: - Frame Assembly

    @Test
    func `Block list element 2-byte format for small block numbers`() {
        let element = FeliCaFrame.blockListElement(blockNumber: 5)
        #expect(element == Data([0x80, 0x05]))
    }

    @Test
    func `Block list element 3-byte format for large block numbers`() {
        let element = FeliCaFrame.blockListElement(blockNumber: 0x0100)
        #expect(element.count == 3)
        // Sony FeliCa Card User's Manual: 3-byte element carries the block
        // number little-endian (D1 = low byte, D2 = high byte).
        #expect(element == Data([0x00, 0x00, 0x01]))
    }

    @Test
    func `3-byte block list element is little-endian with service index`() {
        #expect(FeliCaFrame.blockListElement(blockNumber: 0x0123, serviceIndex: 2) == Data([0x02, 0x23, 0x01]))
    }

    @Test
    func `Block list element 0 (first block)`() {
        let element = FeliCaFrame.blockListElement(blockNumber: 0)
        #expect(element == Data([0x80, 0x00]))
    }

    @Test
    func `Block list element encodes service index in 2-byte format`() {
        let element = FeliCaFrame.blockListElement(blockNumber: 5, serviceIndex: 3)
        #expect(element == Data([0x83, 0x05]))
    }

    // MARK: - Attribute Info Parsing

    @Test
    func `Parse valid attribute info block`() throws {
        // Version=1.0, nbr=4, nbw=1, nmaxb=0x000D (13),
        // reserved, writeFlag=0, rwFlag=1, ndefLen=0x000042 (66)
        var block = Data(repeating: 0x00, count: 16)
        block[0] = 0x10 // version 1.0
        block[1] = 0x04 // nbr
        block[2] = 0x01 // nbw
        block[3] = 0x00 // nmaxb high
        block[4] = 0x0D // nmaxb low
        block[9] = 0x00 // writeFlag
        block[10] = 0x01 // rwFlag
        block[11] = 0x00 // ndefLen byte 0
        block[12] = 0x00 // ndefLen byte 1
        block[13] = 0x42 // ndefLen byte 2

        // Calculate checksum (sum of bytes 0-13)
        var sum: UInt16 = 0
        for i in 0 ..< 14 {
            sum &+= UInt16(block[i])
        }
        block[14] = UInt8((sum >> 8) & 0xFF)
        block[15] = UInt8(sum & 0xFF)

        let info = try FeliCaAttributeInfo(data: block)
        #expect(info.version == 0x10)
        #expect(info.nbr == 4)
        #expect(info.nbw == 1)
        #expect(info.nmaxb == 13)
        #expect(info.rwFlag == 0x01)
        #expect(info.ndefLength == 0x42)
    }

    @Test
    func `Attribute info with bad checksum throws`() {
        var block = Data(repeating: 0x00, count: 16)
        block[14] = 0xFF // wrong checksum
        block[15] = 0xFF

        #expect(throws: NFCError.self) {
            _ = try FeliCaAttributeInfo(data: block)
        }
    }

    @Test
    func `Attribute info with short data throws`() {
        #expect(throws: NFCError.self) {
            _ = try FeliCaAttributeInfo(data: Data(repeating: 0, count: 10))
        }
    }

    // MARK: - Memory Model

    @Test
    func `FeliCa block size is 16`() {
        #expect(FeliCaMemory.blockSize == 16)
    }

    @Test
    func `Command codes`() {
        #expect(FeliCaFrame.POLLING == 0x04)
        #expect(FeliCaFrame.CHECK == 0x06)
        #expect(FeliCaFrame.UPDATE == 0x08)
    }

    @Test
    func `Probe common FeliCa services returns detected service metadata`() async throws {
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [
                FeliCaType3Reader.readServiceCode: Data([0x00, 0x10]),
                Data([0x8B, 0x00]): Data([0x00, 0x21]),
            ]
        )

        let services = try await FeliCaCommands(transport: transport).probeCommonServices(maxServiceIndex: 2)

        #expect(services.count == 2)
        #expect(services.contains(where: { $0.serviceCode == FeliCaType3Reader.readServiceCode && $0.label == "NDEF Read Service" }))
        #expect(services.contains(where: { $0.serviceCode == Data([0x8B, 0x00]) && $0.label == "Random Read-Only Service #2" }))
    }

    @Test
    func `Plain service reads stop after the last readable block on each service`() async throws {
        let serviceCode = Data([0x8B, 0x00])
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [serviceCode: Data([0x00, 0x21])],
            serviceBlocks: [
                serviceCode: [
                    Data(repeating: 0x11, count: FeliCaMemory.blockSize),
                    Data(repeating: 0x22, count: FeliCaMemory.blockSize),
                ],
            ]
        )
        let commands = FeliCaCommands(transport: transport)
        let probes = try await commands.probeCommonServices(maxServiceIndex: 2)

        let snapshots = try await commands.readPlainServices(probes, maxBlocksPerService: 4)

        #expect(snapshots.count == 1)
        #expect(snapshots[0].serviceCode == serviceCode)
        #expect(snapshots[0].blocks.count == 2)
        #expect(snapshots[0].payload.count == FeliCaMemory.blockSize * 2)
        #expect(transport.readLog == [
            ["\(serviceCode.hexString):0"],
            ["\(serviceCode.hexString):1"],
            ["\(serviceCode.hexString):2"],
        ])
    }

    @Test
    func `Plain service reads batch multiple services and split on boundary failures`() async throws {
        let serviceA = Data([0x8B, 0x00])
        let serviceB = Data([0x4B, 0x00])
        let transport = MockFeliCaServiceTransport(
            serviceVersions: [
                serviceA: Data([0x00, 0x21]),
                serviceB: Data([0x00, 0x34]),
            ],
            serviceBlocks: [
                serviceA: [
                    Data(repeating: 0x11, count: FeliCaMemory.blockSize),
                    Data(repeating: 0x12, count: FeliCaMemory.blockSize),
                ],
                serviceB: [
                    Data(repeating: 0x21, count: FeliCaMemory.blockSize),
                ],
            ]
        )
        let commands = FeliCaCommands(transport: transport)
        let services = [
            FeliCaCommands.ServiceProbe(serviceCode: serviceA, label: "A", keyVersion: Data([0x00, 0x21])),
            FeliCaCommands.ServiceProbe(serviceCode: serviceB, label: "B", keyVersion: Data([0x00, 0x34])),
        ]

        let snapshots = try await commands.readPlainServices(services, maxBlocksPerService: 3)

        #expect(snapshots.count == 2)
        #expect(snapshots[0].blocks.count == 2)
        #expect(snapshots[1].blocks.count == 1)
        #expect(transport.readLog.first == [
            "\(serviceA.hexString):0",
            "\(serviceB.hexString):0",
        ])
        #expect(transport.readLog.contains([
            "\(serviceA.hexString):1",
            "\(serviceB.hexString):1",
        ]))
        #expect(transport.readLog.contains(["\(serviceA.hexString):1"]))
        #expect(transport.readLog.contains(["\(serviceB.hexString):1"]))
    }

    // MARK: - Service attributes (Sony FeliCa Card User's Manual)

    @Test
    func `Service attribute codes follow the FeliCa attribute table`() {
        #expect(FeliCaMemory.ServiceType.randomReadWrite.accessBits == 0x09)
        #expect(FeliCaMemory.ServiceType.randomReadOnly.accessBits == 0x0B)
        #expect(FeliCaMemory.ServiceType.cyclicReadWrite.accessBits == 0x0D)
        #expect(FeliCaMemory.ServiceType.cyclicReadOnly.accessBits == 0x0F)
        #expect(FeliCaMemory.ServiceType.purseDirectAccess.accessBits == 0x11)
        #expect(FeliCaMemory.ServiceType.purseCashback.accessBits == 0x13)
    }

    @Test
    func `Common service codes include cyclic services`() {
        let codes = FeliCaCommands.commonServiceCodes(maxServiceIndex: 36).map(\.serviceCode)
        #expect(codes.contains(Data([0x0F, 0x00])))
        #expect(codes.contains(Data([0x0D, 0x00])))
        // CJRC history service 0x090F = (36 << 6) | 0x0F, little-endian on the wire.
        #expect(codes.contains(Data([0x0F, 0x09])))
    }

    @Test
    func `Multi-service reads never put more than 16 services in one request`() async throws {
        var versions: [Data: Data] = [:]
        var blocks: [Data: [Data]] = [:]
        for serviceNumber in 0 ..< 20 {
            let code = UInt16(serviceNumber) << 6 | 0x0B
            let encoded = Data([UInt8(code & 0xFF), UInt8(code >> 8)])
            versions[encoded] = Data([0x00, 0x01])
            blocks[encoded] = [Data(repeating: UInt8(serviceNumber), count: FeliCaMemory.blockSize)]
        }
        let transport = MockFeliCaServiceTransport(serviceVersions: versions, serviceBlocks: blocks)
        let commands = FeliCaCommands(transport: transport)
        let probes = try await commands.probeCommonServices(maxServiceIndex: 19)
        #expect(probes.count == 20)

        let snapshots = try await commands.readPlainServices(probes, maxBlocksPerService: 1)

        #expect(snapshots.count == 20)
        #expect(transport.readLog.allSatisfy { $0.count <= 16 })
        #expect(transport.readLog.count == 2)
    }

    // MARK: - Type 3 NDEF validation (NFC Forum T3T 1.0 §7.1)

    @Test
    func `Type 3 readNDEF rejects Nbr of zero`() async {
        let transport = type3Transport(attribute: Self.attributeBlock(nbr: 0, ndefLength: 13))
        await #expect(throws: NFCError.self) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 readNDEF rejects interrupted write`() async {
        let transport = type3Transport(attribute: Self.attributeBlock(writeFlag: 0x0F, ndefLength: 13))
        await #expect(throws: NFCError.self) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 readNDEF rejects Ln beyond Nmaxb blocks`() async {
        let transport = type3Transport(attribute: Self.attributeBlock(nmaxb: 1, ndefLength: 17))
        await #expect(throws: NFCError.self) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 readNDEF rejects unsupported major version`() async {
        let transport = type3Transport(attribute: Self.attributeBlock(version: 0x20, ndefLength: 13))
        await #expect(throws: NFCError.self) {
            _ = try await FeliCaType3Reader(transport: transport).readNDEF()
        }
    }

    @Test
    func `Type 3 readNDEF reads valid message`() async throws {
        let message = Data((0 ..< 20).map { UInt8($0) })
        let transport = type3Transport(
            attribute: Self.attributeBlock(nmaxb: 4, ndefLength: UInt32(message.count)),
            body: [Data(message.prefix(16)), Data(message.suffix(4)) + Data(count: 12)]
        )
        let ndef = try await FeliCaType3Reader(transport: transport).readNDEF()
        #expect(ndef == message)
    }

    private func type3Transport(attribute: Data, body: [Data] = []) -> MockFeliCaServiceTransport {
        MockFeliCaServiceTransport(
            serviceVersions: [:],
            serviceBlocks: [FeliCaType3Reader.readServiceCode: [attribute] + body]
        )
    }

    private static func attributeBlock(
        version: UInt8 = 0x10,
        nbr: UInt8 = 4,
        nmaxb: UInt16 = 13,
        writeFlag: UInt8 = 0x00,
        ndefLength: UInt32
    ) -> Data {
        var block = Data(repeating: 0x00, count: 16)
        block[0] = version
        block[1] = nbr
        block[2] = 1
        block[3] = UInt8(nmaxb >> 8)
        block[4] = UInt8(nmaxb & 0xFF)
        block[9] = writeFlag
        block[10] = 0x01
        block[11] = UInt8((ndefLength >> 16) & 0xFF)
        block[12] = UInt8((ndefLength >> 8) & 0xFF)
        block[13] = UInt8(ndefLength & 0xFF)
        let sum = block.prefix(14).reduce(UInt16(0)) { $0 &+ UInt16($1) }
        block[14] = UInt8(sum >> 8)
        block[15] = UInt8(sum & 0xFF)
        return block
    }

    @Test
    func `Plain service reads rethrow tag loss instead of reporting an empty probe`() async {
        let transport = TagLossFeliCaServiceTransport()
        let services = [
            FeliCaCommands.ServiceProbe(serviceCode: Data([0x8B, 0x00]), label: "A", keyVersion: Data([0x00, 0x10])),
            FeliCaCommands.ServiceProbe(serviceCode: Data([0x4B, 0x00]), label: "B", keyVersion: Data([0x00, 0x10])),
        ]

        let error = await #expect(throws: NFCError.self) {
            _ = try await FeliCaCommands(transport: transport).readPlainServices(services, maxBlocksPerService: 2)
        }
        guard case .tagConnectionLost? = error else {
            Issue.record("expected tagConnectionLost, got \(String(describing: error))")
            return
        }
        // One shared read, no bisection retries after the tag is gone.
        #expect(transport.readCount == 1)
    }

    // MARK: - Block writes (Sony FeliCa Lite-S User's Manual: 1 block per write)

    @Test
    func `writeFeliCaBlocks sends one block per Write Without Encryption by default`() async throws {
        let transport = RecordingFeliCaWriteTransport()
        let blocks = (0 ..< 3).map { Data(repeating: UInt8($0), count: 16) }

        try await CoreExtendedNFC.writeFeliCaBlocks(startingAt: 5, blocks: blocks, transport: transport)

        // before: one command carrying all three blocks, which FeliCa Lite / Lite-S reject.
        #expect(transport.writes.map(\.blockList) == [
            [Data([0x80, 0x05])], [Data([0x80, 0x06])], [Data([0x80, 0x07])],
        ])
        #expect(transport.writes.map(\.blockData) == blocks.map { [$0] })
    }

    @Test
    func `writeFeliCaBlocks groups blocks when the caller allows it`() async throws {
        let transport = RecordingFeliCaWriteTransport()
        let blocks = Array(repeating: Data(count: 16), count: 3)

        try await CoreExtendedNFC.writeFeliCaBlocks(startingAt: 1, blocks: blocks, maxBlocksPerWrite: 2, transport: transport)

        #expect(transport.writes.map(\.blockList.count) == [2, 1])
    }
}

/// A FeliCa tag that records every Write Without Encryption.
private final class RecordingFeliCaWriteTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    let systemCode = Data([0x88, 0xB4])
    var writes: [(blockList: [Data], blockData: [Data])] = []

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readWithoutEncryption(serviceCode _: Data, blockList _: [Data]) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList: [Data], blockData: [Data]) async throws {
        writes.append((blockList, blockData))
    }

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        nodeCodeList.map { _ in Data([0x00, 0x00]) }
    }
}

/// A FeliCa tag that leaves the field on the first block read.
private final class TagLossFeliCaServiceTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    let systemCode = Data([0x12, 0xFC])
    var readCount = 0

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readWithoutEncryption(serviceCodeList _: [Data], blockList _: [Data]) async throws -> [Data] {
        readCount += 1
        throw NFCError.tagConnectionLost
    }

    func readWithoutEncryption(serviceCode _: Data, blockList _: [Data]) async throws -> [Data] {
        readCount += 1
        throw NFCError.tagConnectionLost
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {
        throw NFCError.tagConnectionLost
    }

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        nodeCodeList.map { _ in Data([0x00, 0x10]) }
    }
}
