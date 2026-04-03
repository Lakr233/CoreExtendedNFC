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
// - Block list element: 2-byte format (0x80|blk) for blocks <256, 3-byte for >=256
@testable import CoreExtendedNFC
import Foundation
import Testing

struct FeliCaTests {
    // MARK: - Frame Assembly

    @Test("Block list element 2-byte format for small block numbers")
    func blockListElement2Byte() {
        let element = FeliCaFrame.blockListElement(blockNumber: 5)
        #expect(element == Data([0x80, 0x05]))
    }

    @Test("Block list element 3-byte format for large block numbers")
    func blockListElement3Byte() {
        let element = FeliCaFrame.blockListElement(blockNumber: 0x0100)
        #expect(element.count == 3)
        #expect(element[0] == 0x00) // service index
        #expect(element[1] == 0x01) // high byte
        #expect(element[2] == 0x00) // low byte
    }

    @Test("Block list element 0 (first block)")
    func blockListElementZero() {
        let element = FeliCaFrame.blockListElement(blockNumber: 0)
        #expect(element == Data([0x80, 0x00]))
    }

    @Test("Block list element encodes service index in 2-byte format")
    func blockListElementServiceIndex() {
        let element = FeliCaFrame.blockListElement(blockNumber: 5, serviceIndex: 3)
        #expect(element == Data([0x83, 0x05]))
    }

    // MARK: - Attribute Info Parsing

    @Test("Parse valid attribute info block")
    func parseAttributeInfo() throws {
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

    @Test("Attribute info with bad checksum throws")
    func badChecksum() {
        var block = Data(repeating: 0x00, count: 16)
        block[14] = 0xFF // wrong checksum
        block[15] = 0xFF

        #expect(throws: NFCError.self) {
            _ = try FeliCaAttributeInfo(data: block)
        }
    }

    @Test("Attribute info with short data throws")
    func shortData() {
        #expect(throws: NFCError.self) {
            _ = try FeliCaAttributeInfo(data: Data(repeating: 0, count: 10))
        }
    }

    // MARK: - Memory Model

    @Test("FeliCa block size is 16")
    func blockSize() {
        #expect(FeliCaMemory.blockSize == 16)
    }

    @Test("Command codes")
    func commandCodes() {
        #expect(FeliCaFrame.POLLING == 0x04)
        #expect(FeliCaFrame.CHECK == 0x06)
        #expect(FeliCaFrame.UPDATE == 0x08)
    }

    @Test("Probe common FeliCa services returns detected service metadata")
    func probeCommonServices() async throws {
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

    @Test("Plain service reads stop after the last readable block on each service")
    func readPlainServicesSequentially() async throws {
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

        let snapshots = await commands.readPlainServices(probes, maxBlocksPerService: 4)

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

    @Test("Plain service reads batch multiple services and split on boundary failures")
    func readPlainServicesBatchedAcrossServices() async {
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

        let snapshots = await commands.readPlainServices(services, maxBlocksPerService: 3)

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
}
