import Foundation

/// ISO 15693 full tag dump operations.
public extension ISO15693Reader {
    /// Read all blocks using the ISO15693 transport.
    func readAllBlocks(transport: any ISO15693TagTransporting) async throws -> MemoryDump {
        let sysInfo = try await transport.getSystemInfo()

        let blockCount = sysInfo.blockCount
        let blockSize = sysInfo.blockSize

        guard blockCount > 0, blockSize > 0 else {
            throw NFCError.unsupportedOperation("ISO 15693 tag did not report its memory size")
        }
        // READ SINGLE BLOCK carries a one-byte block number; blocks past 255
        // need the extended commands, which this transport does not expose.
        guard blockCount <= NDEFTagMapping.type5SingleByteAddressableBlocks else {
            throw NFCError.unsupportedOperation("ISO 15693 reads beyond block 255 need extended addressing commands")
        }

        var blocks: [MemoryDump.Block] = []

        for i in 0 ..< blockCount {
            try Task.checkCancellation()
            guard let blockNumber = UInt8(exactly: i) else {
                throw NFCError.unsupportedOperation("ISO 15693 reads beyond block 255 need extended addressing commands")
            }
            let data = try await transport.readBlock(blockNumber)
            blocks.append(MemoryDump.Block(number: i, data: Data(data.prefix(blockSize))))
        }

        let cardInfo = CardInfo(
            type: .iso15693_generic,
            uid: transport.identifier,
            icManufacturer: transport.icManufacturerCode
        )

        return MemoryDump(cardInfo: cardInfo, blocks: blocks)
    }

    /// Write a single block using the ISO15693 transport.
    func writeBlock(_ number: UInt8, data: Data, transport: ISO15693Transport) async throws {
        try await transport.writeBlock(number, data: data)
    }
}
