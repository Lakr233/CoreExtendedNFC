import Foundation

/// NFC Forum Type 3 tag NDEF reading.
/// Ported from libnfc utils/nfc-read-forum-tag3.c.
public struct FeliCaType3Reader: Sendable {
    /// NDEF Read service code (little-endian): 0x000B.
    public static let readServiceCode = Data([0x0B, 0x00])
    /// NDEF Write service code (little-endian): 0x0009.
    public static let writeServiceCode = Data([0x09, 0x00])

    private let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read the Attribute Information Block (block 0).
    public func readAttributeInfo() async throws -> FeliCaAttributeInfo {
        let blockList = [FeliCaFrame.blockListElement(blockNumber: 0)]
        let blocks = try await transport.readWithoutEncryption(
            serviceCode: Self.readServiceCode,
            blockList: blockList
        )
        guard let block = blocks.first, block.count >= 16 else {
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }
        return try FeliCaAttributeInfo(data: block)
    }

    /// Read NDEF message from Type 3 tag.
    public func readNDEF() async throws -> Data {
        NFCLog.info("FeliCa Type 3 NDEF read", source: "FeliCa")
        let attrInfo = try await readAttributeInfo()
        guard attrInfo.ndefLength > 0 else {
            return Data()
        }
        NFCLog.debug("NDEF length=\(attrInfo.ndefLength), NBR=\(attrInfo.nbr)", source: "FeliCa")

        let totalBlocks = (Int(attrInfo.ndefLength) + FeliCaMemory.blockSize - 1) / FeliCaMemory.blockSize // ceil division
        let blockData = try await readBlocks(
            from: 1,
            count: totalBlocks,
            maxPerRead: Int(attrInfo.nbr)
        )

        return Data(blockData.prefix(Int(attrInfo.ndefLength)))
    }

    /// Write an NDEF message to a Type 3 tag using the NFC Forum write procedure.
    public func writeNDEF(_ message: Data) async throws {
        NFCLog.info("FeliCa Type 3 NDEF write: \(message.count) bytes", source: "FeliCa")
        let attrInfo = try await readAttributeInfo()
        guard attrInfo.rwFlag == 0x01 else {
            throw NFCError.tagLocked
        }

        let maxLength = Int(attrInfo.nmaxb) * FeliCaMemory.blockSize
        guard message.count <= maxLength else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 3 tag capacity")
        }

        let paddedMessageBlocks = stride(from: 0, to: message.count, by: FeliCaMemory.blockSize).map { offset in
            var block = Data(message[offset ..< min(offset + FeliCaMemory.blockSize, message.count)])
            if block.count < FeliCaMemory.blockSize {
                block.append(Data(repeating: 0x00, count: FeliCaMemory.blockSize - block.count))
            }
            return block
        }

        try await writeBlocks(
            startingAt: 0,
            blocks: [attrInfo.encoded(writeFlag: 0x0F, ndefLength: UInt32(message.count))],
            maxPerWrite: max(1, Int(attrInfo.nbw))
        )

        if !paddedMessageBlocks.isEmpty {
            try await writeBlocks(
                startingAt: 1,
                blocks: paddedMessageBlocks,
                maxPerWrite: max(1, Int(attrInfo.nbw))
            )
        }

        try await writeBlocks(
            startingAt: 0,
            blocks: [attrInfo.encoded(writeFlag: 0x00, ndefLength: UInt32(message.count))],
            maxPerWrite: max(1, Int(attrInfo.nbw))
        )
    }

    /// Read a range of blocks, chunking to respect max blocks per CHECK.
    func readBlocks(from startBlock: Int, count: Int, maxPerRead: Int) async throws -> Data {
        var result = Data()
        var remaining = count
        var currentBlock = startBlock

        while remaining > 0 {
            let chunkSize = min(remaining, maxPerRead)
            var blockList: [Data] = []
            for i in 0 ..< chunkSize {
                blockList.append(FeliCaFrame.blockListElement(blockNumber: UInt16(currentBlock + i)))
            }

            let blocks = try await transport.readWithoutEncryption(
                serviceCode: Self.readServiceCode,
                blockList: blockList
            )

            for block in blocks {
                result.append(block)
            }

            currentBlock += chunkSize
            remaining -= chunkSize
        }

        return result
    }

    func writeBlocks(startingAt startBlock: Int, blocks: [Data], maxPerWrite: Int) async throws {
        var remaining = blocks[...]
        var currentBlock = startBlock

        while !remaining.isEmpty {
            let chunkCount = min(maxPerWrite, remaining.count)
            let chunk = Array(remaining.prefix(chunkCount))
            var blockList: [Data] = []
            for index in 0 ..< chunkCount {
                blockList.append(FeliCaFrame.blockListElement(blockNumber: UInt16(currentBlock + index)))
            }

            try await transport.writeWithoutEncryption(
                serviceCode: Self.writeServiceCode,
                blockList: blockList,
                blockData: chunk
            )

            remaining.removeFirst(chunkCount)
            currentBlock += chunkCount
        }
    }
}

/// FeliCa Type 3 Attribute Information Block (block 0 of NDEF service).
public struct FeliCaAttributeInfo: Sendable {
    /// Mapping version (e.g., 0x10 = v1.0).
    public let version: UInt8
    /// Max blocks per CHECK (read) command.
    public let nbr: UInt8
    /// Max blocks per UPDATE (write) command.
    public let nbw: UInt8
    /// Max number of NDEF data blocks.
    public let nmaxb: UInt16
    /// Reserved bytes 5...8.
    public let reserved: Data
    /// Write flag: 0x00=finished, 0x0F=writing in progress.
    public let writeFlag: UInt8
    /// Read/write access: 0x00=read-only, 0x01=read-write.
    public let rwFlag: UInt8
    /// NDEF message length (3-byte big-endian).
    public let ndefLength: UInt32
    /// Checksum of bytes 0-13.
    public let checksum: UInt16

    public init(data: Data) throws {
        guard data.count >= 16 else {
            throw NFCError.invalidResponse(data)
        }
        let d = Array(data)
        version = d[0]
        nbr = d[1]
        nbw = d[2]
        nmaxb = UInt16(d[3]) << 8 | UInt16(d[4])
        reserved = Data(d[5 ..< 9])
        writeFlag = d[9]
        rwFlag = d[10]
        // NDEF length: 3 bytes big-endian at bytes 11-13
        ndefLength = UInt32(d[11]) << 16 | UInt32(d[12]) << 8 | UInt32(d[13])
        checksum = UInt16(d[14]) << 8 | UInt16(d[15])

        // Verify checksum
        var sum: UInt16 = 0
        for i in 0 ..< 14 {
            sum = sum &+ UInt16(d[i])
        }
        guard sum == checksum else {
            throw NFCError.crcMismatch
        }
    }

    func encoded(
        writeFlag: UInt8? = nil,
        rwFlag: UInt8? = nil,
        ndefLength: UInt32? = nil
    ) -> Data {
        var block = Data(repeating: 0x00, count: 16)
        block[0] = version
        block[1] = nbr
        block[2] = nbw
        block[3] = UInt8((nmaxb >> 8) & 0xFF)
        block[4] = UInt8(nmaxb & 0xFF)
        block.replaceSubrange(5 ..< 9, with: reserved)
        block[9] = writeFlag ?? self.writeFlag
        block[10] = rwFlag ?? self.rwFlag

        let resolvedLength = ndefLength ?? self.ndefLength
        block[11] = UInt8((resolvedLength >> 16) & 0xFF)
        block[12] = UInt8((resolvedLength >> 8) & 0xFF)
        block[13] = UInt8(resolvedLength & 0xFF)

        var sum: UInt16 = 0
        for index in 0 ..< 14 {
            sum = sum &+ UInt16(block[index])
        }
        block[14] = UInt8((sum >> 8) & 0xFF)
        block[15] = UInt8(sum & 0xFF)
        return block
    }
}
