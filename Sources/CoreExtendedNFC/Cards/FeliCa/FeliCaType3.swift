import Foundation

/// NFC Forum Type 3 tag NDEF reading.
/// Ported from libnfc utils/nfc-read-forum-tag3.c.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class FeliCaType3Reader: @unchecked Sendable {
    /// NDEF Read service code (little-endian): 0x000B.
    public static let readServiceCode = Data([0x0B, 0x00])
    /// NDEF Write service code (little-endian): 0x0009.
    public static let writeServiceCode = Data([0x09, 0x00])

    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read the Attribute Information Block (block 0).
    ///
    /// Throws ``NFCError/tagNotNDEFFormatted`` when the card has no NDEF read service
    /// (`0x000B`) or the attribute block is blank (all zeros), and
    /// ``NFCError/checksumMismatch`` when the block checksum is wrong.
    open func readAttributeInfo() async throws -> FeliCaAttributeInfo {
        let blockList = [FeliCaFrame.blockListElement(blockNumber: 0)]
        let blocks: [Data]
        do {
            blocks = try await transport.readWithoutEncryption(
                serviceCode: Self.readServiceCode,
                blockList: blockList
            )
        } catch let error as NFCError {
            guard case .felicaBlockReadFailed = error else { throw error }
            // Only the status flags come back; ask whether the NDEF service exists at all.
            let versions = try await transport.requestService(nodeCodeList: [Self.readServiceCode])
            if versions.first == Self.unavailableServiceVersion {
                throw NFCError.tagNotNDEFFormatted
            }
            throw error
        }
        guard let block = blocks.first, block.count >= 16 else {
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }
        // A blank attribute block (version 0, zero checksum) means no NDEF mapping.
        if block.prefix(16).allSatisfy({ $0 == 0x00 }) {
            throw NFCError.tagNotNDEFFormatted
        }
        return try FeliCaAttributeInfo(data: block)
    }

    /// Key version Request Service returns for a service the card does not have.
    public static let unavailableServiceVersion = Data([0xFF, 0xFF])

    /// Read NDEF message from Type 3 tag.
    open func readNDEF() async throws -> Data {
        NFCLog.info("FeliCa Type 3 NDEF read", source: "FeliCa")
        let attrInfo = try await readAttributeInfo()
        // NFC Forum T3T 1.0 §7.1: the NDEF is invalid unless the mapping major
        // version is 1, Nbr >= 1, WriteF == 00h (no interrupted write) and
        // Ln <= Nmaxb × 16.
        guard attrInfo.version >> 4 == 1 else {
            throw NFCError.unsupportedOperation(
                "Unsupported Type 3 mapping version \(attrInfo.version >> 4).\(attrInfo.version & 0x0F)"
            )
        }
        guard attrInfo.nbr > 0 else {
            throw NFCError.invalidResponse(attrInfo.encoded())
        }
        guard attrInfo.writeFlag == 0x00 else {
            throw NFCError.invalidResponse(attrInfo.encoded())
        }
        guard attrInfo.ndefLength <= UInt32(attrInfo.nmaxb) * UInt32(FeliCaMemory.blockSize) else {
            throw NFCError.invalidResponse(attrInfo.encoded())
        }
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
    open func writeNDEF(_ message: Data) async throws {
        NFCLog.info("FeliCa Type 3 NDEF write: \(message.count) bytes", source: "FeliCa")
        let attrInfo = try await readAttributeInfo()
        guard attrInfo.version >> 4 == 1 else {
            throw NFCError.unsupportedOperation(
                "Unsupported Type 3 mapping version \(attrInfo.version >> 4).\(attrInfo.version & 0x0F)"
            )
        }
        guard attrInfo.rwFlag == 0x01 else {
            throw NFCError.tagLocked
        }

        let maxLength = Int(attrInfo.nmaxb) * FeliCaMemory.blockSize
        guard message.count <= maxLength else {
            throw NFCError.ndefCapacityExceeded(required: message.count, capacity: maxLength)
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
    open func readBlocks(from startBlock: Int, count: Int, maxPerRead: Int) async throws -> Data {
        var result = Data()
        var remaining = count
        var currentBlock = startBlock

        guard maxPerRead > 0 else {
            throw NFCError.unsupportedOperation("Type 3 Nbr must be at least 1")
        }

        while remaining > 0 {
            try Task.checkCancellation()
            let chunkSize = min(remaining, maxPerRead)
            var blockList: [Data] = []
            for i in 0 ..< chunkSize {
                guard let blockNumber = UInt16(exactly: currentBlock + i) else {
                    throw NFCError.unsupportedOperation("Type 3 block number exceeds 65535")
                }
                blockList.append(FeliCaFrame.blockListElement(blockNumber: blockNumber))
            }

            let blocks = try await transport.readWithoutEncryption(
                serviceCode: Self.readServiceCode,
                blockList: blockList
            )
            guard blocks.count == chunkSize else {
                throw NFCError.invalidResponse(Data(blocks.joined()))
            }

            for block in blocks {
                guard block.count == FeliCaMemory.blockSize else {
                    throw NFCError.invalidResponse(block)
                }
                result.append(block)
            }

            currentBlock += chunkSize
            remaining -= chunkSize
        }

        return result
    }

    open func writeBlocks(startingAt startBlock: Int, blocks: [Data], maxPerWrite: Int) async throws {
        var remaining = blocks[...]
        var currentBlock = startBlock

        guard maxPerWrite > 0 else {
            throw NFCError.unsupportedOperation("Type 3 Nbw must be at least 1")
        }

        while !remaining.isEmpty {
            try Task.checkCancellation()
            let chunkCount = min(maxPerWrite, remaining.count)
            let chunk = Array(remaining.prefix(chunkCount))
            var blockList: [Data] = []
            for index in 0 ..< chunkCount {
                guard let blockNumber = UInt16(exactly: currentBlock + index) else {
                    throw NFCError.unsupportedOperation("Type 3 block number exceeds 65535")
                }
                blockList.append(FeliCaFrame.blockListElement(blockNumber: blockNumber))
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
            throw NFCError.checksumMismatch
        }
    }

    /// Re-encode the attribute block, optionally overriding the write flag,
    /// read/write flag and NDEF length, with a freshly computed checksum.
    public func encoded(
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
