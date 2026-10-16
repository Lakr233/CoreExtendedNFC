import Foundation

/// ISO 15693 full tag dump and block addressing.
public extension ISO15693Reader {
    /// Read every block of the tag through ``transport``.
    ///
    /// Blocks 0-255 use READ SINGLE BLOCK; blocks from 256 on use EXTENDED READ
    /// SINGLE BLOCK (ISO/IEC 15693-3 command 30h, 2-byte block number). When the
    /// tag or transport rejects the extended command, the dump stops there: it is
    /// marked ``CardCapability/partiallyReadable`` and a "Blocks Read" fact
    /// records how many blocks were read.
    ///
    /// Lock flags come from Get Multiple Block Security Status for blocks 0-255;
    /// blocks above 255 are reported unlocked.
    ///
    /// - Parameter info: The scanned card, stored in the dump. When `nil`, a
    ///   generic ISO 15693 ``CardInfo`` is built from the transport's UID and IC
    ///   manufacturer code.
    /// - Throws: ``NFCError/unsupportedOperation(_:)`` when the tag does not
    ///   report its memory size, and transport errors from the mandatory reads.
    func readAllBlocks(info: CardInfo? = nil) async throws -> MemoryDump {
        let systemInfo = try await transport.getSystemInfo()
        guard systemInfo.blockCount > 0, systemInfo.blockSize > 0 else {
            throw NFCError.unsupportedOperation("The ISO 15693 tag did not report its memory size")
        }
        let singleByteBlocks = min(systemInfo.blockCount, Self.singleByteAddressableBlocks)

        // Get Multiple Block Security Status is optional (ISO/IEC 15693-3 §10.4.13), and
        // a tag may stay silent instead of answering with an error. CoreNFC reports that
        // silence with the same transceive codes (100/101) as a removed tag, so it is not
        // taken as final here: the mandatory block reads below fail on block 0 if the
        // tag is really gone.
        let lockStatuses: [Bool]
        do {
            lockStatuses = try await transport.getBlockSecurityStatus(
                range: NSRange(location: 0, length: singleByteBlocks)
            )
        } catch where !isSessionTerminating(error) || isMissingTagResponse(error) {
            lockStatuses = Array(repeating: false, count: singleByteBlocks)
        }

        var blocks: [MemoryDump.Block] = []
        for blockNumber in 0 ..< singleByteBlocks {
            try Task.checkCancellation()
            let data = try await transport.readBlock(UInt8(blockNumber))
            blocks.append(.init(
                number: blockNumber,
                data: Data(data.prefix(systemInfo.blockSize)),
                locked: lockStatuses.indices.contains(blockNumber) ? lockStatuses[blockNumber] : false
            ))
        }

        var rejectedExtendedBlock: Int?
        for blockNumber in singleByteBlocks ..< systemInfo.blockCount {
            try Task.checkCancellation()
            guard let data = try await extendedReadIfSupported(blockNumber) else {
                rejectedExtendedBlock = blockNumber
                break
            }
            blocks.append(.init(number: blockNumber, data: Data(data.prefix(systemInfo.blockSize))))
        }

        let ndefMessage = NDEFTagMapping.extractType5Message(from: blocks)
        let cardInfo = info ?? CardInfo(
            type: .iso15693_generic,
            uid: transport.identifier,
            icManufacturer: transport.icManufacturerCode
        )
        let truncationFact: MemoryDump.Fact? = rejectedExtendedBlock.map { block in
            .init(
                key: "Blocks Read",
                value: "\(blocks.count) of \(systemInfo.blockCount) (the tag rejected extended addressing at block \(block))"
            )
        }

        return MemoryDump(
            cardInfo: cardInfo,
            blocks: blocks,
            ndefMessage: ndefMessage,
            facts: [
                .init(key: "Block Size", value: "\(systemInfo.blockSize) bytes"),
                .init(key: "Blocks", value: "\(systemInfo.blockCount)"),
                truncationFact,
                systemInfo.dsfid.map { .init(key: "DSFID", value: String(format: "0x%02X", $0), monospaced: true) },
                systemInfo.afi.map { .init(key: "AFI", value: String(format: "0x%02X", $0), monospaced: true) },
                systemInfo.icReference.map { .init(key: "IC Reference", value: String(format: "0x%02X", $0), monospaced: true) },
                ndefMessage.map { .init(key: "NDEF Bytes", value: "\($0.count)") },
            ].compactMap(\.self),
            capabilities: rejectedExtendedBlock == nil ? [.readable] : [.partiallyReadable]
        )
    }

    /// Read the tag through `transport` instead of this reader's own transport.
    @available(*, deprecated, message: "Use readAllBlocks(info:), which reads through the reader's transport")
    func readAllBlocks(transport: any ISO15693TagTransporting) async throws -> MemoryDump {
        try await ISO15693Reader(transport: transport).readAllBlocks()
    }

    /// Read one block, using EXTENDED READ SINGLE BLOCK for blocks from 256 on.
    ///
    /// - Throws: ``NFCError/invalidParameter(_:)`` when `number` is outside
    ///   0...65535; transport errors, including the tag rejecting the extended command.
    func readBlock(at number: Int) async throws -> Data {
        if let single = UInt8(exactly: number) {
            return try await transport.readBlock(single)
        }
        guard let extended = UInt16(exactly: number) else {
            throw NFCError.invalidParameter("ISO 15693 block number \(number) is out of range")
        }
        return try await transport.extendedReadBlock(extended)
    }

    /// Write one block, using EXTENDED WRITE SINGLE BLOCK for blocks from 256 on.
    ///
    /// - Throws: ``NFCError/invalidParameter(_:)`` when `number` is outside
    ///   0...65535; transport errors, including the tag rejecting the extended command.
    func writeBlock(at number: Int, data: Data) async throws {
        if let single = UInt8(exactly: number) {
            return try await transport.writeBlock(single, data: data)
        }
        guard let extended = UInt16(exactly: number) else {
            throw NFCError.invalidParameter("ISO 15693 block number \(number) is out of range")
        }
        try await transport.extendedWriteBlock(extended, data: data)
    }

    /// Write a single block through `transport`.
    @available(*, deprecated, message: "Use writeBlock(at:data:), which writes through the reader's transport")
    func writeBlock(_ number: UInt8, data: Data, transport: any ISO15693TagTransporting) async throws {
        try await transport.writeBlock(number, data: data)
    }
}

extension ISO15693Reader {
    /// Highest block count reachable with READ / WRITE SINGLE BLOCK, whose block
    /// number is one byte (ISO/IEC 15693-3 §10.4.1).
    static let singleByteAddressableBlocks = 256

    /// EXTENDED READ SINGLE BLOCK, or `nil` when the tag or transport rejects it.
    ///
    /// The extended commands are optional, and a tag that does not implement them
    /// may stay silent; CoreNFC reports that like a lost tag, so a missing answer
    /// also counts as "not supported". Session loss and cancellation are rethrown.
    func extendedReadIfSupported(_ number: Int) async throws -> Data? {
        guard let address = UInt16(exactly: number) else { return nil }
        do {
            return try await transport.extendedReadBlock(address)
        } catch where !isSessionTerminating(error) || isMissingTagResponse(error) {
            return nil
        }
    }
}
