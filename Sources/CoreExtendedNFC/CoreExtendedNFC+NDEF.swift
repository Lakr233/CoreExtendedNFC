import Foundation

// MARK: - NDEF Operations

extension CoreExtendedNFC {
    /// Read and parse an NDEF message using the best available family-specific path.
    public static func readNDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> NDEFMessage {
        switch info.type.family {
        case .type4, .passport, .mifareDesfire:
            // Multi-application cards (e.g. ePassport chips that also carry NDEF)
            // sit on ISO 7816 transport, so try the Type 4 NDEF path as a fallback.
            let payload = try await Type4Tag(transport: transport).readNDEF()
            return try NDEFMessage(data: payload)
        case .felica:
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa NDEF reading requires a FeliCa transport")
            }
            let payload = try await FeliCaType3Reader(transport: felicaTransport).readNDEF()
            return try NDEFMessage(data: payload)
        case .iso15693:
            guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
                throw NFCError.unsupportedOperation("ISO 15693 NDEF reading requires an ISO 15693 transport")
            }
            let payload = try await readType5NDEF(transport: iso15693Transport)
            return try NDEFMessage(data: payload)
        case .ntag, .mifareUltralight:
            let dump = try await dumpCard(info: info, transport: transport)
            guard let parsed = dump.parsedNDEFMessage else {
                // NFC Forum T2T 1.0 §6.4.1: without the E1h CC magic the tag is not NDEF formatted.
                let ccPage = dump.pages.first(where: { $0.number == 3 })
                guard ccPage?.data.first == 0xE1 else { throw NFCError.tagNotNDEFFormatted }
                throw NFCError.ndefMessageNotFound
            }
            return parsed
        default:
            throw NFCError.tagNotSupported
        }
    }

    /// Write an NDEF message using the best available family-specific path.
    ///
    /// Type 2 and Type 5 tags must already be NDEF formatted: the CC is read first
    /// and the write is refused with ``NFCError/tagNotNDEFFormatted`` when it is
    /// missing, ``NFCError/ndefCapacityExceeded(required:capacity:)`` when the message
    /// does not fit, or ``NFCError/tagLocked`` when it denies write access. Only the
    /// blocks holding the NDEF TLV are written on Type 5 tags; use
    /// ``formatNDEF(info:transport:)`` to format a blank tag.
    public static func writeNDEF(
        _ message: NDEFMessage,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        // Refuse records that cannot be encoded instead of writing a truncated message.
        // A message with no records is written as an empty NDEF message (T2T/T5T
        // `03 00 FE`, T4T NLEN = 0, T3T Ln = 0), which is how a tag is erased.
        let payload = message.records.isEmpty ? Data() : try message.validatedData()
        switch info.type.family {
        case .type4, .passport, .mifareDesfire:
            // Multi-application cards sit on ISO 7816 transport, so use the Type 4 NDEF path.
            try await Type4Tag(transport: transport).writeNDEF(payload)
        case .felica:
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa NDEF writing requires a FeliCa transport")
            }
            try await FeliCaType3Reader(transport: felicaTransport).writeNDEF(payload)
        case .ntag, .mifareUltralight:
            try await writeType2NDEF(payload, info: info, transport: transport)
        case .iso15693:
            guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
                throw NFCError.unsupportedOperation("ISO 15693 NDEF writing requires an ISO 15693 transport")
            }
            try await writeType5NDEF(payload, transport: iso15693Transport)
        default:
            throw NFCError.tagNotSupported
        }
    }

    /// Format a blank tag for NDEF use by writing the Capability Container
    /// and an empty NDEF message area.
    ///
    /// Supported families:
    /// - Type 2 (Ultralight/NTAG): writes CC to page 3 and clears user pages.
    /// - Type 5 (ISO 15693): writes a fresh CC to block 0 and clears the data area.
    /// - Type 4 and Type 3: CC is managed by tag firmware and cannot be formatted via commands.
    ///
    /// - Warning: Formatting is destructive and, on Type 2 tags, partly irreversible.
    ///   It erases the user pages, and page 3 (the CC) is one-time programmable:
    ///   its bits are OR-ed into the current value and can never be cleared, so
    ///   a tag whose page 3 already holds other bits keeps them and may end up
    ///   with an unusable CC. This is the only library path that writes page 3
    ///   with the irreversible opt-in; ``writeNDEF(_:info:transport:)`` never
    ///   writes page 3.
    public static func formatNDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        switch info.type.family {
        case .ntag, .mifareUltralight:
            try await formatType2NDEF(info: info, transport: transport)
        case .iso15693:
            guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
                throw NFCError.unsupportedOperation("ISO 15693 NDEF formatting requires an ISO 15693 transport")
            }
            try await formatType5NDEF(transport: iso15693Transport)
        default:
            // Type 3 / Type 4 CCs are managed by the tag firmware.
            throw NFCError.tagNotSupported
        }
    }

    // MARK: - Private

    /// Read the NDEF message of a Type 5 tag without dumping the whole tag.
    ///
    /// Reads the CC from block 0, then only the blocks covering the T5T_Area announced
    /// by MLEN (NFC Forum T5T 1.0 §4.3.1 / §7.3). Blocks from 256 on are read with
    /// EXTENDED READ SINGLE BLOCK; when the tag rejects it the read stops there, so a
    /// message that ends past block 255 is then reported as not found.
    private static func readType5NDEF(
        transport: any ISO15693TagTransporting
    ) async throws -> Data {
        let systemInfo = try await transport.getSystemInfo()
        try requireKnownMemorySize(systemInfo)
        let blockSize = systemInfo.blockSize
        let reader = ISO15693Reader(transport: transport)

        var blocks: [MemoryDump.Block] = []
        var leadingBytes = Data()
        var extendedRejected = false
        /// Read the next block; `false` when no further block can be read.
        func readNextBlock() async throws -> Bool {
            try Task.checkCancellation()
            let number = blocks.count
            guard number < systemInfo.blockCount, !extendedRejected else { return false }
            let raw: Data
            if number < ISO15693Reader.singleByteAddressableBlocks {
                raw = try await reader.readBlock(at: number)
            } else if let data = try await reader.extendedReadIfSupported(number) {
                raw = data
            } else {
                extendedRejected = true
                return false
            }
            let data = Data(raw.prefix(blockSize))
            blocks.append(.init(number: number, data: data))
            leadingBytes.append(data)
            return true
        }

        guard try await readNextBlock() else {
            throw NFCError.ndefMessageNotFound
        }
        guard let ccLength = NDEFTagMapping.type5FormattedCCLength(leadingBytes: leadingBytes) else {
            throw NFCError.tagNotNDEFFormatted
        }
        while leadingBytes.count < ccLength {
            guard try await readNextBlock() else { break }
        }
        let areaLength = NDEFTagMapping.type5DataAreaLength(leadingBytes: leadingBytes) ?? 0
        let areaEnd = min(ccLength + areaLength, systemInfo.blockCount * blockSize)
        let blocksNeeded = (areaEnd + blockSize - 1) / blockSize
        while blocks.count < blocksNeeded {
            guard try await readNextBlock() else { break }
        }

        guard let payload = NDEFTagMapping.extractType5Message(from: blocks) else {
            throw NFCError.ndefMessageNotFound
        }
        return payload
    }

    /// ISO/IEC 15693-3 makes the memory-size field of Get System Information optional;
    /// CoreNFC then reports block size and count as `-1`.
    private static func requireKnownMemorySize(_ systemInfo: ISO15693SystemInfo) throws {
        guard systemInfo.blockCount > 0, systemInfo.blockSize > 0 else {
            throw NFCError.unsupportedOperation("The ISO 15693 tag did not report its memory size")
        }
    }

    /// Write `message` into the NDEF data area announced by the tag's Capability
    /// Container (page 3). The area is CC2 × 8 bytes (NFC Forum T2T 1.0 §6.1), which
    /// can be smaller than the user memory (NTAG215/216), and readers stop there.
    private static func writeType2NDEF(
        _ message: Data,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let memory = UltralightMemoryMap.forType(info.type)
        let commands = UltralightCommands(transport: transport)
        let ccPage = try await commands.readPages(startPage: 3)
        let capacity = try NDEFTagMapping.type2WritableCapacity(cc: ccPage, memoryMap: memory)
        try await writeType2Area(message, capacity: capacity, memory: memory, commands: commands)
    }

    private static func writeType2Area(
        _ message: Data,
        capacity: Int,
        memory: UltralightMemoryMap,
        commands: UltralightCommands
    ) async throws {
        let bytes = try NDEFTagMapping.buildType2Area(message: message, capacity: capacity)

        // Resolve every page address before the first write so an impossible layout
        // is refused up front instead of leaving the tag half-written.
        let writes = try stride(from: 0, to: bytes.count, by: 4).enumerated().map { index, offset in
            guard let page = UInt8(exactly: Int(memory.userDataStart) + index) else {
                throw NFCError.unsupportedOperation("Type 2 NDEF area extends beyond page 255")
            }
            return (page: page, chunk: Data(bytes[offset ..< min(offset + 4, bytes.count)]))
        }

        for write in writes {
            try Task.checkCancellation()
            try await commands.writePage(write.page, data: write.chunk, memoryMap: memory)
        }
    }

    private static func formatType2NDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        // Clear user data pages first, then write CC last.
        // If a write fails mid-way, the tag has no valid CC and won't be
        // recognised as NDEF-formatted — safer than leaving a CC pointing
        // at garbage data.
        let memory = UltralightMemoryMap.forType(info.type)
        let commands = UltralightCommands(transport: transport)
        try await writeType2Area(Data(), capacity: memory.userDataByteCount, memory: memory, commands: commands)

        // Write Capability Container to page 3 as the final step
        try Task.checkCancellation()
        // The CC is OTP on Type 2 tags (bits can only be set), so opt in explicitly.
        try await commands.writePage(
            3,
            data: NDEFTagMapping.buildType2CC(for: info.type),
            memoryMap: memory,
            allowIrreversible: true
        )
    }

    /// Write an NDEF message to an NDEF-formatted Type 5 tag.
    ///
    /// Reads the CC first and refuses tags that are not formatted (CC magic E1h/E2h)
    /// or deny write access, then writes only the blocks holding the NDEF TLV and
    /// its terminator. Use ``formatNDEF(info:transport:)`` to format a blank tag.
    private static func writeType5NDEF(
        _ message: Data,
        transport: any ISO15693TagTransporting
    ) async throws {
        let systemInfo = try await transport.getSystemInfo()
        try requireKnownMemorySize(systemInfo)
        guard systemInfo.blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }

        var leadingBytes = try await transport.readBlock(0)
        let ccLength = try NDEFTagMapping.type5CCLength(firstBlock: leadingBytes)
        var nextBlock: UInt8 = 1
        while leadingBytes.count < ccLength {
            try Task.checkCancellation()
            guard Int(nextBlock) < systemInfo.blockCount else {
                throw NFCError.invalidResponse(leadingBytes)
            }
            leadingBytes.append(try await transport.readBlock(nextBlock))
            nextBlock += 1
        }

        let writes: [(block: Int, data: Data)]
        do {
            writes = try NDEFTagMapping.type5NDEFWrites(
                message: message,
                leadingBytes: leadingBytes,
                blockSize: systemInfo.blockSize,
                blockCount: systemInfo.blockCount
            )
        } catch {
            // The single-byte addressable area (blocks 0-255) is too small. Use the
            // rest of a larger tag when it accepts the extended commands, probed with
            // a read before anything is written.
            guard systemInfo.blockCount > ISO15693Reader.singleByteAddressableBlocks,
                  let extendedWrites = try? type5ExtendedNDEFWrites(
                      message: message,
                      leadingBytes: leadingBytes,
                      blockSize: systemInfo.blockSize,
                      blockCount: systemInfo.blockCount
                  ),
                  let lastBlock = extendedWrites.last?.block,
                  try await ISO15693Reader(transport: transport).extendedReadIfSupported(lastBlock) != nil
            else { throw error }
            writes = extendedWrites
        }

        let reader = ISO15693Reader(transport: transport)
        for write in writes {
            try Task.checkCancellation()
            try await reader.writeBlock(at: write.block, data: write.data)
        }
    }

    /// Plan the block writes for `message` over the whole T5T_Area, including
    /// blocks above 255 (written with EXTENDED WRITE SINGLE BLOCK).
    ///
    /// Same layout as ``NDEFTagMapping/type5NDEFWrites(message:leadingBytes:blockSize:blockCount:)``
    /// (CC kept as read, NDEF TLV then terminator TLV, NFC Forum T5T 1.0 §4.3 / §7.5)
    /// without the single-byte addressing bound.
    private static func type5ExtendedNDEFWrites(
        message: Data,
        leadingBytes: Data,
        blockSize: Int,
        blockCount: Int
    ) throws -> [(block: Int, data: Data)] {
        let ccLength = try NDEFTagMapping.type5CCLength(firstBlock: leadingBytes)
        let cc = Data(leadingBytes.prefix(ccLength))
        guard cc.count == ccLength else {
            throw NFCError.invalidResponse(leadingBytes)
        }
        let areaLength = NDEFTagMapping.type5DataAreaLength(leadingBytes: leadingBytes) ?? 0
        let capacity = min(areaLength, max(0, blockCount * blockSize - ccLength))

        var tlv = Data([0x03])
        if message.count > 0xFE {
            tlv.append(contentsOf: [0xFF, UInt8((message.count >> 8) & 0xFF), UInt8(message.count & 0xFF)])
        } else {
            tlv.append(UInt8(message.count))
        }
        tlv.append(message)
        tlv.append(0xFE)
        guard tlv.count <= capacity else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 5 user memory")
        }

        var area = cc + tlv
        area.append(Data(repeating: 0x00, count: (blockSize - area.count % blockSize) % blockSize))
        let firstBlock = ccLength / blockSize
        let lastBlock = area.count / blockSize - 1
        return (firstBlock ... lastBlock).map { block in
            let offset = block * blockSize
            return (block, Data(area[offset ..< offset + blockSize]))
        }
    }

    /// Format a Type 5 tag: write a fresh CC and an empty NDEF message, clearing
    /// the rest of the single-byte addressable data area.
    private static func formatType5NDEF(
        transport: any ISO15693TagTransporting
    ) async throws {
        let systemInfo = try await transport.getSystemInfo()
        try requireKnownMemorySize(systemInfo)
        let blocks = try NDEFTagMapping.buildType5Blocks(
            message: Data(),
            blockSize: systemInfo.blockSize,
            blockCount: systemInfo.blockCount
        )
        // Validate every block address before the first write so a large tag is
        // refused up front instead of being left half-written.
        guard blocks.count <= NDEFTagMapping.type5SingleByteAddressableBlocks else {
            throw NFCError.unsupportedOperation("ISO 15693 writes beyond block 255 need extended commands")
        }

        for (index, block) in blocks.enumerated() {
            try Task.checkCancellation()
            guard let blockNumber = UInt8(exactly: index) else {
                throw NFCError.unsupportedOperation("ISO 15693 writes beyond block 255 need extended commands")
            }
            try await transport.writeBlock(blockNumber, data: block)
        }
    }
}
