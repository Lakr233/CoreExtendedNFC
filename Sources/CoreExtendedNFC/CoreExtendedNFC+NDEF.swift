import Foundation

// MARK: - NDEF Operations

public extension CoreExtendedNFC {
    /// Read and parse an NDEF message using the best available family-specific path.
    ///
    /// An NDEF-formatted tag that holds an empty NDEF message (Type 2 / Type 5
    /// `03 00`, Type 4 NLEN = 0, Type 3 Ln = 0), as left by erasing it with
    /// ``writeNDEF(_:info:transport:)``, throws ``NFCError/ndefMessageNotFound`` on
    /// every family.
    ///
    /// On Type 2 tags the message is read up to the data area size the CC declares
    /// (CC byte 2 × 8 bytes, NFC Forum T2T 1.0 §6.1), also past the product's memory
    /// map when the product is not identified, stopping at the first page the tag rejects.
    static func readNDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> NDEFMessage {
        switch info.type.family {
        case .type4, .passport, .mifareDesfire:
            // Multi-application cards (e.g. ePassport chips that also carry NDEF)
            // sit on ISO 7816 transport, so try the Type 4 NDEF path as a fallback.
            let payload = try await Type4Reader(transport: transport).readNDEF()
            return try parseReadNDEF(payload)
        case .felica:
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa NDEF reading requires a FeliCa transport")
            }
            let payload = try await FeliCaType3Reader(transport: felicaTransport).readNDEF()
            return try parseReadNDEF(payload)
        case .iso15693:
            guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
                throw NFCError.unsupportedOperation("ISO 15693 NDEF reading requires an ISO 15693 transport")
            }
            let payload = try await readType5NDEF(transport: iso15693Transport)
            return try parseReadNDEF(payload)
        case .ntag, .mifareUltralight:
            let dump = try await dumpCard(info: info, transport: transport)
            if let parsed = dump.parsedNDEFMessage {
                return parsed
            }
            // NFC Forum T2T 1.0 §6.4.1: without the E1h CC magic the tag is not NDEF formatted.
            let ccPage = dump.pages.first(where: { $0.number == 3 })
            guard ccPage?.data.first == 0xE1 else { throw NFCError.tagNotNDEFFormatted }
            if let parsed = try await readType2NDEFPastMemoryMap(dump: dump, transport: transport) {
                return parsed
            }
            throw NFCError.ndefMessageNotFound
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
    ///
    /// Type 2 and Type 5 writes follow the NFC Forum write procedure: the NDEF TLV
    /// length is first written as zero, then the message, and the real length last,
    /// so an interrupted write leaves an empty message rather than a truncated one.
    /// On Type 2 tags the NDEF TLV is written at the start of the user area (page 4),
    /// after any Lock Control and Memory Control TLVs found there (NFC Forum T2T 1.0
    /// §2.3.4 / §2.3.5), which are kept unchanged. They are only kept when each has a
    /// length of 3 and they are followed by an NDEF or Terminator TLV, or only by NULL
    /// TLVs, within the pages read (pages 4-10); other leading bytes, such as earlier
    /// non-NDEF data, are overwritten from page 4. When such a TLV declares lock or
    /// reserved bytes inside the data area, the message and its padding stop before
    /// the page holding the first of them, and a tag whose reserved bytes share a page
    /// with the control TLVs is refused with ``NFCError/unsupportedOperation(_:)``.
    /// A Type 2 message that fills the data area exactly is written without a
    /// Terminator TLV. A Type 5 tag whose CC requires
    /// the special frame format (CC byte 3 b4) is refused with
    /// ``NFCError/unsupportedOperation(_:)``.
    static func writeNDEF(
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
            try await Type4Reader(transport: transport).writeNDEF(payload)
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
    static func formatNDEF(
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

    /// Parse the bytes a family reader returned; an empty NDEF message (length 0)
    /// is reported as ``NFCError/ndefMessageNotFound`` like on Type 2 tags.
    /// Read the rest of a Type 2 data area that the dump's memory map did not cover,
    /// and extract the NDEF message from it.
    ///
    /// The dump stops at the product's memory map, a conservative 16 pages for
    /// products GET_VERSION does not identify (NTAG I2C, and NTAG203 and other tags
    /// that do not answer it). The data area is CC byte 2 × 8 bytes from page 4
    /// (NFC Forum T2T 1.0 §6.1), so the pages up to its end are read, stopping at
    /// the first page the tag rejects. Only reads are sent; writes keep the memory
    /// map. Returns `nil` when the dump stopped early (a protected area), already
    /// holds a complete NDEF TLV (an erased tag's `03 00`), the CC declares nothing
    /// past it, or no message is found there.
    static func readType2NDEFPastMemoryMap(
        dump: MemoryDump,
        transport: any NFCTagTransport
    ) async throws -> NDEFMessage? {
        // A complete NDEF TLV inside the map (even an empty one, 03 00) leaves nothing
        // to look for further on; only a scan that ran out of bytes reads on.
        guard dump.capabilities == [.readable],
              NDEFTagMapping.extractType2Message(from: dump.pages) == nil,
              let declaredPages = NDEFTagMapping.type2DeclaredPageCount(from: dump.pages),
              let lastPage = dump.pages.last?.number,
              Int(lastPage) + 1 == dump.pages.count,
              declaredPages > dump.pages.count
        else { return nil }
        let reader = UltralightDump(commands: UltralightCommands(transport: transport))
        let extraPages = try await reader.readPagesUntilRejected(from: dump.pages.count, to: declaredPages)
        guard !extraPages.isEmpty,
              let payload = NDEFTagMapping.extractType2Message(from: dump.pages + extraPages)
        else { return nil }
        return try? NDEFMessage(data: payload)
    }

    static func parseReadNDEF(_ payload: Data) throws -> NDEFMessage {
        guard !payload.isEmpty else { throw NFCError.ndefMessageNotFound }
        return try NDEFMessage(data: payload)
    }

    /// Read the NDEF message of a Type 5 tag without dumping the whole tag.
    ///
    /// Reads the CC from block 0, then only the blocks covering the T5T_Area announced
    /// by MLEN (NFC Forum T5T 1.0 §4.3.1 / §7.3). A CC without the E1h / E2h magic or
    /// with a major version above 1 throws ``NFCError/tagNotNDEFFormatted``, and one
    /// that denies read access throws ``NFCError/tagLocked``. Blocks from 256 on are read with
    /// EXTENDED READ SINGLE BLOCK; when the tag rejects it the read stops there, so a
    /// message that ends past block 255 is then reported as not found.
    static func readType5NDEF(
        transport: any ISO15693TagTransporting
    ) async throws -> Data {
        let systemInfo = try await ISO15693Reader(transport: transport).getSystemInfo()
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
        // T5T 1.0 §7.3: magic, major version and read access are checked first.
        let ccLength = try NDEFTagMapping.type5ReadableCCLength(leadingBytes: leadingBytes)
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
    static func requireKnownMemorySize(_ systemInfo: ISO15693SystemInfo) throws {
        guard systemInfo.blockCount > 0, systemInfo.blockSize > 0 else {
            throw NFCError.unsupportedOperation("The ISO 15693 tag did not report its memory size")
        }
    }

    /// Write `message` into the NDEF data area announced by the tag's Capability
    /// Container (page 3). The area is CC2 × 8 bytes (NFC Forum T2T 1.0 §6.1), which
    /// can be smaller than the user memory (NTAG215/216), and readers stop there.
    static func writeType2NDEF(
        _ message: Data,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let memory = UltralightMemoryMap.forType(info.type)
        let commands = UltralightCommands(transport: transport)
        let ccPage = try await commands.readPages(startPage: 3)
        let capacity = try NDEFTagMapping.type2WritableCapacity(cc: ccPage, memoryMap: memory)

        // READ returns pages 3-6; keep the Lock / Memory Control TLVs at the start of
        // the data area, reading pages 7-10 once when one of them runs past page 6.
        let dataAreaOffset = Int(memory.userDataStart) * 4
        var leadingBytes = Data(ccPage.prefix(16).dropFirst(4).prefix(capacity))
        var layout = try NDEFTagMapping.type2WriteLayout(
            leadingBytes: leadingBytes,
            dataAreaOffset: dataAreaOffset,
            capacity: capacity
        )
        if layout == nil {
            let nextPage = Int(memory.userDataStart) + leadingBytes.count / 4
            if let page = UInt8(exactly: nextPage) {
                leadingBytes.append(try await commands.readPages(startPage: page).prefix(16))
                leadingBytes = Data(leadingBytes.prefix(capacity))
                // No more pages are read: control TLVs followed only by NULL TLVs are kept.
                layout = try NDEFTagMapping.type2WriteLayout(
                    leadingBytes: leadingBytes,
                    dataAreaOffset: dataAreaOffset,
                    capacity: capacity,
                    keepingControlTLVsBeforeNULLs: true
                )
            }
        }
        guard let plan = layout else {
            throw NFCError.unsupportedOperation("Type 2 control TLVs are too long; NDEF writing is not supported")
        }
        try await writeType2Area(
            message,
            capacity: plan.capacity,
            preservedPrefix: plan.preservedPrefix,
            endsDataArea: plan.endsDataArea,
            memory: memory,
            commands: commands
        )
    }

    static func writeType2Area(
        _ message: Data,
        capacity: Int,
        preservedPrefix: Data = Data(),
        endsDataArea: Bool = true,
        memory: UltralightMemoryMap,
        commands: UltralightCommands
    ) async throws {
        let bytes = try NDEFTagMapping.buildType2Area(
            message: message,
            capacity: capacity,
            preservedPrefix: preservedPrefix,
            endsDataArea: endsDataArea
        )

        // Resolve every page address before the first write so an impossible layout
        // is refused up front instead of leaving the tag half-written.
        let pages = try stride(from: 0, to: bytes.count, by: 4).enumerated().map { index, offset in
            guard UInt8(exactly: Int(memory.userDataStart) + index) != nil else {
                throw NFCError.unsupportedOperation("Type 2 NDEF area extends beyond page 255")
            }
            return (block: Int(memory.userDataStart) + index, data: Data(bytes[offset ..< min(offset + 4, bytes.count)]))
        }
        // NFC Forum write procedure: TLV length 0 first, the real length last.
        let writes = NDEFTagMapping.lengthLastWriteOrder(
            pages,
            blockSize: 4,
            tlvOffset: Int(memory.userDataStart) * 4 + preservedPrefix.count
        )

        for write in writes {
            try Task.checkCancellation()
            try await commands.writePage(UInt8(write.block), data: write.data, memoryMap: memory)
        }
    }

    static func formatType2NDEF(
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
    /// its terminator: the TLV length as zero first and the real length last.
    /// Use ``formatNDEF(info:transport:)`` to format a blank tag.
    static func writeType5NDEF(
        _ message: Data,
        transport: any ISO15693TagTransporting
    ) async throws {
        let systemInfo = try await ISO15693Reader(transport: transport).getSystemInfo()
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

        let reader = ISO15693Reader(transport: transport)
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
            guard systemInfo.blockCount > NDEFTagMapping.type5SingleByteAddressableBlocks,
                  let extendedWrites = try? NDEFTagMapping.type5NDEFWrites(
                      message: message,
                      leadingBytes: leadingBytes,
                      blockSize: systemInfo.blockSize,
                      blockCount: systemInfo.blockCount,
                      addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
                  ),
                  let lastBlock = extendedWrites.last?.block,
                  try await reader.extendedReadIfSupported(lastBlock) != nil
            else { throw error }
            writes = extendedWrites
        }

        let orderedWrites = NDEFTagMapping.lengthLastWriteOrder(
            writes,
            blockSize: systemInfo.blockSize,
            tlvOffset: ccLength
        )
        for write in orderedWrites {
            try Task.checkCancellation()
            try await reader.writeBlock(at: write.block, data: write.data)
        }
    }

    /// Format a Type 5 tag: write a fresh CC and an empty NDEF message, clearing
    /// the rest of the data area.
    ///
    /// On a tag with more than 256 blocks the T5T_Area covers the whole memory
    /// (CC magic E2h, NFC Forum T5T 1.0 §4.3.1) and blocks from 256 on are written
    /// with EXTENDED WRITE SINGLE BLOCK, once an EXTENDED READ SINGLE BLOCK of the
    /// last block shows the tag accepts the extended commands. Otherwise the area
    /// is confined to blocks 0-255 (CC magic E1h).
    static func formatType5NDEF(
        transport: any ISO15693TagTransporting
    ) async throws {
        let systemInfo = try await ISO15693Reader(transport: transport).getSystemInfo()
        try requireKnownMemorySize(systemInfo)
        let reader = ISO15693Reader(transport: transport)

        // Every block address is planned before the first write, so a layout the tag
        // cannot take is refused up front instead of leaving it half-written.
        var blocks = try NDEFTagMapping.buildType5Blocks(
            message: Data(),
            blockSize: systemInfo.blockSize,
            blockCount: systemInfo.blockCount
        )
        if systemInfo.blockCount > NDEFTagMapping.type5SingleByteAddressableBlocks {
            let extendedBlocks = try NDEFTagMapping.buildType5Blocks(
                message: Data(),
                blockSize: systemInfo.blockSize,
                blockCount: systemInfo.blockCount,
                addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
            )
            if try await reader.extendedReadIfSupported(extendedBlocks.count - 1) != nil {
                blocks = extendedBlocks
            }
        }

        for (blockNumber, block) in blocks.enumerated() {
            try Task.checkCancellation()
            try await reader.writeBlock(at: blockNumber, data: block)
        }
    }
}
