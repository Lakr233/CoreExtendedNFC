import Foundation

/// CoreExtendedNFC — high-level API for NFC tag operations on iOS.
///
/// Provides card identification, command construction, memory models,
/// and dump/restore orchestration on top of CoreNFC's RF transport.
public enum CoreExtendedNFC {
    /// Scan for any NFC tag, identify it, and return card info + transport.
    ///
    /// The returned ``NFCSessionManager`` keeps the NFC session alive.
    /// Call ``NFCSessionManager/invalidate()`` when you are done with the transport.
    ///
    /// - Throws: ``NFCError``. When the user dismisses the NFC sheet or the calling task
    ///   is cancelled, the error's ``Swift/Error/isNFCCancellation`` is `true`; apps
    ///   usually stay silent then.
    public static func scan(
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport, NFCSessionManager) {
        let manager = NFCSessionManager()
        let (info, transport) = try await manager.scan(message: message)

        do {
            let refinedInfo = try await refineCardInfo(info, transport: transport)
            manager.setAlertMessage(String(localized: "Detected \(refinedInfo.type.description)", bundle: .module))
            return (refinedInfo, transport, manager)
        } catch {
            // Never leave the system NFC sheet open when the caller gets no manager back.
            throw manager.invalidateAfterFailure(error)
        }
    }

    /// Scan and automatically dump the card's full memory.
    public static func scanAndDump(
        message: String? = nil
    ) async throws -> (CardInfo, MemoryDump) {
        let (info, transport, manager) = try await scan(message: message)

        // Non-operable cards (Classic, etc.) — return identification only
        guard info.type.isOperableOnIOS else {
            manager.invalidate()
            return (info, MemoryDump(cardInfo: info))
        }

        do {
            manager.setAlertMessage(String(localized: "Reading...", bundle: .module))
            let dump = try await dumpCard(info: info, transport: transport)
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return (info, dump)
        } catch {
            throw manager.invalidateAfterFailure(error)
        }
    }

    /// Dump a card's memory using an already-connected transport.
    public static func dumpCard(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        try Task.checkCancellation()
        NFCLog.info("Dumping \(info.type.description)", source: "Core")
        switch info.type.family {
        case .mifareUltralight, .ntag:
            let commands = UltralightCommands(transport: transport)
            let map = UltralightMemoryMap.forType(info.type)
            let dumper = UltralightDump(commands: commands)
            return try await dumper.dumpAll(cardInfo: info, map: map)

        case .mifareDesfire:
            return try await dumpDESFire(info: info, transport: transport)

        case .type4:
            return try await dumpType4(info: info, transport: transport)

        case .felica:
            return try await dumpFeliCa(info: info, transport: transport)

        case .iso15693:
            return try await dumpISO15693(info: info, transport: transport)

        case .iso14443B where info.type == .myNumberCard:
            return try await dumpMyNumberCard(info: info, transport: transport)

        case .mifareClassic:
            throw NFCError.notOperableOnIOS(info.type)

        case .passport:
            throw NFCError.unsupportedOperation(
                "Use readPassport() for eMRTD chips; the generic dump flow does not enter BAC or secure messaging."
            )

        default:
            // No dump flow exists for this card type.
            throw NFCError.tagNotSupported
        }
    }

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

    /// Refine a coarse scan classification using family-specific probes.
    public static func refineCardInfo(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        let refined = try await CardInfoRefiner.refine(info, transport: transport)
        if refined.type != info.type {
            NFCLog.info("Refined \(info.type.description) → \(refined.type.description)", source: "Core")
        }
        return refined
    }

    // MARK: - Passport / eMRTD

    /// Read data groups from an electronic passport or ID card.
    ///
    /// Performs BAC authentication using the MRZ key, then reads and parses
    /// the requested data groups from the chip.
    ///
    /// - Parameters:
    ///   - mrzKey: The MRZ key string (use ``MRZKeyGenerator/computeMRZKey(documentNumber:dateOfBirth:dateOfExpiry:)``).
    ///   - dataGroups: Which data groups to read (default: COM, DG1, DG2, SOD).
    ///   - message: The alert message shown during NFC scanning.
    /// - Returns: A ``PassportModel`` with all parsed data.
    /// - Throws: ``NFCError``. When the user dismisses the NFC sheet or the calling task
    ///   is cancelled, the error's ``Swift/Error/isNFCCancellation`` is `true`; apps
    ///   usually stay silent then.
    public static func readPassport(
        mrzKey: String,
        dataGroups: [DataGroupId] = [.com, .dg1, .dg2, .sod],
        performActiveAuth: Bool = true,
        trustAnchorsDER: [Data] = [],
        message: String? = nil,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> PassportModel {
        let manager = NFCSessionManager()
        let (_, transport) = try await manager.scan(for: [.iso14443], message: message ?? String(localized: "Hold your iPhone near your passport", bundle: .module))

        do {
            let reader = PassportReader(transport: transport)
            let passport = try await reader.readPassport(
                mrzKey: mrzKey,
                dataGroups: dataGroups,
                performActiveAuth: performActiveAuth,
                trustAnchorsDER: trustAnchorsDER,
                onProgress: { msg in
                    manager.setAlertMessage(msg)
                    onProgress?(msg)
                }
            )
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return passport
        } catch {
            throw manager.invalidateAfterFailure(error)
        }
    }

    // MARK: - Private

    /// Dump a DESFire card: list apps, list files, read all accessible data.
    private static func dumpDESFire(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        try await DESFireDump(commands: DESFireCommands(transport: transport))
            .dumpAll(cardInfo: info)
    }

    private static func dumpType4(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        let reader = Type4Reader(transport: transport)
        let capabilityContainer = try await reader.readCapabilityContainer()
        let ndef = try await reader.readNDEF()

        let files: [MemoryDump.FileData] = [
            .init(
                identifier: Type4Constants.ccFileID,
                data: capabilityContainer.encoded,
                name: "Capability Container"
            ),
            .init(identifier: capabilityContainer.ndefFileID, data: capabilityContainer.encodeNDEFFile(ndef), name: "NDEF File"),
        ]

        return MemoryDump(
            cardInfo: info,
            files: files,
            ndefMessage: ndef,
            facts: [
                .init(key: "Mapping Version", value: String(format: "0x%02X", capabilityContainer.mappingVersion), monospaced: true),
                .init(key: "MLe", value: "\(capabilityContainer.mle) bytes"),
                .init(key: "MLc", value: "\(capabilityContainer.mlc) bytes"),
                .init(key: "NDEF File ID", value: capabilityContainer.ndefFileID.hexString, monospaced: true),
                .init(key: "NDEF Bytes", value: "\(ndef.count)"),
                .init(key: "Write Access", value: capabilityContainer.writeAccess == 0x00 ? "Writable" : "Read-only"),
            ],
            capabilities: capabilityContainer.writeAccess == 0x00 ? [.readable, .writable] : [.readable]
        )
    }

    private static func dumpMyNumberCard(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            throw NFCError.unsupportedOperation("My Number card reading requires an ISO 7816 transport")
        }

        let reader = MyNumberCardReader(transport: iso7816Transport)
        let tokenInfo = try await reader.readTokenInfo()
        let tokenData = Data(tokenInfo.utf8)

        return MemoryDump(
            cardInfo: info,
            files: [
                .init(
                    identifier: MyNumberCardConstants.jpkiTokenEFID,
                    data: tokenData,
                    name: "JPKI Token"
                ),
            ],
            facts: [
                .init(key: "JPKI Token", value: tokenInfo, monospaced: true),
                .init(key: "Protected Data", value: "Individual number requires the card-info-input-support PIN"),
            ],
            capabilities: [.readable, .authenticationRequired]
        )
    }

    private static func dumpFeliCa(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        guard let felicaTransport = transport as? any FeliCaTagTransporting else {
            throw NFCError.unsupportedOperation("FeliCa dump requires a FeliCa transport")
        }

        let reader = FeliCaType3Reader(transport: felicaTransport)
        let commands = FeliCaCommands(transport: felicaTransport)
        // Probing is best-effort, but a lost tag or ended session must fail the dump
        // instead of producing a smaller "successful" one.
        let serviceProbes: [FeliCaCommands.ServiceProbe]
        do {
            serviceProbes = try await commands.probeCommonServices()
        } catch where !isSessionTerminating(error) {
            serviceProbes = []
        }

        var blocks: [MemoryDump.Block] = []
        var facts: [MemoryDump.Fact] = [
            .init(key: "System Code", value: info.systemCode?.hexString ?? felicaTransport.systemCode.hexString, monospaced: true),
            .init(key: "Common Services", value: "\(serviceProbes.count)"),
            serviceProbes.isEmpty ? nil : .init(key: "Detected Services", value: summarizeFeliCaServices(serviceProbes)),
        ].compactMap(\.self)
        var capabilities: Set<CardCapability> = []
        var ndefMessage: Data?
        var ndefAttributeInfo: FeliCaAttributeInfo?

        if serviceProbes.contains(where: { $0.serviceCode == FeliCaType3Reader.readServiceCode }) {
            do {
                let attributeBlocks = try await felicaTransport.readWithoutEncryption(
                    serviceCode: FeliCaType3Reader.readServiceCode,
                    blockList: [FeliCaFrame.blockListElement(blockNumber: 0)]
                )
                guard let attributeBlock = attributeBlocks.first else {
                    throw NFCError.invalidResponse(Data())
                }

                let attributeInfo = try FeliCaAttributeInfo(data: attributeBlock)
                let ndef = try await reader.readNDEF()
                let totalDataBlocks = (Int(attributeInfo.ndefLength) + FeliCaMemory.blockSize - 1) / FeliCaMemory.blockSize
                blocks.append(.init(number: 0, data: attributeBlock))

                for index in 0 ..< totalDataBlocks {
                    let start = index * FeliCaMemory.blockSize
                    let end = min(start + FeliCaMemory.blockSize, ndef.count)
                    let chunk = start < end ? Data(ndef[start ..< end]) : Data()
                    blocks.append(.init(number: index + 1, data: chunk))
                }

                ndefAttributeInfo = attributeInfo
                ndefMessage = ndef
            } catch where !isSessionTerminating(error) {
                // Malformed or unreadable Type 3 area: keep the rest of the dump.
            }
        }

        try Task.checkCancellation()

        let extraServiceSnapshots = try await commands.readPlainServices(
            serviceProbes,
            maxBlocksPerService: 4,
            excluding: Set([FeliCaType3Reader.readServiceCode, FeliCaType3Reader.writeServiceCode])
        )
        try Task.checkCancellation()
        let files = extraServiceSnapshots.map { snapshot in
            MemoryDump.FileData(
                identifier: snapshot.serviceCode,
                data: snapshot.payload,
                name: "\(snapshot.label) (\(snapshot.blocks.count) blocks)"
            )
        }

        if let attributeInfo = ndefAttributeInfo {
            facts.append(contentsOf: [
                .init(key: "NDEF Bytes", value: "\(attributeInfo.ndefLength)"),
                .init(key: "Max Read Blocks", value: "\(attributeInfo.nbr)"),
                .init(key: "Max Write Blocks", value: "\(attributeInfo.nbw)"),
                .init(key: "Read / Write", value: attributeInfo.rwFlag == 0x01 ? "Read-write" : "Read-only"),
            ])
            capabilities.insert(.readable)
            if attributeInfo.rwFlag == 0x01 {
                capabilities.insert(.writable)
            }
        }

        if !extraServiceSnapshots.isEmpty {
            facts.append(.init(key: "Plain Service Snapshots", value: "\(extraServiceSnapshots.count)"))
            capabilities.insert(.readable)
        }

        return MemoryDump(
            cardInfo: info,
            blocks: blocks,
            files: files,
            ndefMessage: ndefMessage,
            facts: facts,
            capabilities: CardCapability.allCases.filter(capabilities.contains)
        )
    }

    private static func dumpISO15693(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
            throw NFCError.unsupportedOperation("ISO 15693 dump requires an ISO 15693 transport")
        }
        // Blocks above 255 are read with the extended commands; a tag that rejects
        // them is dumped up to block 255 and the truncation is recorded as a fact.
        return try await ISO15693Reader(transport: iso15693Transport).readAllBlocks(info: info)
    }

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

    private static func summarizeFeliCaServices(_ services: [FeliCaCommands.ServiceProbe]) -> String {
        let preview = services.prefix(4).map { "\($0.label) [\($0.serviceCode.hexString)]" }
        if services.count > 4 {
            return preview.joined(separator: ", ") + ", +\(services.count - 4) more"
        }
        return preview.joined(separator: ", ")
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
