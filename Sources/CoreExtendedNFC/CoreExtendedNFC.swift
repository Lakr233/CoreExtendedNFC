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
    public static func scan(
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport, NFCSessionManager) {
        let manager = NFCSessionManager()
        let (info, transport) = try await manager.scan(message: message ?? String(localized: "Hold your iPhone near the NFC tag", bundle: .module))

        let refinedInfo = try await refineCardInfo(info, transport: transport)
        manager.setAlertMessage("\(refinedInfo.type.description)")
        return (refinedInfo, transport, manager)
    }

    /// Scan and automatically dump the card's full memory.
    public static func scanAndDump(
        message: String? = nil
    ) async throws -> (CardInfo, MemoryDump) {
        let (info, transport, manager) = try await scan(message: message ?? String(localized: "Hold your iPhone near the NFC tag", bundle: .module))

        // Non-operable cards (Classic, etc.) — return identification only
        guard info.type.isOperableOnIOS else {
            manager.setAlertMessage("\(info.type.description)")
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
            manager.invalidate(errorMessage: error.localizedDescription)
            throw error
        }
    }

    /// Dump a card's memory using an already-connected transport.
    public static func dumpCard(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
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

        case .mifareClassic:
            throw NFCError.notOperableOnIOS(info.type)

        case .passport:
            throw NFCError.unsupportedOperation(
                "Use readPassport() for eMRTD chips; the generic dump flow does not enter BAC or secure messaging."
            )

        default:
            throw NFCError.unsupportedOperation(
                "Automatic dump not yet supported for \(info.type.description)"
            )
        }
    }

    /// Read and parse an NDEF message using the best available family-specific path.
    public static func readNDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> NDEFMessage {
        switch info.type.family {
        case .type4:
            let payload = try await Type4Tag(transport: transport).readNDEF()
            return try NDEFMessage(data: payload)
        case .felica:
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa NDEF reading requires a FeliCa transport")
            }
            let payload = try await FeliCaType3Reader(transport: felicaTransport).readNDEF()
            return try NDEFMessage(data: payload)
        case .ntag, .mifareUltralight, .iso15693:
            let dump = try await dumpCard(info: info, transport: transport)
            guard let parsed = dump.parsedNDEFMessage else {
                throw NFCError.unsupportedOperation("No NDEF message detected for \(info.type.description)")
            }
            return parsed
        case .passport, .mifareDesfire:
            // Multi-application cards (e.g. ePassport chips that also carry NDEF)
            // sit on ISO 7816 transport, so try the Type 4 NDEF path as a fallback.
            let payload = try await Type4Tag(transport: transport).readNDEF()
            return try NDEFMessage(data: payload)
        default:
            throw NFCError.unsupportedOperation("Unified NDEF reading is not supported for \(info.type.description)")
        }
    }

    /// Write an NDEF message using the best available family-specific path.
    public static func writeNDEF(
        _ message: NDEFMessage,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        switch info.type.family {
        case .type4:
            try await Type4Tag(transport: transport).writeNDEF(message.data)
        case .felica:
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa NDEF writing requires a FeliCa transport")
            }
            try await FeliCaType3Reader(transport: felicaTransport).writeNDEF(message.data)
        case .ntag, .mifareUltralight:
            try await writeType2NDEF(message.data, info: info, transport: transport)
        case .iso15693:
            guard let iso15693Transport = transport as? any ISO15693TagTransporting else {
                throw NFCError.unsupportedOperation("ISO 15693 NDEF writing requires an ISO 15693 transport")
            }
            try await writeType5NDEF(message.data, transport: iso15693Transport)
        case .passport, .mifareDesfire:
            try await Type4Tag(transport: transport).writeNDEF(message.data)
        default:
            throw NFCError.unsupportedOperation("Unified NDEF writing is not yet supported for \(info.type.description)")
        }
    }

    /// Format a blank tag for NDEF use by writing the Capability Container
    /// and an empty NDEF message area.
    ///
    /// Supported families:
    /// - Type 2 (Ultralight/NTAG): writes CC to page 3 and clears user pages.
    /// - Type 5 (ISO 15693): delegates to the existing write path which creates CC.
    /// - Type 4 and Type 3: CC is managed by tag firmware and cannot be formatted via commands.
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
            try await writeType5NDEF(Data(), transport: iso15693Transport)
        default:
            throw NFCError.unsupportedOperation(
                "NDEF formatting is not supported for \(info.type.description)"
            )
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
            manager.invalidate(errorMessage: error.localizedDescription)
            throw error
        }
    }

    // MARK: - Private

    /// Dump a DESFire card: list apps, list files, read all accessible data.
    private static func dumpDESFire(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        let commands = DESFireCommands(transport: transport)
        var files: [MemoryDump.FileData] = []

        let aids = try await commands.getApplicationIDs()
        for aid in aids {
            try await commands.selectApplication(aid)
            let fileIDs = try await commands.getFileIDs()

            for fileID in fileIDs {
                do {
                    let settings = try await commands.getFileSettings(fileID)
                    let data: Data
                    switch settings.fileType {
                    case .standardData, .backupData:
                        data = try await commands.readData(fileID: fileID)
                    case .linearRecord, .cyclicRecord:
                        data = try await commands.readRecords(fileID: fileID)
                    case .valueFile:
                        let value = try await commands.getValue(fileID: fileID)
                        var valueData = Data(count: 4)
                        valueData[0] = UInt8(truncatingIfNeeded: value)
                        valueData[1] = UInt8(truncatingIfNeeded: value >> 8)
                        valueData[2] = UInt8(truncatingIfNeeded: value >> 16)
                        valueData[3] = UInt8(truncatingIfNeeded: value >> 24)
                        data = valueData
                    }
                    files.append(MemoryDump.FileData(fileID: fileID, data: data))
                } catch let error as NFCError {
                    // Only skip auth/permission errors — re-throw transport failures
                    switch error {
                    case .desfireError(.authenticationError),
                         .desfireError(.permissionDenied),
                         .desfireError(.noSuchKey):
                        continue
                    default:
                        throw error
                    }
                }
            }
        }

        return MemoryDump(
            cardInfo: info,
            files: files,
            facts: [
                .init(key: "Applications", value: "\(aids.count)"),
                .init(key: "Accessible Files", value: "\(files.count)"),
            ],
            capabilities: files.isEmpty ? [.authenticationRequired, .partiallyReadable] : [.partiallyReadable]
        )
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
                data: encodeType4CC(capabilityContainer),
                name: "Capability Container"
            ),
            .init(identifier: capabilityContainer.ndefFileID, data: encodeType4NDEFFile(ndef), name: "NDEF File"),
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

    private static func dumpFeliCa(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        guard let felicaTransport = transport as? any FeliCaTagTransporting else {
            throw NFCError.unsupportedOperation("FeliCa dump requires a FeliCa transport")
        }

        let reader = FeliCaType3Reader(transport: felicaTransport)
        let commands = FeliCaCommands(transport: felicaTransport)
        let serviceProbes = await (try? commands.probeCommonServices()) ?? []

        var blocks: [MemoryDump.Block] = []
        var files: [MemoryDump.FileData] = []
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
                let totalDataBlocks = Int((attributeInfo.ndefLength + 15) / 16)
                blocks.append(.init(number: 0, data: attributeBlock))

                for index in 0 ..< totalDataBlocks {
                    let start = index * FeliCaMemory.blockSize
                    let end = min(start + FeliCaMemory.blockSize, ndef.count)
                    let chunk = start < end ? Data(ndef[start ..< end]) : Data()
                    blocks.append(.init(number: index + 1, data: chunk))
                }

                ndefAttributeInfo = attributeInfo
                ndefMessage = ndef
            } catch {}
        }

        let extraServiceSnapshots = await commands.readPlainServices(
            serviceProbes,
            maxBlocksPerService: 4,
            excluding: Set([FeliCaType3Reader.readServiceCode, FeliCaType3Reader.writeServiceCode])
        )
        files = extraServiceSnapshots.map { snapshot in
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

        let systemInfo = try await iso15693Transport.getSystemInfo()
        let lockStatuses: [Bool]
        do {
            lockStatuses = try await iso15693Transport.getBlockSecurityStatus(
                range: NSRange(location: 0, length: systemInfo.blockCount)
            )
        } catch {
            lockStatuses = Array(repeating: false, count: systemInfo.blockCount)
        }

        var blocks: [MemoryDump.Block] = []
        for blockNumber in 0 ..< systemInfo.blockCount {
            guard let blockIndex = UInt8(exactly: blockNumber) else {
                throw NFCError.unsupportedOperation("ISO 15693 dump currently supports up to 256 blocks per session")
            }
            let data = try await iso15693Transport.readBlock(blockIndex)
            let payload = Data(data.prefix(systemInfo.blockSize))
            blocks.append(
                .init(
                    number: blockNumber,
                    data: payload,
                    locked: lockStatuses.indices.contains(blockNumber) ? lockStatuses[blockNumber] : false
                )
            )
        }

        let ndefMessage = NDEFTagMapping.extractType5Message(from: blocks)

        return MemoryDump(
            cardInfo: info,
            blocks: blocks,
            ndefMessage: ndefMessage,
            facts: [
                .init(key: "Block Size", value: "\(systemInfo.blockSize) bytes"),
                .init(key: "Blocks", value: "\(systemInfo.blockCount)"),
                .init(key: "DSFID", value: String(format: "0x%02X", systemInfo.dsfid), monospaced: true),
                .init(key: "AFI", value: String(format: "0x%02X", systemInfo.afi), monospaced: true),
                .init(key: "IC Reference", value: String(format: "0x%02X", systemInfo.icReference), monospaced: true),
                ndefMessage.map { .init(key: "NDEF Bytes", value: "\($0.count)") },
            ].compactMap(\.self),
            capabilities: [.readable]
        )
    }

    private static func encodeType4CC(_ cc: Type4CC) -> Data {
        var data = Data([
            UInt8((cc.ccLen >> 8) & 0xFF),
            UInt8(cc.ccLen & 0xFF),
            cc.mappingVersion,
            UInt8((cc.mle >> 8) & 0xFF),
            UInt8(cc.mle & 0xFF),
            UInt8((cc.mlc >> 8) & 0xFF),
            UInt8(cc.mlc & 0xFF),
            0x04,
            0x06,
        ])
        data.append(cc.ndefFileID)
        data.append(contentsOf: [
            UInt8((cc.ndefMaxSize >> 8) & 0xFF),
            UInt8(cc.ndefMaxSize & 0xFF),
            cc.readAccess,
            cc.writeAccess,
        ])
        return data
    }

    private static func encodeType4NDEFFile(_ ndef: Data) -> Data {
        var data = Data([
            UInt8((ndef.count >> 8) & 0xFF),
            UInt8(ndef.count & 0xFF),
        ])
        data.append(ndef)
        return data
    }

    private static func summarizeFeliCaServices(_ services: [FeliCaCommands.ServiceProbe]) -> String {
        let preview = services.prefix(4).map { "\($0.label) [\($0.serviceCode.hexString)]" }
        if services.count > 4 {
            return preview.joined(separator: ", ") + ", +\(services.count - 4) more"
        }
        return preview.joined(separator: ", ")
    }

    private static func writeType2NDEF(
        _ message: Data,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let memory = UltralightMemoryMap.forType(info.type)
        let capacity = Int(memory.userDataEnd - memory.userDataStart + 1) * 4
        let bytes = try NDEFTagMapping.buildType2Area(message: message, capacity: capacity)
        let commands = UltralightCommands(transport: transport)

        for (index, offset) in stride(from: 0, to: bytes.count, by: 4).enumerated() {
            let page = memory.userDataStart + UInt8(index)
            let chunk = Data(bytes[offset ..< min(offset + 4, bytes.count)])
            try await commands.writePage(page, data: chunk)
        }
    }

    private static func formatType2NDEF(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let memory = UltralightMemoryMap.forType(info.type)
        let commands = UltralightCommands(transport: transport)

        // Clear user data pages first, then write CC last.
        // If a write fails mid-way, the tag has no valid CC and won't be
        // recognised as NDEF-formatted — safer than leaving a CC pointing
        // at garbage data.
        let capacity = Int(memory.userDataEnd - memory.userDataStart + 1) * 4
        let bytes = try NDEFTagMapping.buildType2Area(message: Data(), capacity: capacity)

        for (index, offset) in stride(from: 0, to: bytes.count, by: 4).enumerated() {
            let page = memory.userDataStart + UInt8(index)
            let chunk = Data(bytes[offset ..< min(offset + 4, bytes.count)])
            try await commands.writePage(page, data: chunk)
        }

        // Write Capability Container to page 3 as the final step
        let cc = NDEFTagMapping.buildType2CC(memoryMap: memory)
        try await commands.writePage(3, data: cc)
    }

    private static func writeType5NDEF(
        _ message: Data,
        transport: any ISO15693TagTransporting
    ) async throws {
        let systemInfo = try await transport.getSystemInfo()
        let blocks = try NDEFTagMapping.buildType5Blocks(
            message: message,
            blockSize: systemInfo.blockSize,
            blockCount: systemInfo.blockCount
        )

        for (index, block) in blocks.enumerated() {
            try await transport.writeBlock(UInt8(index), data: block)
        }
    }
}
