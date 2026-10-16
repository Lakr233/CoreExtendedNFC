import Foundation

// MARK: - Memory Dump

public extension CoreExtendedNFC {
    /// Dump a card's memory using an already-connected transport.
    static func dumpCard(
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

    /// Dump a DESFire card: list apps, list files, read all accessible data.
    static func dumpDESFire(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> MemoryDump {
        try await DESFireDump(commands: DESFireCommands(transport: transport))
            .dumpAll(cardInfo: info)
    }

    static func dumpType4(
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

    static func dumpMyNumberCard(
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

    static func dumpFeliCa(
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

    static func dumpISO15693(
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

    static func summarizeFeliCaServices(_ services: [FeliCaCommands.ServiceProbe]) -> String {
        let preview = services.prefix(4).map { "\($0.label) [\($0.serviceCode.hexString)]" }
        if services.count > 4 {
            return preview.joined(separator: ", ") + ", +\(services.count - 4) more"
        }
        return preview.joined(separator: ", ")
    }
}
