import Foundation

// MARK: - FeliCa Operations

public extension CoreExtendedNFC {
    // MARK: Service Discovery

    /// Probe common FeliCa service codes to discover available services.
    static func probeFeliCaServices(
        maxServiceIndex: Int = 15,
        transport: any NFCTagTransport
    ) async throws -> [FeliCaCommands.ServiceProbe] {
        try await FeliCaCommands(transport: felicaTransport(transport))
            .probeCommonServices(maxServiceIndex: maxServiceIndex)
    }

    /// Read data from discovered plain (non-encrypted) services.
    static func readFeliCaPlainServices(
        _ services: [FeliCaCommands.ServiceProbe],
        maxBlocksPerService: Int = 4,
        excluding excludedServiceCodes: Set<Data> = [],
        transport: any NFCTagTransport
    ) async throws -> [FeliCaCommands.ServiceSnapshot] {
        try await FeliCaCommands(transport: felicaTransport(transport))
            .readPlainServices(
                services,
                maxBlocksPerService: maxBlocksPerService,
                excluding: excludedServiceCodes
            )
    }

    // MARK: Block-Level Operations

    /// Read contiguous blocks from a FeliCa Type 3 tag.
    static func readFeliCaBlocks(
        from startBlock: Int,
        count: Int,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await FeliCaType3Reader(transport: felicaTransport(transport))
            .readBlocks(from: startBlock, count: count, maxPerRead: 4)
    }

    /// Write blocks to a FeliCa Type 3 tag.
    ///
    /// FeliCa Lite and Lite-S accept one block per Write Without Encryption
    /// (Sony FeliCa Lite-S User's Manual, Write Without Encryption: Number of
    /// Blocks = 1), so blocks are written one per command by default. Pass a larger
    /// `maxBlocksPerWrite` only for a card known to accept more, such as one whose
    /// Type 3 attribute block announces a larger Nbw.
    static func writeFeliCaBlocks(
        startingAt startBlock: Int,
        blocks: [Data],
        maxBlocksPerWrite: Int = 1,
        transport: any NFCTagTransport
    ) async throws {
        try await FeliCaType3Reader(transport: felicaTransport(transport))
            .writeBlocks(startingAt: startBlock, blocks: blocks, maxPerWrite: maxBlocksPerWrite)
    }

    // MARK: Type 3 NDEF Attribute

    /// Read the FeliCa Type 3 attribute information block.
    static func readFeliCaAttributeInfo(
        transport: any NFCTagTransport
    ) async throws -> FeliCaAttributeInfo {
        try await FeliCaType3Reader(transport: felicaTransport(transport))
            .readAttributeInfo()
    }

    static func felicaTransport(_ transport: any NFCTagTransport) throws -> any FeliCaTagTransporting {
        guard let felicaTransport = transport as? any FeliCaTagTransporting else {
            throw NFCError.unsupportedOperation("FeliCa operations require a FeliCa transport")
        }
        return felicaTransport
    }
}
