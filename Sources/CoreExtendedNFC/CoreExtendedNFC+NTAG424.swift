import Foundation

// MARK: - NTAG 424 DNA Operations

public extension CoreExtendedNFC {
    /// GetFileSettings (`F5h`): file type, communication mode, access rights, size
    /// and, when enabled, the Secure Dynamic Messaging settings of an NTAG 424 DNA file.
    ///
    /// Plain (unauthenticated) only; the NDEF application must be selected.
    static func getNTAG424FileSettings(
        fileID: UInt8,
        transport: any NFCTagTransport
    ) async throws -> NTAG424FileSettings {
        try await NTAG424Commands(transport: transport)
            .getFileSettings(fileID: fileID)
    }

    /// WriteData (`8Dh`) in CommMode.Plain to an NTAG 424 DNA file, split into
    /// commands of at most `chunkSize` data bytes.
    ///
    /// Only works for files whose communication mode is plain and whose write
    /// access is free (or granted without secure messaging).
    static func writeNTAG424DataPlain(
        fileID: UInt8,
        offset: UInt32 = 0,
        data: Data,
        chunkSize: Int = NTAG424Commands.defaultWriteChunkSize,
        transport: any NFCTagTransport
    ) async throws {
        try await NTAG424Commands(transport: transport)
            .writeDataPlain(fileID: fileID, offset: offset, data: data, chunkSize: chunkSize)
    }
}
