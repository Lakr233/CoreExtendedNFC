import Foundation

/// Deprecated ISO 15693 dump and write entry points that take an explicit transport,
/// and block-addressing constants. The dump itself lives on ``ISO15693Reader``.
public extension ISO15693Reader {
    /// Read the tag through `transport` instead of this reader's own transport.
    @available(*, deprecated, message: "Use readAllBlocks(info:), which reads through the reader's transport")
    func readAllBlocks(transport: any ISO15693TagTransporting) async throws -> MemoryDump {
        try await ISO15693Reader(transport: transport).readAllBlocks()
    }

    /// Write a single block through `transport`.
    @available(*, deprecated, message: "Use writeBlock(at:data:), which writes through the reader's transport")
    func writeBlock(_ number: UInt8, data: Data, transport: any ISO15693TagTransporting) async throws {
        try await transport.writeBlock(number, data: data)
    }

    /// Highest block count reachable with READ / WRITE SINGLE BLOCK, whose block
    /// number is one byte (ISO/IEC 15693-3 §10.4.1).
    static let singleByteAddressableBlocks = 256
}
