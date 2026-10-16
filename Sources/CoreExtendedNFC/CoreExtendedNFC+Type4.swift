import Foundation

// MARK: - Type 4 Tag Operations

public extension CoreExtendedNFC {
    /// Read the Capability Container from a Type 4 tag.
    static func readType4CapabilityContainer(
        transport: any NFCTagTransport
    ) async throws -> Type4CC {
        try await Type4Reader(transport: transport).readCapabilityContainer()
    }

    /// Read raw NDEF data from a Type 4 tag.
    static func readType4NDEF(
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await Type4Reader(transport: transport).readNDEF()
    }

    /// Write raw NDEF data to a Type 4 tag.
    static func writeType4NDEF(
        _ message: Data,
        transport: any NFCTagTransport
    ) async throws {
        try await Type4Reader(transport: transport).writeNDEF(message)
    }

    // MARK: Deprecated Names

    @available(*, deprecated, renamed: "readType4CapabilityContainer(transport:)")
    static func readType4CC(
        transport: any NFCTagTransport
    ) async throws -> Type4CC {
        try await readType4CapabilityContainer(transport: transport)
    }
}
