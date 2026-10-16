import Foundation

/// High-level Type 4 tag operations.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class Type4Tag: @unchecked Sendable {
    public let transport: any NFCTagTransport
    public let reader: Type4Reader

    public init(transport: any NFCTagTransport) {
        self.transport = transport
        reader = Type4Reader(transport: transport)
    }

    /// Read NDEF message from a Type 4A/4B tag.
    open func readNDEF() async throws -> Data {
        try await reader.readNDEF()
    }

    /// Write NDEF message to a Type 4A/4B tag.
    open func writeNDEF(_ message: Data) async throws {
        try await reader.writeNDEF(message)
    }

    /// Read the Capability Container.
    open func readCC() async throws -> Type4CC {
        try await reader.readCapabilityContainer()
    }
}
