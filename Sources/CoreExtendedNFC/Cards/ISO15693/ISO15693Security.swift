import Foundation

/// Normalized response payload for ISO 15693 security operations.
public struct ISO15693SecurityResponse: Sendable, Equatable {
    /// Raw ISO 15693 response flag bits returned by CoreNFC.
    public let responseFlags: Int
    /// Response payload bytes returned by the tag.
    public let data: Data

    public init(responseFlags: Int, data: Data) {
        self.responseFlags = responseFlags
        self.data = data
    }
}

/// High-level ISO 15693 security and configuration operations.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class ISO15693SecurityManager: @unchecked Sendable {
    public let transport: any ISO15693TagTransporting

    public init(transport: any ISO15693TagTransporting) {
        self.transport = transport
    }

    /// Update the AFI and, only when `permanentlyLock` is `true`, lock it.
    ///
    /// - Warning: `permanentlyLock: true` sends LOCK AFI (ISO/IEC 15693-3 §10.4.7),
    ///   which is irreversible: the AFI can never be changed again on that tag.
    open func configureAFI(_ afi: UInt8, permanentlyLock: Bool = false) async throws {
        try await transport.writeAFI(afi)
        if permanentlyLock {
            try await transport.lockAFI()
        }
    }

    /// Update the AFI and optionally lock it.
    @available(
        *,
        deprecated,
        renamed: "configureAFI(_:permanentlyLock:)",
        message: "Locking is irreversible; use `permanentlyLock:` to opt in explicitly"
    )
    open func configureAFI(_ afi: UInt8, lock: Bool) async throws {
        try await configureAFI(afi, permanentlyLock: lock)
    }

    /// Update the DSFID and, only when `permanentlyLock` is `true`, lock it.
    ///
    /// - Warning: `permanentlyLock: true` sends LOCK DSFID (ISO/IEC 15693-3 §10.4.9),
    ///   which is irreversible: the DSFID can never be changed again on that tag.
    open func configureDSFID(_ dsfid: UInt8, permanentlyLock: Bool = false) async throws {
        try await transport.writeDSFID(dsfid)
        if permanentlyLock {
            try await transport.lockDSFID()
        }
    }

    /// Update the DSFID and optionally lock it.
    @available(
        *,
        deprecated,
        renamed: "configureDSFID(_:permanentlyLock:)",
        message: "Locking is irreversible; use `permanentlyLock:` to opt in explicitly"
    )
    open func configureDSFID(_ dsfid: UInt8, lock: Bool) async throws {
        try await configureDSFID(dsfid, permanentlyLock: lock)
    }

    /// Send a manufacturer-specific custom command.
    open func customCommand(code: Int, parameters: Data = Data()) async throws -> Data {
        try await transport.customCommand(code: code, parameters: parameters)
    }

    /// Start or continue a challenge flow for the selected crypto suite.
    open func challenge(
        cryptoSuiteIdentifier: Int,
        message: Data = Data()
    ) async throws {
        try await transport.challenge(
            cryptoSuiteIdentifier: cryptoSuiteIdentifier,
            message: message
        )
    }

    /// Authenticate using the selected ISO 15693 crypto suite.
    open func authenticate(
        cryptoSuiteIdentifier: Int,
        message: Data
    ) async throws -> ISO15693SecurityResponse {
        try await transport.authenticate(
            cryptoSuiteIdentifier: cryptoSuiteIdentifier,
            message: message
        )
    }

    /// Update a security key on tags that support the ISO 15693 key update primitive.
    open func keyUpdate(
        keyIdentifier: Int,
        message: Data
    ) async throws -> ISO15693SecurityResponse {
        try await transport.keyUpdate(
            keyIdentifier: keyIdentifier,
            message: message
        )
    }
}
