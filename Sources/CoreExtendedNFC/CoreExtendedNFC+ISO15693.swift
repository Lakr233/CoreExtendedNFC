import Foundation

// MARK: - ISO 15693 Operations

public extension CoreExtendedNFC {
    // MARK: Block Operations

    /// Read a single block from an ISO 15693 tag.
    static func readISO15693Block(
        _ blockNumber: UInt8,
        transport: any NFCTagTransport
    ) async throws -> Data {
        let iso = try iso15693Transport(from: transport)
        return try await iso.readBlock(blockNumber)
    }

    /// Write a single block to an ISO 15693 tag.
    static func writeISO15693Block(
        _ blockNumber: UInt8,
        data: Data,
        transport: any NFCTagTransport
    ) async throws {
        let iso = try iso15693Transport(from: transport)
        try await iso.writeBlock(blockNumber, data: data)
    }

    /// Read multiple contiguous blocks from an ISO 15693 tag.
    static func readISO15693Blocks(
        range: NSRange,
        transport: any NFCTagTransport
    ) async throws -> [Data] {
        let iso = try iso15693Transport(from: transport)
        return try await iso.readBlocks(range: range)
    }

    /// Get system information (block count, block size, DSFID, AFI, IC reference).
    static func getISO15693SystemInfo(
        transport: any NFCTagTransport
    ) async throws -> ISO15693SystemInfo {
        let iso = try iso15693Transport(from: transport)
        return try await iso.getSystemInfo()
    }

    /// Get lock status for a range of blocks.
    static func getISO15693BlockSecurityStatus(
        range: NSRange,
        transport: any NFCTagTransport
    ) async throws -> [Bool] {
        let iso = try iso15693Transport(from: transport)
        return try await iso.getBlockSecurityStatus(range: range)
    }

    // MARK: Configuration

    /// Update the AFI and, only when `permanentlyLock` is `true`, lock it.
    ///
    /// - Warning: `permanentlyLock: true` sends LOCK AFI (ISO/IEC 15693-3 §10.4.7),
    ///   which is irreversible: the AFI can never be changed again on that tag.
    static func configureISO15693AFI(
        _ afi: UInt8,
        permanentlyLock: Bool = false,
        transport: any NFCTagTransport
    ) async throws {
        let iso = try iso15693Transport(from: transport)
        try await iso.writeAFI(afi)
        if permanentlyLock {
            try await iso.lockAFI()
        }
    }

    /// Update the AFI and optionally lock it.
    @available(
        *,
        deprecated,
        renamed: "configureISO15693AFI(_:permanentlyLock:transport:)",
        message: "Locking is irreversible; use `permanentlyLock:` to opt in explicitly"
    )
    static func configureISO15693AFI(
        _ afi: UInt8,
        lock: Bool,
        transport: any NFCTagTransport
    ) async throws {
        try await configureISO15693AFI(afi, permanentlyLock: lock, transport: transport)
    }

    /// Update the DSFID and, only when `permanentlyLock` is `true`, lock it.
    ///
    /// - Warning: `permanentlyLock: true` sends LOCK DSFID (ISO/IEC 15693-3 §10.4.9),
    ///   which is irreversible: the DSFID can never be changed again on that tag.
    static func configureISO15693DSFID(
        _ dsfid: UInt8,
        permanentlyLock: Bool = false,
        transport: any NFCTagTransport
    ) async throws {
        let iso = try iso15693Transport(from: transport)
        try await iso.writeDSFID(dsfid)
        if permanentlyLock {
            try await iso.lockDSFID()
        }
    }

    /// Update the DSFID and optionally lock it.
    @available(
        *,
        deprecated,
        renamed: "configureISO15693DSFID(_:permanentlyLock:transport:)",
        message: "Locking is irreversible; use `permanentlyLock:` to opt in explicitly"
    )
    static func configureISO15693DSFID(
        _ dsfid: UInt8,
        lock: Bool,
        transport: any NFCTagTransport
    ) async throws {
        try await configureISO15693DSFID(dsfid, permanentlyLock: lock, transport: transport)
    }

    // MARK: Security

    /// Send a manufacturer-specific custom command.
    static func iso15693CustomCommand(
        code: Int,
        parameters: Data = Data(),
        transport: any NFCTagTransport
    ) async throws -> Data {
        let iso = try iso15693Transport(from: transport)
        let manager = ISO15693SecurityManager(transport: iso)
        return try await manager.customCommand(code: code, parameters: parameters)
    }

    /// Start or continue a challenge flow for the selected crypto suite.
    static func iso15693Challenge(
        cryptoSuiteIdentifier: Int,
        message: Data = Data(),
        transport: any NFCTagTransport
    ) async throws {
        let iso = try iso15693Transport(from: transport)
        let manager = ISO15693SecurityManager(transport: iso)
        try await manager.challenge(
            cryptoSuiteIdentifier: cryptoSuiteIdentifier,
            message: message
        )
    }

    /// Authenticate using the selected ISO 15693 crypto suite.
    static func iso15693Authenticate(
        cryptoSuiteIdentifier: Int,
        message: Data,
        transport: any NFCTagTransport
    ) async throws -> ISO15693SecurityResponse {
        let iso = try iso15693Transport(from: transport)
        let manager = ISO15693SecurityManager(transport: iso)
        return try await manager.authenticate(
            cryptoSuiteIdentifier: cryptoSuiteIdentifier,
            message: message
        )
    }

    /// Update a security key on tags that support the ISO 15693 key update primitive.
    static func iso15693KeyUpdate(
        keyIdentifier: Int,
        message: Data,
        transport: any NFCTagTransport
    ) async throws -> ISO15693SecurityResponse {
        let iso = try iso15693Transport(from: transport)
        let manager = ISO15693SecurityManager(transport: iso)
        return try await manager.keyUpdate(
            keyIdentifier: keyIdentifier,
            message: message
        )
    }

    // MARK: Helpers

    static func iso15693Transport(
        from transport: any NFCTagTransport
    ) throws -> any ISO15693TagTransporting {
        guard let iso = transport as? any ISO15693TagTransporting else {
            throw NFCError.unsupportedOperation("ISO 15693 operations require an ISO 15693 transport")
        }
        return iso
    }
}
