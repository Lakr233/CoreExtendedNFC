import Foundation

// MARK: - Ultralight / NTAG Operations

public extension CoreExtendedNFC {
    // MARK: Page-Level Read / Write

    /// Read 4 pages (16 bytes) starting from the given page number.
    static func readPages(
        startPage: UInt8,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await UltralightCommands(transport: transport)
            .readPages(startPage: startPage)
    }

    /// Write 4 bytes to a single page.
    ///
    /// Pages 0-2 (UID / static lock / OTP) and page 3 values other than a
    /// read/write NDEF CC are refused unless `allowIrreversible` is `true`; with a
    /// `memoryMap`, pages outside the user area are refused too. See
    /// ``UltralightCommands/writePage(_:data:memoryMap:allowIrreversible:)``.
    ///
    /// - Warning: Lock bytes, OTP bits and configuration pages are one-way:
    ///   `allowIrreversible: true` can permanently lock or brick the tag.
    static func writePage(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false,
        transport: any NFCTagTransport
    ) async throws {
        try await UltralightCommands(transport: transport)
            .writePage(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
    }

    /// FAST_READ: Read a contiguous range of pages in a single command.
    static func fastRead(
        from startPage: UInt8,
        to endPage: UInt8,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await UltralightCommands(transport: transport)
            .fastRead(from: startPage, to: endPage)
    }

    /// Compatibility write (16-byte frame for legacy readers).
    ///
    /// Pages 0-2 (UID / static lock / OTP) and page 3 values other than a
    /// read/write NDEF CC are refused unless `allowIrreversible` is `true`; with a
    /// `memoryMap`, pages outside the user area are refused too. See
    /// ``UltralightCommands/compatibilityWrite(_:data:memoryMap:allowIrreversible:)``.
    ///
    /// - Warning: Lock bytes, OTP bits and configuration pages are one-way:
    ///   `allowIrreversible: true` can permanently lock or brick the tag.
    static func compatibilityWrite(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false,
        transport: any NFCTagTransport
    ) async throws {
        try await UltralightCommands(transport: transport)
            .compatibilityWrite(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
    }

    // MARK: Version & Identity

    /// GET_VERSION (0x60): Identify the exact Ultralight/NTAG chip variant.
    static func getUltralightVersion(
        transport: any NFCTagTransport
    ) async throws -> UltralightVersionResponse {
        try await UltralightCommands(transport: transport)
            .getVersion()
    }

    // MARK: NTAG-Specific

    /// READ_SIG (0x3C): Read the 32-byte NXP ECC signature for chip authenticity verification.
    static func readSignature(
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await UltralightCommands(transport: transport)
            .readSignature()
    }

    /// READ_CNT (0x39): Read the NFC single-shot counter value.
    static func readCounter(
        counterID: UInt8 = 0x02,
        transport: any NFCTagTransport
    ) async throws -> UInt32 {
        try await UltralightCommands(transport: transport)
            .readCounter(counterID: counterID)
    }

    // MARK: Authentication

    /// PWD_AUTH (0x1B): Authenticate with a 4-byte password.
    /// Returns the 2-byte PACK (Password Acknowledgment).
    /// Supported on Ultralight EV1 and NTAG.
    static func passwordAuth(
        password: Data,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await UltralightCommands(transport: transport)
            .passwordAuth(password: password)
    }

    /// AUTHENTICATE (0x1A): MIFARE Ultralight C 2K3DES mutual authentication.
    static func authenticateUltralightC(
        key: Data,
        transport: any NFCTagTransport
    ) async throws -> UltralightCAuthenticationSession {
        try await UltralightCommands(transport: transport)
            .authenticateUltralightC(key: key)
    }

    /// Read AUTH0 and ACCESS config pages to determine password-protection range.
    static func readAuthConfig(
        configStartPage: UInt8,
        transport: any NFCTagTransport
    ) async throws -> (auth0Page: UInt8, accessBits: UInt8) {
        try await UltralightCommands(transport: transport)
            .readAuthConfig(configStartPage: configStartPage)
    }

    /// Read Ultralight C access configuration (AUTH0 / AUTH1 from pages 42–43).
    static func readUltralightCAccessConfiguration(
        transport: any NFCTagTransport
    ) async throws -> UltralightCAccessConfiguration {
        try await UltralightCommands(transport: transport)
            .readUltralightCAccessConfiguration()
    }

    // MARK: Dump & Restore

    /// Restore user pages from a previous ``MemoryDump`` to an Ultralight/NTAG tag.
    static func restoreUltralight(
        dump: MemoryDump,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let commands = UltralightCommands(transport: transport)
        let map = UltralightMemoryMap.forType(info.type)
        let dumper = UltralightDump(commands: commands)
        try await dumper.restore(dump: dump, map: map)
    }
}
