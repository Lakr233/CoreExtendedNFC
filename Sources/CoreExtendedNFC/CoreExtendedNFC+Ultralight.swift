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

    /// Last page that is user memory on every Ultralight / NTAG product
    /// (MF0ICU1 and MF0UL11 / NTAG210 user area 04h-0Fh). Above it a page may be
    /// a lock, configuration, password or key page depending on the product.
    internal static let ultralightCommonUserDataEnd: UInt8 = 0x0F

    /// Write 4 bytes to a single page.
    ///
    /// Without `allowIrreversible: true` these writes are refused with
    /// ``NFCError/irreversibleWriteRefused(page:)``:
    /// - pages 0-2 (UID and static lock bytes);
    /// - page 3 (OTP), unless the write would leave it unchanged;
    /// - with a `memoryMap`, every page outside the product's user data area;
    /// - without a `memoryMap`, every page above 15 (0Fh), because the lock,
    ///   configuration, PWD/PACK and key pages start right after the user area
    ///   on the smallest products. Pass ``UltralightMemoryMap/forType(_:)`` to
    ///   write the user area of larger tags.
    ///
    /// See ``UltralightCommands/writePage(_:data:memoryMap:allowIrreversible:)``.
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
        try requireKnownPage(page, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
        try await UltralightCommands(transport: transport)
            .writePage(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
    }

    /// Without a memory map, a page above the smallest product's user area may be
    /// a configuration, password or key page, so it needs the opt-in.
    private static func requireKnownPage(
        _ page: UInt8,
        memoryMap: UltralightMemoryMap?,
        allowIrreversible: Bool
    ) throws {
        guard !allowIrreversible, memoryMap == nil, page > ultralightCommonUserDataEnd else { return }
        throw NFCError.irreversibleWriteRefused(page: page)
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
    /// The same pages are refused as for
    /// ``writePage(_:data:memoryMap:allowIrreversible:transport:)``, including
    /// every page above 15 when no `memoryMap` is given. See
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
        try requireKnownPage(page, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
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
    ///
    /// The dump must come from the same product as `info` and every user page
    /// must hold 4 bytes; otherwise ``NFCError/invalidParameter(_:)`` is thrown
    /// before anything is written. See ``UltralightDump/restore(dump:map:target:)``.
    static func restoreUltralight(
        dump: MemoryDump,
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws {
        let commands = UltralightCommands(transport: transport)
        let map = UltralightMemoryMap.forType(info.type)
        let dumper = UltralightDump(commands: commands)
        try await dumper.restore(dump: dump, map: map, target: info)
    }
}
