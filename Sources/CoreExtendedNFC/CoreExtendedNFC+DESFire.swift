import Foundation

// MARK: - DESFire Operations

public extension CoreExtendedNFC {
    // MARK: Card Info

    /// GET_VERSION: Returns hardware, software, and UID info for a DESFire chip.
    static func getDESFireVersion(
        transport: any NFCTagTransport
    ) async throws -> DESFireVersionInfo {
        try await DESFireCommands(transport: transport)
            .getVersion()
    }

    // MARK: Application Management

    /// GET_APPLICATION_IDS: List all application AIDs (3 bytes each) on the card.
    static func getDESFireApplicationIDs(
        transport: any NFCTagTransport
    ) async throws -> [Data] {
        try await DESFireCommands(transport: transport)
            .getApplicationIDs()
    }

    /// SELECT_APPLICATION: Select an application by its 3-byte AID.
    static func selectDESFireApplication(
        _ aid: Data,
        transport: any NFCTagTransport
    ) async throws {
        try await DESFireCommands(transport: transport)
            .selectApplication(aid)
    }

    /// GET_FILE_IDS: List file IDs in the currently selected application.
    static func getDESFireFileIDs(
        transport: any NFCTagTransport
    ) async throws -> [UInt8] {
        try await DESFireCommands(transport: transport)
            .getFileIDs()
    }

    /// GET_FILE_SETTINGS: Get settings (type, access rights, size) for a specific file.
    static func getDESFireFileSettings(
        _ fileID: UInt8,
        transport: any NFCTagTransport
    ) async throws -> DESFireFileSettings {
        try await DESFireCommands(transport: transport)
            .getFileSettings(fileID)
    }

    // MARK: Data Operations

    /// READ_DATA: Read data from a standard or backup data file.
    static func readDESFireData(
        fileID: UInt8,
        offset: UInt32 = 0,
        length: UInt32 = 0,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await DESFireCommands(transport: transport)
            .readData(fileID: fileID, offset: offset, length: length)
    }

    /// READ_RECORDS: Read records from a linear or cyclic record file.
    static func readDESFireRecords(
        fileID: UInt8,
        offset: UInt32 = 0,
        count: UInt32 = 0,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await DESFireCommands(transport: transport)
            .readRecords(fileID: fileID, offset: offset, count: count)
    }

    /// GET_VALUE: Read the signed 32-bit value from a value file.
    static func getDESFireValue(
        fileID: UInt8,
        transport: any NFCTagTransport
    ) async throws -> Int32 {
        try await DESFireCommands(transport: transport)
            .getValue(fileID: fileID)
    }

    /// Send a raw DESFire native command (with AF chaining handled automatically).
    static func sendDESFireCommand(
        _ command: UInt8,
        data: Data? = nil,
        transport: any NFCTagTransport
    ) async throws -> Data {
        try await DESFireCommands(transport: transport)
            .sendCommand(command, data: data)
    }

    // MARK: Authentication

    /// AuthenticateISO (0x1A): 2K3DES mutual authentication.
    static func authenticateDESFireISO(
        keyNo: UInt8,
        key: Data,
        transport: any NFCTagTransport
    ) async throws -> DESFireAuthenticationSession {
        try await DESFireCommands(transport: transport)
            .authenticateISO(keyNo: keyNo, key: key)
    }

    /// AuthenticateEV2First (0x71): AES-128 mutual authentication.
    static func authenticateDESFireEV2(
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6),
        transport: any NFCTagTransport
    ) async throws -> DESFireAuthenticationSession {
        try await DESFireCommands(transport: transport)
            .authenticateEV2First(keyNo: keyNo, key: key, pcdCapabilities: pcdCapabilities)
    }

    // MARK: Authenticated Read Convenience

    /// Authenticate with ISO scheme, then read a data file.
    static func readDESFireDataAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        length: UInt32 = 0,
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await DESFireCommands(transport: transport)
            .readDataAuthenticatedISO(
                fileID: fileID,
                keyNo: keyNo,
                key: key,
                offset: offset,
                length: length
            )
    }

    /// Authenticate with EV2 scheme, then read a data file.
    static func readDESFireDataAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        length: UInt32 = 0,
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6),
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await DESFireCommands(transport: transport)
            .readDataAuthenticatedEV2(
                fileID: fileID,
                keyNo: keyNo,
                key: key,
                offset: offset,
                length: length,
                pcdCapabilities: pcdCapabilities
            )
    }

    /// Authenticate with ISO scheme, then read a record file.
    static func readDESFireRecordsAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        count: UInt32 = 0,
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await DESFireCommands(transport: transport)
            .readRecordsAuthenticatedISO(
                fileID: fileID,
                keyNo: keyNo,
                key: key,
                offset: offset,
                count: count
            )
    }

    /// Authenticate with EV2 scheme, then read a record file.
    static func readDESFireRecordsAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        count: UInt32 = 0,
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6),
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await DESFireCommands(transport: transport)
            .readRecordsAuthenticatedEV2(
                fileID: fileID,
                keyNo: keyNo,
                key: key,
                offset: offset,
                count: count,
                pcdCapabilities: pcdCapabilities
            )
    }

    /// Authenticate with ISO scheme, then read a value file.
    static func getDESFireValueAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        try await DESFireCommands(transport: transport)
            .getValueAuthenticatedISO(fileID: fileID, keyNo: keyNo, key: key)
    }

    /// Authenticate with EV2 scheme, then read a value file.
    static func getDESFireValueAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6),
        transport: any NFCTagTransport
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        try await DESFireCommands(transport: transport)
            .getValueAuthenticatedEV2(
                fileID: fileID,
                keyNo: keyNo,
                key: key,
                pcdCapabilities: pcdCapabilities
            )
    }

    // MARK: Deprecated Names

    @available(*, deprecated, renamed: "getDESFireApplicationIDs(transport:)")
    static func getApplicationIDs(
        transport: any NFCTagTransport
    ) async throws -> [Data] {
        try await getDESFireApplicationIDs(transport: transport)
    }

    @available(*, deprecated, renamed: "selectDESFireApplication(_:transport:)")
    static func selectApplication(
        _ aid: Data,
        transport: any NFCTagTransport
    ) async throws {
        try await selectDESFireApplication(aid, transport: transport)
    }

    @available(*, deprecated, renamed: "getDESFireFileIDs(transport:)")
    static func getFileIDs(
        transport: any NFCTagTransport
    ) async throws -> [UInt8] {
        try await getDESFireFileIDs(transport: transport)
    }

    @available(*, deprecated, renamed: "getDESFireFileSettings(_:transport:)")
    static func getFileSettings(
        _ fileID: UInt8,
        transport: any NFCTagTransport
    ) async throws -> DESFireFileSettings {
        try await getDESFireFileSettings(fileID, transport: transport)
    }
}
