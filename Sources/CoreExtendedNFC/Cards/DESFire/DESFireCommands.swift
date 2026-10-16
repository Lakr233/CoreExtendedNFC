import Foundation

/// DESFire native command builder and sender.
/// Commands are wrapped in ISO 7816 framing: [0x90, CMD, 0x00, 0x00, LEN, DATA..., 0x00].
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class DESFireCommands: @unchecked Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    // MARK: - Command Codes

    public static let GET_VERSION: UInt8 = 0x60
    public static let GET_APPLICATION_IDS: UInt8 = 0x6A
    public static let SELECT_APPLICATION: UInt8 = 0x5A
    public static let GET_FILE_IDS: UInt8 = 0x6F
    public static let GET_FILE_SETTINGS: UInt8 = 0xF5
    public static let READ_DATA: UInt8 = 0xBD
    public static let WRITE_DATA: UInt8 = 0x3D
    public static let READ_RECORDS: UInt8 = 0xBB
    public static let GET_VALUE: UInt8 = 0x6C
    public static let ADDITIONAL_FRAME: UInt8 = 0xAF
    public static let GET_KEY_SETTINGS: UInt8 = 0x45
    public static let GET_CARD_UID: UInt8 = 0x51
    public static let FREE_MEMORY: UInt8 = 0x6E
    public static let FORMAT_PICC: UInt8 = 0xFC
    public static let AUTHENTICATE_ISO: UInt8 = 0x1A
    public static let AUTHENTICATE_EV2_FIRST: UInt8 = 0x71

    // MARK: - Core Send

    /// Send a DESFire native command with automatic AF chaining.
    open func sendCommand(_ cmd: UInt8, data: Data? = nil) async throws -> Data {
        try await sendWithChaining(cmd, data: data)
    }
}
