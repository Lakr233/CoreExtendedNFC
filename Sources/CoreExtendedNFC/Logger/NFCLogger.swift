import Foundation

/// Protocol for receiving NFC library log output.
/// Conform to this protocol and assign an instance to ``NFCLogConfiguration/logger``
/// to capture protocol-level traces (APDU sends/receives, chaining, etc.).
public protocol NFCLogger: Sendable {
    func log(_ level: LogLevel, _ message: String, source: String)
}

/// Global configuration for the NFC logging subsystem.
public enum NFCLogConfiguration: Sendable {
    private static let storage = LockedValue<(any NFCLogger)?>(nil)
    private static let payloadStorage = LockedValue(false)

    /// The active logger. Reads and writes are synchronised, so it can be
    /// replaced at any time while NFC work is running on other threads.
    public static var logger: (any NFCLogger)? {
        get { storage.withLock { $0 } }
        set { storage.withLock { $0 = newValue } }
    }

    /// Whether raw payload bytes (APDU data, raw frames, block contents, UIDs)
    /// appear in log messages. Defaults to `false`: frames are logged as header,
    /// lengths and status word only.
    ///
    /// Secrets are redacted regardless of this flag: PIN / password / authentication
    /// exchanges (ISO 7816 VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER,
    /// GET CHALLENGE, EXTERNAL / MUTUAL / GENERAL / INTERNAL AUTHENTICATE,
    /// MIFARE `PWD_AUTH` and PACK, Ultralight C and DESFire authentication) log
    /// `<redacted n bytes>`, and secure-messaging APDUs log header and status word only.
    ///
    /// - Warning: Enabling this writes card contents and identifiers (UIDs, file data,
    ///   transit history) to the logger. Enable it only for local debugging.
    public static var logPayloads: Bool {
        get { payloadStorage.withLock { $0 } }
        set { payloadStorage.withLock { $0 = newValue } }
    }
}

/// Internal shorthand for logging throughout the library.
enum NFCLog {
    static func debug(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.debug, message(), source: source)
    }

    static func info(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.info, message(), source: source)
    }

    static func error(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.error, message(), source: source)
    }
}
