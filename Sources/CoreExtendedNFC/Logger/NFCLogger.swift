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

/// Shorthand for logging through ``NFCLogConfiguration/logger``.
public enum NFCLog {
    public static func debug(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.debug, message(), source: source)
    }

    public static func info(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.info, message(), source: source)
    }

    public static func error(_ message: @autoclosure () -> String, source: String) {
        NFCLogConfiguration.logger?.log(.error, message(), source: source)
    }

    /// A value read from the card (balance, station code, …) for a log line: the value
    /// itself only when ``NFCLogConfiguration/logPayloads`` is on, `<redacted>` otherwise.
    public static func cardValue(
        _ value: some CustomStringConvertible,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) -> String {
        logPayloads ? value.description : "<redacted>"
    }
}
