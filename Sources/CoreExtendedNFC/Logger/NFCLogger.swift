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

    /// The active logger. Reads and writes are synchronised, so it can be
    /// replaced at any time while NFC work is running on other threads.
    public static var logger: (any NFCLogger)? {
        get { storage.withLock { $0 } }
        set { storage.withLock { $0 = newValue } }
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
