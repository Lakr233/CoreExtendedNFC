import Foundation

/// Records why a reader session ended so that commands failing afterwards (or in
/// flight when it ended) report the real cause.
///
/// When the user taps Cancel on the system NFC sheet, CoreNFC calls
/// `didInvalidateWithError` with `NFCReaderSessionInvalidationErrorUserCanceled`,
/// but the commands that were running or are sent later fail with transceive codes
/// such as `NFCReaderTransceiveErrorSessionInvalidated` (103). Transports consult
/// the monitor of their session and report those failures as
/// ``NFCError/userCanceled`` once the user cancel has been recorded.
public final class SessionTerminationMonitor: Sendable {
    private let userCanceledFlag = LockedValue(false)

    public init() {}

    /// Whether the user dismissed the session.
    public var userCanceled: Bool {
        userCanceledFlag.withLock { $0 }
    }

    /// Record that the user dismissed the session.
    public func recordUserCancel() {
        userCanceledFlag.withLock { $0 = true }
    }
}
