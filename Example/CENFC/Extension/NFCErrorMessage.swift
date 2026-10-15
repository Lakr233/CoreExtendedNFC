import CoreExtendedNFC
import Foundation

/// How the app reports errors from CoreExtendedNFC and its own code.
nonisolated enum NFCErrorMessage {
    /// Whether `error` means the user ended the operation, so no error alert should be shown.
    static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        return (error as? NFCError)?.isUserCancellation == true
    }

    /// A localized, human-readable description of `error`.
    ///
    /// `NFCError` conforms to `LocalizedError`, so this never shows a raw enum dump.
    static func message(for error: Error) -> String {
        error.localizedDescription
    }
}
