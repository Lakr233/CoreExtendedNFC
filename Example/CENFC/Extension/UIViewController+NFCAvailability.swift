import CoreExtendedNFC
import UIKit

extension UIViewController {
    /// Presents an appropriate alert for an NFC error.
    ///
    /// When the error is ``NFCError/nfcNotAvailable``, a special alert is shown
    /// that guides the user to open Settings. Session cancellation errors are
    /// silently ignored. Other errors return `false` and the caller presents
    /// the alert, usually with ``presentErrorAlert(for:)``.
    ///
    /// - Returns: `true` if the error was handled (alert shown or silently
    ///   ignored), `false` if the caller should handle it.
    ///
    /// Pass the operation's `session` so a failure that raced the user's cancel
    /// is also treated as a cancel.
    func presentNFCErrorAlertIfNeeded(for error: Error, session: NFCSessionManager? = nil) -> Bool {
        if NFCErrorMessage.isCancellation(error, session: session) {
            return true
        }
        if case .nfcNotAvailable? = error as? NFCError {
            presentNFCNotAvailableAlert()
            return true
        }
        return false
    }

    /// Shows an "Error" alert describing `error` in the user's language.
    func presentErrorAlert(for error: Error, title: String = String(localized: "Error")) {
        presentInfoAlert(title: title, message: NFCErrorMessage.message(for: error))
    }

    /// Shows an alert explaining NFC is not available, with a button to open Settings.
    private func presentNFCNotAvailableAlert() {
        let alert = UIAlertController(
            title: String(localized: "NFC Not Available"),
            message: String(localized: "NFC is required to scan tags and read cards. Please check that NFC is enabled in Settings."),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(
            title: String(localized: "Open Settings"),
            style: .default
        ) { _ in
            if let url = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(url)
            }
        })
        alert.addAction(UIAlertAction(
            title: String(localized: "Cancel"),
            style: .cancel
        ))
        presentQueued(alert)
    }
}

extension NFCSessionManager {
    /// Ends the session after a failed operation.
    ///
    /// The system sheet shows the failure instead of the success checkmark that a
    /// plain ``invalidate()`` displays. A cancelled session is closed quietly.
    func invalidate(after error: Error) {
        if NFCErrorMessage.isCancellation(error, session: self) {
            invalidate()
        } else {
            invalidate(errorMessage: NFCErrorMessage.message(for: error))
        }
    }
}
