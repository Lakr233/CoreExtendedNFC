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
    func presentNFCErrorAlertIfNeeded(for error: Error) -> Bool {
        if let nfcError = error as? NFCError, case .nfcNotAvailable = nfcError {
            presentNFCNotAvailableAlert()
            return true
        }

        let description = String(describing: error)
        if description.contains("invalidat") || description.contains("cancel") {
            return true
        }

        return false
    }

    /// Shows a generic "Error" alert describing `error`.
    func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Error"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
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
        present(alert, animated: true)
    }
}
