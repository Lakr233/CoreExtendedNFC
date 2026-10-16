import UIKit

extension PassportViewController {
    func importFile(at url: URL) {
        Task {
            do {
                let record = try await ImportFileReader.readInBackground(url) { data in
                    try PassportDocument.importRecord(from: data)
                }
                importRecord(record)
            } catch {
                presentErrorAlert(for: error)
            }
        }
    }

    /// Adds an imported record, asking first when it would replace a stored
    /// record with the same document number.
    private func importRecord(_ record: PassportRecord) {
        guard let existing = PassportStore.shared.importConflict(for: record) else {
            PassportStore.shared.importRecord(record)
            reloadSnapshot()
            return
        }
        let alert = UIAlertController(
            title: String(localized: "Replace Passport Record?"),
            message: String(localized: "A record for \(existing.displayName) with the same document number is already saved. Replacing it discards the saved record, including its security results from reading the chip."),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Replace"), style: .destructive) { [weak self] _ in
            PassportStore.shared.importRecord(record, replacingExisting: true)
            self?.reloadSnapshot()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Keep Both"), style: .default) { [weak self] _ in
            PassportStore.shared.importRecord(record, replacingExisting: false)
            self?.reloadSnapshot()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        presentQueued(alert)
    }
}

// MARK: - UIDocumentPickerDelegate

extension PassportViewController: UIDocumentPickerDelegate {
    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            importFile(at: url)
        }
    }
}
