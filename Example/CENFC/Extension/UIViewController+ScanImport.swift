import UIKit

extension UIViewController {
    /// Stores a scan record imported from a `.cenfc` file, asking first when it
    /// would replace a saved record (same exported record or same card UID).
    func importScanRecord(_ record: ScanRecord, at index: Int = 0, store: ScanStore = .shared) {
        guard let existing = store.importConflict(for: record) else {
            store.importRecord(record, replacingExisting: false, at: index)
            return
        }
        presentQueued(Self.makeScanImportConflictAlert(existing: existing) { replacingExisting in
            store.importRecord(record, replacingExisting: replacingExisting, at: index)
        })
    }

    /// Replace / Keep Both / Cancel, like the passport import conflict prompt.
    /// `onChoice` gets `true` for Replace and `false` for Keep Both; Cancel stores nothing.
    static func makeScanImportConflictAlert(
        existing: ScanRecord,
        onChoice: @escaping (_ replacingExisting: Bool) -> Void
    ) -> UIAlertController {
        let alert = UIAlertController(
            title: String(localized: "Replace Scan Record?"),
            message: String(localized: "A record for this \(existing.cardInfo.type.description) card is already saved. Replacing it discards the saved record."),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Replace"), style: .destructive) { _ in
            onChoice(true)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Keep Both"), style: .default) { _ in
            onChoice(false)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        return alert
    }
}
