import UIKit

extension UIViewController {
    /// Presents a share sheet for exported record files and deletes the files
    /// once the sheet closes, whether the user shared, saved or cancelled.
    ///
    /// Exports can hold personal data, so they must not linger in the temporary
    /// directory (see ``ExportFileLocation``). When UIKit refuses the
    /// presentation (this screen is off screen or already presenting something),
    /// the completion handler never runs, so the files are removed right away.
    func presentExportSheet(for fileURLs: [URL], barButtonItem: UIBarButtonItem? = nil) {
        guard view.window != nil, presentedViewController == nil else {
            ExportFileLocation.remove(fileURLs)
            return
        }
        let activity = UIActivityViewController(activityItems: fileURLs, applicationActivities: nil)
        if let popover = activity.popoverPresentationController {
            if let barButtonItem {
                popover.barButtonItem = barButtonItem
            } else {
                popover.sourceView = view
            }
        }
        activity.completionWithItemsHandler = { _, _, _, _ in
            ExportFileLocation.remove(fileURLs)
        }
        present(activity, animated: true)
        if activity.presentingViewController == nil {
            ExportFileLocation.remove(fileURLs)
        }
    }
}
