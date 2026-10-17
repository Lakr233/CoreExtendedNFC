import UIKit

extension UIViewController {
    /// Presents a share sheet for exported record files and deletes the files
    /// once the sheet closes, whether the user shared, saved or cancelled.
    ///
    /// Exports can hold personal data, so they must not linger in the temporary
    /// directory (see ``ExportFileLocation``). When UIKit refuses the
    /// presentation (this screen is off screen or already presenting something),
    /// the completion handler never runs, so the files are removed right away.
    ///
    /// Where the sheet shows as a popover (a wide window), it points at
    /// `barButtonItem`, else at `sourceView` (the row the export came from), else
    /// at this screen's trailing bar button, so it never sits on the view's
    /// corner or centre.
    func presentExportSheet(
        for fileURLs: [URL],
        barButtonItem: UIBarButtonItem? = nil,
        sourceView: UIView? = nil
    ) {
        guard view.window != nil, presentedViewController == nil else {
            ExportFileLocation.remove(fileURLs)
            return
        }
        let activity = UIActivityViewController(activityItems: fileURLs, applicationActivities: nil)
        if let popover = activity.popoverPresentationController {
            anchorPopover(popover, barButtonItem: barButtonItem, sourceView: sourceView)
        }
        activity.completionWithItemsHandler = { _, _, _, _ in
            ExportFileLocation.remove(fileURLs)
        }
        present(activity, animated: true)
        if activity.presentingViewController == nil {
            ExportFileLocation.remove(fileURLs)
        }
    }

    /// Points `popover` at `barButtonItem`, else at `sourceView`, else at this
    /// screen's trailing bar button. Only a screen without any of them falls
    /// back to its own view.
    func anchorPopover(
        _ popover: UIPopoverPresentationController,
        barButtonItem: UIBarButtonItem? = nil,
        sourceView: UIView? = nil
    ) {
        if let barButtonItem {
            popover.barButtonItem = barButtonItem
        } else if let sourceView {
            popover.sourceView = sourceView
            popover.sourceRect = sourceView.bounds
        } else if let trailingItem = navigationItem.rightBarButtonItems?.first {
            popover.barButtonItem = trailingItem
        } else {
            popover.sourceView = view
        }
    }
}
