import UIKit

/// A screen that shows one stored record (card, dump, NDEF record, passport).
///
/// When the record is deleted while the screen is open in the detail column of
/// a split view, the list puts the placeholder back (see
/// `UIViewController.closeRecordDetail(ifRecordIsGone:)`).
@MainActor
protocol RecordDetailScreen: AnyObject {
    /// The ID of the stored record on screen, or `nil` for one not stored yet.
    var displayedRecordID: UUID? { get }

    /// Called just before the screen is closed because its record was deleted.
    func recordWasDeleted()
}

extension RecordDetailScreen {
    func recordWasDeleted() {}
}

/// A screen with work to save or cancel when it closes for good (an NDEF
/// editor's edits, a pending chip read or exchange).
///
/// The screen calls ``screenWillClose()`` itself when it is popped (see
/// `UIViewController.isLeavingForGood`). A split view also calls it on every
/// screen of the detail column before it replaces that column, because a
/// replaced column on a tab that is not selected gets no appearance callbacks.
@MainActor
protocol ClosingAwareScreen: AnyObject {
    /// Saves or cancels the screen's work. May run more than once.
    func screenWillClose()
}

extension UIViewController {
    /// Opens a record from a list.
    ///
    /// In a split view with two columns the record replaces the detail column;
    /// otherwise (collapsed split view, plain navigation) it is pushed onto this
    /// screen's navigation stack. Screens opened from inside a record are pushed
    /// on that record's own navigation controller instead.
    func showRecordDetail(_ detail: UIViewController) {
        if let split = splitViewController, !split.isCollapsed {
            split.showRecordDetailColumn(detail)
        } else {
            navigationController?.pushViewController(detail, animated: true)
        }
    }

    /// Puts the placeholder back in the detail column when it shows a record
    /// that `isStored` no longer finds.
    func closeRecordDetail(ifRecordIsGone isStored: (UUID) -> Bool) {
        guard let split = splitViewController,
              let detail = split.recordDetailNavigationController
        else { return }
        let deletedScreens = detail.viewControllers.compactMap { controller -> (any RecordDetailScreen)? in
            guard let screen = controller as? any RecordDetailScreen,
                  let id = screen.displayedRecordID,
                  !isStored(id)
            else { return nil }
            return screen
        }
        guard !deletedScreens.isEmpty else { return }
        deletedScreens.forEach { $0.recordWasDeleted() }
        split.showRecordPlaceholder()
    }

    /// Whether this screen is going away for good, as opposed to being covered
    /// by a push, a sheet or another tab.
    ///
    /// Besides a pop or a dismissal, a screen in a split view's detail column
    /// also leaves when its whole navigation controller is replaced (another
    /// record opened, a deleted record closed). Then the screen itself does not
    /// report `isMovingFromParent`, so this also checks whether its navigation
    /// controller is leaving or has already been detached. Check it in both
    /// `viewWillDisappear(_:)` and `viewDidDisappear(_:)`: the navigation
    /// controller may only be detached by the time the transition ends.
    var isLeavingForGood: Bool {
        if isMovingFromParent || isBeingDismissed {
            return true
        }
        guard let navigationController else {
            // Popped or removed: in no container and not presented.
            return parent == nil && presentingViewController == nil
        }
        if navigationController.isMovingFromParent || navigationController.isBeingDismissed {
            return true
        }
        return navigationController.parent == nil
            && navigationController.presentingViewController == nil
            && navigationController.view.window == nil
    }
}
