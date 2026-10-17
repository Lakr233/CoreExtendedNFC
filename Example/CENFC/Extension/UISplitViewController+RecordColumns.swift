import ConfigurableKit
import UIKit

/// The two-column layout of the Scanner, Dump, NDEF and Passport tabs: the list
/// in the primary column, the open record in the secondary one.
///
/// No compact column is set. When the window becomes compact (the closed outer
/// display, an ordinary iPhone) UIKit collapses the secondary column onto the
/// list's navigation stack, so a record that is open stays open.
extension UISplitViewController {
    static func makeRecordSplit(
        listNavigation: UINavigationController,
        delegate: any UISplitViewControllerDelegate
    ) -> UISplitViewController {
        let split = UISplitViewController(style: .doubleColumn)
        split.preferredDisplayMode = .oneBesideSecondary
        split.preferredSplitBehavior = .tile
        // The list always stays beside the record: no sidebar toggle or swipe hides it.
        split.displayModeButtonVisibility = .never
        split.presentsWithGesture = false
        split.setViewController(listNavigation, for: .primary)
        split.setViewController(
            makeRecordDetailNavigation(screens: [RecordDetailPlaceholderViewController()], listNavigation: listNavigation),
            for: .secondary
        )
        split.delegate = delegate
        return split
    }

    /// A navigation controller for the detail column, with an accessibility
    /// identifier derived from the list's (`nav.scanner` → `nav.scanner.detail`).
    static func makeRecordDetailNavigation(
        screens: [UIViewController],
        listNavigation: UINavigationController?
    ) -> UINavigationController {
        let navigation = RecordDetailNavigationController()
        navigation.setViewControllers(screens, animated: false)
        if let identifier = listNavigation?.navigationBar.accessibilityIdentifier {
            navigation.navigationBar.accessibilityIdentifier = "\(identifier).detail"
        }
        return navigation
    }

    /// The navigation controller of the list column.
    var recordListNavigationController: UINavigationController? {
        viewController(for: .primary) as? UINavigationController
    }

    /// The navigation controller of the detail column.
    var recordDetailNavigationController: UINavigationController? {
        viewController(for: .secondary) as? UINavigationController
    }

    /// Whether the detail column holds nothing but the placeholder.
    var isShowingRecordPlaceholder: Bool {
        guard let detail = recordDetailNavigationController else { return true }
        return detail.viewControllers.allSatisfy { $0 is RecordDetailPlaceholderViewController }
    }

    /// Shows `detail` as the only screen of the detail column, in a new
    /// navigation controller that replaces the previous one.
    func showRecordDetailColumn(_ detail: UIViewController) {
        closeRecordDetailScreens()
        setViewController(
            Self.makeRecordDetailNavigation(screens: [detail], listNavigation: recordListNavigationController),
            for: .secondary
        )
    }

    /// Puts the placeholder back in the detail column.
    ///
    /// While collapsed, only the stack of the hidden detail column is replaced,
    /// so nothing is pushed onto the list.
    func showRecordPlaceholder() {
        if isCollapsed, let detail = recordDetailNavigationController {
            closeRecordDetailScreens()
            detail.setViewControllers([RecordDetailPlaceholderViewController()], animated: false)
        } else {
            showRecordDetailColumn(RecordDetailPlaceholderViewController())
        }
    }

    /// Moves screens back into the detail column after the window expanded.
    ///
    /// While compact, records open by a push onto the list's stack (see
    /// `UIViewController.showRecordDetail(_:)`). If any of them are
    /// still above the list once the split view has two columns again, they move
    /// to the detail column. An emptied detail column gets the placeholder back,
    /// and a placeholder left below real screens is dropped.
    func tidyRecordColumnsAfterExpanding() {
        guard let list = recordListNavigationController,
              let root = list.viewControllers.first
        else { return }

        let stranded = Array(list.viewControllers.dropFirst())
        if !stranded.isEmpty {
            closeRecordDetailScreens()
            list.setViewControllers([root], animated: false)
            setViewController(
                Self.makeRecordDetailNavigation(screens: stranded, listNavigation: list),
                for: .secondary
            )
            return
        }

        guard let detail = recordDetailNavigationController else {
            showRecordPlaceholder()
            return
        }
        let screens = detail.viewControllers
        let realScreens = screens.filter { !($0 is RecordDetailPlaceholderViewController) }
        if screens.isEmpty {
            showRecordPlaceholder()
        } else if !realScreens.isEmpty, realScreens.count != screens.count {
            detail.setViewControllers(realScreens, animated: false)
        }
    }

    /// Lets the screens of the detail column save or cancel their work before
    /// the column is replaced.
    func closeRecordDetailScreens() {
        for screen in recordDetailNavigationController?.viewControllers ?? [] {
            (screen as? any ClosingAwareScreen)?.screenWillClose()
        }
    }
}

/// The navigation controller of the detail column.
///
/// In a split view the detail column's views extend under the list column and
/// rely on the safe area to stay clear of it. Stack screens pin their scroll
/// view to the view's edges, so their rows would sit under the list; this keeps
/// every stack screen shown here inside the horizontal safe area.
final class RecordDetailNavigationController: UINavigationController, UINavigationControllerDelegate {
    override func viewDidLoad() {
        super.viewDidLoad()
        delegate = self
    }

    func navigationController(
        _: UINavigationController,
        willShow viewController: UIViewController,
        animated _: Bool
    ) {
        (viewController as? StackScrollController)?.pinContentToHorizontalSafeArea()
    }
}
