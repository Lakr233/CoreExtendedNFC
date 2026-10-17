import UIKit

class TabBarController: UITabBarController {
    private var hasScheduledWelcome = false
    private enum Accessibility {
        static let tabBar = "main.tabbar"
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        tabBar.accessibilityIdentifier = Accessibility.tabBar

        let scannerVC = ScannerViewController()
        let dumpVC = DumpViewController()
        let ndefVC = NDEFViewController()
        let passportVC = PassportViewController()
        let toolsVC = ToolsViewController()

        // Scanner, Dump, NDEF and Passport show the open record beside the list
        // when the window is wide enough; Tools stays a single navigation stack.
        let tabs: [(UIViewController, String, String, String, Bool)] = [
            (scannerVC, String(localized: "Scanner"), "sensor.tag.radiowaves.forward", "scanner", true),
            (dumpVC, String(localized: "Dump"), "internaldrive", "dump", true),
            (ndefVC, String(localized: "NDEF"), "doc.text", "ndef", true),
            (passportVC, String(localized: "Passport"), "person.text.rectangle", "passport", true),
            (toolsVC, String(localized: "Tools"), "wrench.and.screwdriver", "tools", false),
        ]

        viewControllers = tabs.map { tab -> UIViewController in
            let (vc, title, icon, identifier, showsRecordColumns) = tab
            vc.title = title
            let tabBarItem = UITabBarItem(
                title: title,
                image: UIImage(systemName: icon),
                selectedImage: nil
            )
            tabBarItem.accessibilityIdentifier = "tab.\(identifier)"
            vc.tabBarItem = tabBarItem
            let nav = UINavigationController(rootViewController: vc)
            nav.navigationBar.prefersLargeTitles = true
            nav.navigationBar.accessibilityIdentifier = "nav.\(identifier)"
            guard showsRecordColumns else {
                nav.tabBarItem = tabBarItem
                return nav
            }
            let split = UISplitViewController.makeRecordSplit(listNavigation: nav, delegate: self)
            split.tabBarItem = tabBarItem
            return split
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        scheduleWelcomeIfNeeded()
    }

    private func scheduleWelcomeIfNeeded() {
        guard WelcomeExperience.shouldPresent else { return }
        guard !hasScheduledWelcome else { return }
        hasScheduledWelcome = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            guard WelcomeExperience.shouldPresent else { return }
            guard presentedViewController == nil else { return }
            let controller = WelcomePageViewController.makePresentedController {
                WelcomeExperience.markPresented()
            }
            present(controller, animated: true)
        }
    }
}

// MARK: - UISplitViewControllerDelegate

extension TabBarController: UISplitViewControllerDelegate {
    /// Collapsing onto the list while only the placeholder is open, so the
    /// compact screen shows the list rather than "Select a record".
    func splitViewController(
        _ svc: UISplitViewController,
        topColumnForCollapsingToProposedTopColumn proposedTopColumn: UISplitViewController.Column
    ) -> UISplitViewController.Column {
        svc.isShowingRecordPlaceholder ? .primary : proposedTopColumn
    }

    func splitViewControllerDidExpand(_ svc: UISplitViewController) {
        svc.tidyRecordColumnsAfterExpanding()
    }
}
