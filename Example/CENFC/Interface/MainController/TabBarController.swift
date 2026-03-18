import UIKit

class TabBarController: UITabBarController {
    private var hasScheduledWelcome = false

    override func viewDidLoad() {
        super.viewDidLoad()

        let scannerVC = ScannerViewController()
        let dumpVC = DumpViewController()
        let ndefVC = NDEFViewController()
        let passportVC = PassportViewController()
        let toolsVC = ToolsViewController()

        let tabs: [(UIViewController, String, String)] = [
            (scannerVC, String(localized: "Scanner"), "sensor.tag.radiowaves.forward"),
            (dumpVC, String(localized: "Dump"), "internaldrive"),
            (ndefVC, String(localized: "NDEF"), "doc.text"),
            (passportVC, String(localized: "Passport"), "person.text.rectangle"),
            (toolsVC, String(localized: "Tools"), "wrench.and.screwdriver"),
        ]

        viewControllers = tabs.map { vc, title, icon in
            vc.title = title
            vc.tabBarItem = UITabBarItem(
                title: title,
                image: UIImage(systemName: icon),
                selectedImage: nil
            )
            let nav = UINavigationController(rootViewController: vc)
            nav.navigationBar.prefersLargeTitles = true
            return nav
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
