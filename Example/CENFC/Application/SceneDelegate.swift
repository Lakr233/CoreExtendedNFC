import UIKit

@objc(SceneDelegate)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private let privacyCover = PrivacyCover()

    func scene(
        _ scene: UIScene,
        willConnectTo _: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = (scene as? UIWindowScene) else { return }
        let window = UIWindow(windowScene: windowScene)
        defer {
            window.makeKeyAndVisible()
            self.window = window
        }
        window.rootViewController = TabBarController()

        // Remove Inbox copies (AirDrop, Mail) left by imports that never
        // finished; keep the file this launch is opening, its import deletes it.
        let openingURLs = connectionOptions.urlContexts.map(\.url)
        Task.detached(priority: .utility) {
            ImportFileReader.purgeInbox(keeping: openingURLs)
        }

        if let urlContext = connectionOptions.urlContexts.first {
            DispatchQueue.main.async { [weak self] in
                self?.handleOpenURL(urlContext.url)
            }
        }
    }

    func sceneWillResignActive(_: UIScene) {
        // Hide passport data from the app switcher snapshot.
        // The cover is its own window above alerts and modals, so a sheet
        // presented while inactive cannot appear on top of it.
        if let window {
            privacyCover.show(over: window)
        }
    }

    func sceneDidBecomeActive(_: UIScene) {
        privacyCover.hide()
    }

    func sceneDidEnterBackground(_: UIScene) {
        // Record saves run asynchronously; finish them before the app can be suspended or killed.
        RecordStores.flushInBackgroundTask()
    }

    func scene(_: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        for context in URLContexts {
            handleOpenURL(context.url)
        }
    }

    private func handleOpenURL(_ url: URL) {
        Task {
            // Routing may read the file to sniff its type; keep that off the main thread.
            let destination = await Task.detached(priority: .userInitiated) {
                OpenURLRouter.destination(for: url)
            }.value
            // A file that is not imported must not stay in Documents/Inbox.
            guard let destination, open(url, at: destination) else {
                ImportFileReader.removeIfInInbox(url)
                return
            }
        }
    }

    /// Hands `url` to the import screen for `destination`.
    /// - Returns: Whether an import screen took the file (it then deletes the Inbox copy).
    private func open(_ url: URL, at destination: OpenURLDestination) -> Bool {
        guard let tabBar = window?.rootViewController as? TabBarController else { return false }

        switch destination {
        case .scanner:
            guard let nav = navigationController(in: tabBar, at: 0),
                  let scanner = nav.viewControllers.first as? ScannerViewController
            else { return false }
            tabBar.selectedIndex = 0
            nav.popToRootViewController(animated: false)
            scanner.importFile(at: url)
        case .ndef:
            guard let nav = navigationController(in: tabBar, at: 2),
                  let ndef = nav.viewControllers.first as? NDEFViewController
            else { return false }
            tabBar.selectedIndex = 2
            nav.popToRootViewController(animated: false)
            ndef.importFile(at: url)
        case .passport:
            guard let nav = navigationController(in: tabBar, at: 3),
                  let passport = nav.viewControllers.first as? PassportViewController
            else { return false }
            tabBar.selectedIndex = 3
            nav.popToRootViewController(animated: false)
            passport.importFile(at: url)
        }
        return true
    }

    private func navigationController(in tabBar: TabBarController, at index: Int) -> UINavigationController? {
        guard let viewControllers = tabBar.viewControllers, viewControllers.indices.contains(index) else {
            return nil
        }
        return viewControllers[index] as? UINavigationController
    }
}
