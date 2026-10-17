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
            guard let scanner: ScannerViewController = showList(in: tabBar, at: 0) else { return false }
            scanner.importFile(at: url)
        case .ndef:
            guard let ndef: NDEFViewController = showList(in: tabBar, at: 2) else { return false }
            ndef.importFile(at: url)
        case .passport:
            guard let passport: PassportViewController = showList(in: tabBar, at: 3) else { return false }
            passport.importFile(at: url)
        }
        return true
    }

    /// Selects the tab at `index` and brings its list back: pops the list's
    /// navigation stack to the root and puts the placeholder back in the detail
    /// column of the tab's split view.
    /// - Returns: The list screen, or `nil` when the tab is not a `List` list.
    private func showList<List: UIViewController>(in tabBar: TabBarController, at index: Int) -> List? {
        guard let viewControllers = tabBar.viewControllers, viewControllers.indices.contains(index) else {
            return nil
        }
        let tab = viewControllers[index]
        let split = tab as? UISplitViewController
        guard let nav = split?.recordListNavigationController ?? (tab as? UINavigationController),
              let list = nav.viewControllers.first as? List
        else { return nil }
        tabBar.selectedIndex = index
        nav.popToRootViewController(animated: false)
        split?.showRecordPlaceholder()
        return list
    }
}
