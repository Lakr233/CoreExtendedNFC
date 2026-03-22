import UIKit

@objc(SceneDelegate)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene, willConnectTo _: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = (scene as? UIWindowScene) else { return }
        let window = UIWindow(windowScene: windowScene)
        defer {
            window.makeKeyAndVisible()
            self.window = window
        }
        window.rootViewController = TabBarController()

        if let urlContext = connectionOptions.urlContexts.first {
            DispatchQueue.main.async { [weak self] in
                self?.handleOpenURL(urlContext.url)
            }
        }
    }

    func scene(_: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        for context in URLContexts {
            handleOpenURL(context.url)
        }
    }

    private func handleOpenURL(_ url: URL) {
        guard let tabBar = window?.rootViewController as? TabBarController,
              let destination = OpenURLRouter.destination(for: url)
        else { return }

        switch destination {
        case .scanner:
            guard let nav = navigationController(in: tabBar, at: 0),
                  let scanner = nav.viewControllers.first as? ScannerViewController
            else { return }
            tabBar.selectedIndex = 0
            nav.popToRootViewController(animated: false)
            scanner.importFile(at: url)
        case .ndef:
            guard let nav = navigationController(in: tabBar, at: 2),
                  let ndef = nav.viewControllers.first as? NDEFViewController
            else { return }
            tabBar.selectedIndex = 2
            nav.popToRootViewController(animated: false)
            ndef.importFile(at: url)
        case .passport:
            guard let nav = navigationController(in: tabBar, at: 3),
                  let passport = nav.viewControllers.first as? PassportViewController
            else { return }
            tabBar.selectedIndex = 3
            nav.popToRootViewController(animated: false)
            passport.importFile(at: url)
        }
    }

    private func navigationController(in tabBar: TabBarController, at index: Int) -> UINavigationController? {
        guard let viewControllers = tabBar.viewControllers, viewControllers.indices.contains(index) else {
            return nil
        }
        return viewControllers[index] as? UINavigationController
    }
}
