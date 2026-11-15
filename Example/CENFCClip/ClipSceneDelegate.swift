import Foundation
import UIKit

final class ClipSceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private let scanScreen = ClipScanViewController()
    /// The last link routed, so the same link arriving twice is routed once.
    private var routedInvocation: ClipInvocation?

    func scene(
        _ scene: UIScene,
        willConnectTo _: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let navigation = UINavigationController(rootViewController: scanScreen)
        navigation.navigationBar.prefersLargeTitles = true
        navigation.navigationBar.accessibilityIdentifier = "nav.clip"
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = navigation
        window.makeKeyAndVisible()
        self.window = window

        // On a device the link arrives as a web-browsing user activity.
        if let invocation = connectionOptions.userActivities.lazy.compactMap(ClipInvocation.init(userActivity:)).first {
            route(invocation)
        }
        #if DEBUG
            // The Simulator hands the link over only as this variable
            // (`simulator launch --env`, Xcode's scheme); no user activity comes.
            // Under Xcode both arrive, which `route(_:)` tolerates.
            if let value = ProcessInfo.processInfo.environment["_XCAppClipURL"],
               let url = URL(string: value),
               let invocation = ClipInvocation(url)
            {
                route(invocation)
            }
        #endif
    }

    /// A link opened while the App Clip is already running.
    func scene(_: UIScene, continue userActivity: NSUserActivity) {
        if let invocation = ClipInvocation(userActivity: userActivity) {
            route(invocation)
        }
    }

    /// The link only opens the App Clip, which is already on its one task: no
    /// parameter changes what is shown, and unknown ones are ignored. A launch
    /// without a link (App Switcher) routes nothing and keeps the current screen.
    private func route(_ invocation: ClipInvocation) {
        guard invocation != routedInvocation else { return }
        routedInvocation = invocation
        #if DEBUG
            NSLog("CENFCClip invocation parameters: %@", String(describing: invocation.parameters.sorted { $0.key < $1.key }))
            // Debug builds only: `&debugSample=typeA` or `&debugSample=felica`
            // opens the result screen with made-up card data, because the
            // Simulator has no NFC to produce a real one.
            if let sample = invocation.parameters["debugSample"] {
                scanScreen.showDebugSample(named: sample)
            }
        #endif
    }
}
