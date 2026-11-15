import UIKit

/// The App Clip's entry point. It keeps no stores, logs or files: one scene,
/// one scan screen.
@main
final class ClipAppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options _: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(
            name: "Default Configuration",
            sessionRole: connectingSceneSession.role
        )
        configuration.delegateClass = ClipSceneDelegate.self
        return configuration
    }
}
