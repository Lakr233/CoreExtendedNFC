@_exported import CoreExtendedNFC
import UIKit

@objc(AppDelegate)
class AppDelegate: UIResponder, UIApplicationDelegate {
    override init() {
        super.init()
        PrintRedirection.start()
        NFCLogConfiguration.logger = AppNFCLogBridge()
    }

    func application(
        _: UIApplication,
        didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        AppBootstrap.preloadPersistentStores()
        AppBootstrap.purgeTemporaryExports()
        return true
    }

    func application(
        _: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options _: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(
            name: "Default Configuration",
            sessionRole: connectingSceneSession.role
        )
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}

@MainActor
private enum AppBootstrap {
    static func preloadPersistentStores() {
        _ = ScanStore.shared
        _ = DumpStore.shared
        _ = NDEFStore.shared
        _ = PassportStore.shared
    }

    /// Removes export and preview files left in the temporary directory when the
    /// app was terminated while a share sheet or preview was open. They can hold
    /// passport data and card contents.
    static func purgeTemporaryExports() {
        Task.detached(priority: .utility) {
            ExportFileLocation.purgeAll()
            PassportDetailViewController.purgeAllPreviews()
        }
    }
}
