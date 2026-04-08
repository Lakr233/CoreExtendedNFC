import UIKit

MainActor.isolated {
    _ = UIApplicationMain(
        CommandLine.argc,
        CommandLine.unsafeArgv,
        nil,
        NSStringFromClass(AppDelegate.self)
    )

    fatalError("UIApplicationMain returned unexpectedly.")
}
