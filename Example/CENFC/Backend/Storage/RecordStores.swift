import UIKit

/// The app's record stores as a group.
@MainActor
enum RecordStores {
    /// Returns once every store's latest saved records are on disk.
    static func flushAll() async {
        await ScanStore.shared.flush()
        await DumpStore.shared.flush()
        await NDEFStore.shared.flush()
        await PassportStore.shared.flush()
    }

    /// Flushes every store inside a background task, so the writes finish even
    /// when the app is moving to the background or about to be terminated.
    static func flushInBackgroundTask(application: UIApplication = .shared) {
        let task = BackgroundTask(application: application)
        Task {
            await flushAll()
            task.end()
        }
    }
}

/// A `beginBackgroundTask` assertion that is ended exactly once.
@MainActor
private final class BackgroundTask {
    private let application: UIApplication
    private var identifier = UIBackgroundTaskIdentifier.invalid

    init(application: UIApplication) {
        self.application = application
        identifier = application.beginBackgroundTask(withName: "Save records") { [weak self] in
            self?.end()
        }
    }

    func end() {
        guard identifier != .invalid else { return }
        application.endBackgroundTask(identifier)
        identifier = .invalid
    }
}
