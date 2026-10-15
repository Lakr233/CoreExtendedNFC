import UIKit

/// Presents alerts one after another.
///
/// UIKit ignores `present(_:animated:)` while the presenter is already showing
/// something, so back-to-back alerts (an info alert followed by a prompt, or one
/// prompt per imported file) would silently drop everything but the first.
/// The queue waits until the previous alert is dismissed and the presenter is
/// free before presenting the next one. Alerts whose presenter has left the
/// window are discarded.
@MainActor
final class AlertQueue {
    static let shared = AlertQueue()

    private struct Pending {
        weak var presenter: UIViewController?
        let alert: UIAlertController
    }

    private var pending: [Pending] = []
    private weak var showing: UIAlertController?
    private var drainTask: Task<Void, Never>?

    var pendingCount: Int {
        pending.count
    }

    func enqueue(_ alert: UIAlertController, on presenter: UIViewController) {
        pending.append(Pending(presenter: presenter, alert: alert))
        drain()
    }

    private func drain() {
        guard drainTask == nil else { return }
        drainTask = Task { [weak self] in
            while let self, presentNext() == false {
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
            self?.drainTask = nil
        }
    }

    /// Presents the next alert when possible.
    /// - Returns: `true` when the queue is empty, `false` when it must try again later.
    private func presentNext() -> Bool {
        if let showing, showing.presentingViewController != nil {
            return false
        }
        showing = nil
        pending.removeAll { $0.presenter == nil }
        guard let next = pending.first, let presenter = next.presenter else {
            return pending.isEmpty
        }
        guard presenter.viewIfLoaded?.window != nil else {
            // The screen that asked for this alert is gone; nobody is left to answer it.
            pending.removeFirst()
            return pending.isEmpty
        }
        guard presenter.presentedViewController == nil else {
            return false
        }
        pending.removeFirst()
        showing = next.alert
        presenter.present(next.alert, animated: true)
        return false
    }
}

extension UIViewController {
    /// Presents `alert` after any alert this app is already showing has been dismissed.
    func presentQueued(_ alert: UIAlertController) {
        AlertQueue.shared.enqueue(alert, on: self)
    }

    /// Shows a single-button informational alert through the alert queue.
    func presentInfoAlert(title: String, message: String?) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        presentQueued(alert)
    }
}
