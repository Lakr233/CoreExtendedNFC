import UIKit

/// Presents alerts one after another.
///
/// UIKit ignores `present(_:animated:)` while the presenter is already showing
/// something, so back-to-back alerts (an info alert followed by a prompt, or one
/// prompt per imported file) would silently drop everything but the first.
/// The queue waits until the previous alert is dismissed and the presenter is
/// free before presenting the next one. An alert waits while its presenter is
/// off screen (another tab, mid-transition) and is discarded only when the
/// presenter is gone for good: deallocated, or removed from its parent and not
/// presented by anything. A presentation UIKit refuses is retried.
@MainActor
final class AlertQueue {
    static let shared = AlertQueue()

    private struct Pending {
        weak var presenter: UIViewController?
        let alert: UIAlertController
    }

    private var pending: [Pending] = []
    /// The alert last handed to UIKit.
    private var showing: Pending?
    /// Whether UIKit actually started presenting ``showing``.
    private var showingConfirmed = false
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
        if let current = showing {
            if current.alert.presentingViewController != nil {
                showingConfirmed = true
                return false
            }
            if !showingConfirmed {
                // UIKit refused the presentation (presenter busy or mid-transition): try again.
                pending.insert(current, at: 0)
            }
            showing = nil
        }
        pending.removeAll { $0.presenter.map(Self.isGone) ?? true }
        guard let next = pending.first, let presenter = next.presenter else {
            return pending.isEmpty
        }
        guard presenter.viewIfLoaded?.window != nil,
              presenter.presentedViewController == nil
        else {
            return false
        }
        pending.removeFirst()
        showing = next
        showingConfirmed = false
        presenter.present(next.alert, animated: true)
        if next.alert.presentingViewController != nil {
            showingConfirmed = true
        }
        return false
    }

    /// Whether `presenter` has left the interface for good, so nobody is left to answer its alert.
    static func isGone(_ presenter: UIViewController) -> Bool {
        presenter.viewIfLoaded?.window == nil
            && presenter.parent == nil
            && presenter.presentingViewController == nil
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
