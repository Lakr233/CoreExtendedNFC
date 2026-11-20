import StoreKit
import UIKit

/// The system banner that offers the full app, shown at the bottom of every
/// App Clip screen (the App Clip has one scene).
///
/// Each screen asks for it when it appears. While a banner is already up, or
/// on its way up, nothing new is presented, so moving between the scan screen
/// and the result keeps the one banner instead of dropping and re-showing it.
/// Once someone swipes it away it comes back the next time a screen appears.
@MainActor
final class ClipStoreOverlay: NSObject {
    static let shared = ClipStoreOverlay()

    /// Room a screen leaves at its bottom so its content can clear the banner.
    static let clearance: CGFloat = 120

    private(set) var isShowing = false

    override private init() {
        super.init()
    }

    func present(in scene: UIWindowScene?) {
        guard let scene, !isShowing else { return }
        isShowing = true
        let overlay = SKOverlay(configuration: SKOverlay.AppClipConfiguration(position: .bottom))
        overlay.delegate = self
        overlay.present(in: scene)
    }
}

extension ClipStoreOverlay: @preconcurrency SKOverlayDelegate {
    func storeOverlayDidFinishDismissal(_: SKOverlay, transitionContext _: SKOverlay.TransitionContext) {
        isShowing = false
    }

    func storeOverlayDidFailToLoad(_: SKOverlay, error _: any Error) {
        isShowing = false
    }
}
