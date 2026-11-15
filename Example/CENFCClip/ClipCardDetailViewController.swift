import ConfigurableKit
import StoreKit
import UIKit

/// The full app's card detail, plus the system banner that offers the full app.
final class ClipCardDetailViewController: CardDetailViewController {
    /// Room below the last row so it can scroll clear of the banner.
    private static let bannerClearance: CGFloat = 120

    override func viewDidLoad() {
        super.viewDidLoad()
        scrollView.contentInset.bottom += Self.bannerClearance
        scrollView.verticalScrollIndicatorInsets.bottom += Self.bannerClearance
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard let scene = view.window?.windowScene else { return }
        let overlay = SKOverlay(configuration: SKOverlay.AppClipConfiguration(position: .bottom))
        overlay.present(in: scene)
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if let scene = view.window?.windowScene {
            SKOverlay.dismiss(in: scene)
        }
    }
}
