import ConfigurableKit
import UIKit

/// The full app's card detail, plus the system banner that offers the full app.
final class ClipCardDetailViewController: CardDetailViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // Room below the last row so it can scroll clear of the banner.
        scrollView.contentInset.bottom += ClipStoreOverlay.clearance
        scrollView.verticalScrollIndicatorInsets.bottom += ClipStoreOverlay.clearance
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        ClipStoreOverlay.shared.present(in: view.window?.windowScene)
    }
}
