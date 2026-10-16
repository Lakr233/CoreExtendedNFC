import SnapKit
import UIKit
import UniformTypeIdentifiers

/// A screen that shows identity-document data (passport list, MRZ entry,
/// passport detail).
///
/// Such screens copy to the pasteboard with ``SensitivePasteboard`` and are
/// hidden behind ``PrivacyCover`` while the app is inactive, so the app
/// switcher snapshot does not show them.
@MainActor
protocol PrivacySensitiveScreen: AnyObject {}

/// Copies personal data so it stays on this device and expires.
@MainActor
enum SensitivePasteboard {
    /// How long copied passport data stays on the pasteboard.
    static let lifetime: TimeInterval = 120

    /// Pasteboard options: not shared through Universal Clipboard, removed after ``lifetime``.
    static func options(now: Date = Date()) -> [UIPasteboard.OptionsKey: Any] {
        [
            .localOnly: true,
            .expirationDate: now.addingTimeInterval(lifetime),
        ]
    }

    static func copy(_ string: String, to pasteboard: UIPasteboard = .general, now: Date = Date()) {
        pasteboard.setItems(
            [[UTType.utf8PlainText.identifier: string]],
            options: options(now: now)
        )
    }
}

/// Covers the window while a ``PrivacySensitiveScreen`` is on screen and the
/// scene is inactive (app switcher, Control Center, incoming call, NFC sheet).
@MainActor
final class PrivacyCover {
    private weak var coverView: UIView?

    var isShown: Bool {
        coverView != nil
    }

    /// Covers `window` when it is showing a privacy-sensitive screen.
    func show(in window: UIWindow) {
        guard coverView == nil,
              let root = window.rootViewController,
              Self.isShowingSensitiveContent(root)
        else { return }
        let cover = Self.makeCoverView()
        window.addSubview(cover)
        cover.snp.makeConstraints { $0.edges.equalToSuperview() }
        coverView = cover
    }

    func hide() {
        coverView?.removeFromSuperview()
        coverView = nil
    }

    /// Whether the visible part of the hierarchy under `controller` includes a
    /// ``PrivacySensitiveScreen``.
    ///
    /// A navigation stack counts as sensitive when any screen in it is, so a hex
    /// dump or Quick Look preview opened from a passport stays covered.
    static func isShowingSensitiveContent(_ controller: UIViewController) -> Bool {
        if controller is PrivacySensitiveScreen {
            return true
        }
        if let presented = controller.presentedViewController,
           isShowingSensitiveContent(presented)
        {
            return true
        }
        if let navigation = controller as? UINavigationController {
            return navigation.viewControllers.contains { isShowingSensitiveContent($0) }
        }
        if let tabBar = controller as? UITabBarController {
            return tabBar.selectedViewController.map(isShowingSensitiveContent) ?? false
        }
        return controller.children.contains { isShowingSensitiveContent($0) }
    }

    private static func makeCoverView() -> UIView {
        let cover = UIView()
        cover.backgroundColor = .systemBackground
        let icon = UIImageView(image: UIImage(systemName: "lock.fill"))
        icon.tintColor = .secondaryLabel
        icon.contentMode = .scaleAspectFit
        cover.addSubview(icon)
        icon.snp.makeConstraints { make in
            make.center.equalToSuperview()
            make.width.height.equalTo(44)
        }
        return cover
    }
}
