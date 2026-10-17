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
///
/// The cover is a separate window at ``windowLevel``, above alerts, so an
/// alert or sheet presented while the scene is inactive still ends up below it.
@MainActor
final class PrivacyCover {
    /// Above alerts and every modal presented in the app window.
    static let windowLevel = UIWindow.Level.alert + 1

    private(set) var coverWindow: UIWindow?

    var isShown: Bool {
        coverWindow != nil
    }

    /// Covers the scene of `window` when it is showing a privacy-sensitive screen.
    func show(over window: UIWindow) {
        guard coverWindow == nil,
              let scene = window.windowScene,
              let root = window.rootViewController,
              Self.isShowingSensitiveContent(root)
        else { return }
        let cover = UIWindow(windowScene: scene)
        cover.windowLevel = Self.windowLevel
        let controller = UIViewController()
        controller.view = Self.makeCoverView()
        cover.rootViewController = controller
        // Shown without becoming key, so focus returns to the app window.
        cover.isHidden = false
        coverWindow = cover
    }

    func hide() {
        coverWindow?.isHidden = true
        coverWindow?.rootViewController = nil
        coverWindow = nil
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
        // A split view counts both columns, whether expanded or collapsed (the
        // detail column's screens then sit on the list's stack). Its children are
        // checked too, in case a column is not reported.
        if let split = controller as? UISplitViewController, split.style != .unspecified {
            let columns = [UISplitViewController.Column.primary, .secondary].compactMap { split.viewController(for: $0) }
            if columns.contains(where: { isShowingSensitiveContent($0) }) {
                return true
            }
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
