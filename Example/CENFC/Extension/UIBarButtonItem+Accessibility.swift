import UIKit

extension UIBarButtonItem {
    /// Names an icon button: sets its title and VoiceOver label, keeps its image,
    /// and returns the button.
    ///
    /// Horizontal bars still show only the symbol. The title is what overflow
    /// menus and vertical bars (iPhone Duo) show next to the symbol. Without a
    /// label VoiceOver reads the SF Symbol name ("plus viewfinder") or nothing at all.
    func accessibilityLabeled(_ label: String) -> UIBarButtonItem {
        title = label
        accessibilityLabel = label
        return self
    }
}
