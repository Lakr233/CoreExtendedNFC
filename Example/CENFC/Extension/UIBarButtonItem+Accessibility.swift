import UIKit

extension UIBarButtonItem {
    /// Sets the VoiceOver label of an icon-only button and returns the button.
    ///
    /// Without a label VoiceOver reads the SF Symbol name ("plus viewfinder")
    /// or nothing at all.
    func accessibilityLabeled(_ label: String) -> UIBarButtonItem {
        accessibilityLabel = label
        return self
    }
}
