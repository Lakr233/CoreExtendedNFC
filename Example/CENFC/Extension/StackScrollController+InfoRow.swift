import ConfigurableKit
import SPIndicator
import UIKit

extension StackScrollController {
    /// Adds a row showing `value` beside its title, or under it when it is too
    /// long to fit there. `descriptionStyle` overrides the page's
    /// `descriptionStyle` for this row, for an explanation people must read.
    func addInfoRow(
        icon: String,
        title: String,
        description: String = "",
        descriptionStyle: ConfigurableDescriptionStyle? = nil,
        value: String,
        isDestructive: Bool = false,
        extraMenuActions: [UIMenuElement] = []
    ) {
        let infoView = ConfigurableInfoView()
        infoView.configure(icon: UIImage(systemName: icon))
        infoView.configure(title: String.LocalizationValue(stringLiteral: title))
        #if APPCLIP
            // The App Clip shows the name and the whole value, without the explanation.
            infoView.configure(description: "")
        #else
            infoView.descriptionStyle = descriptionStyle
            infoView.configure(description: String.LocalizationValue(stringLiteral: description))
        #endif
        infoView.configure(value: value, isDestructive: isDestructive)
        // Passport screens keep copied values on this device and let them expire.
        let copiesSensitively = self is PrivacySensitiveScreen
        infoView.use { [weak self, weak infoView] in
            // Where the page hides the explanation, the value's menu still has it.
            let showsDescription = infoView?.effectiveDescriptionStyle == .full
            let valueAction = UIAction(
                title: value,
                subtitle: showsDescription || description.isEmpty ? nil : description,
                attributes: .disabled
            ) { _ in }
            let copyAction = UIAction(
                title: String(localized: "Copy"),
                image: UIImage(systemName: "doc.on.doc")
            ) { _ in
                if copiesSensitively {
                    SensitivePasteboard.copy(value)
                } else {
                    UIPasteboard.general.string = value
                }
                self?.showCopiedBanner()
            }
            return [
                valueAction,
                UIMenu(options: .displayInline, children: extraMenuActions + [copyAction]),
            ]
        }
        stackView.addArrangedSubviewWithMargin(infoView)
        stackView.addArrangedSubview(SeparatorView())
    }

    func showCopiedBanner() {
        SPIndicator.present(
            title: String(localized: "Copied"),
            preset: .done,
            haptic: .success
        )
    }
}
