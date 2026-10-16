import ConfigurableKit
import SPIndicator
import UIKit

extension StackScrollController {
    func addInfoRow(
        icon: String,
        title: String,
        description: String = "",
        value: String,
        isDestructive: Bool = false,
        wrapValue: Bool = false,
        extraMenuActions: [UIMenuElement] = []
    ) {
        let infoView = ConfigurableInfoView()
        infoView.configure(icon: UIImage(systemName: icon))
        infoView.configure(title: String.LocalizationValue(stringLiteral: title))
        infoView.configure(description: String.LocalizationValue(stringLiteral: description))
        infoView.configure(value: value, isDestructive: isDestructive, wrapValue: wrapValue)
        // Passport screens keep copied values on this device and let them expire.
        let copiesSensitively = self is PrivacySensitiveScreen
        infoView.use { [weak self] in
            let valueAction = UIAction(title: value, attributes: .disabled) { _ in }
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
