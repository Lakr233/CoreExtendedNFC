import ConfigurableKit
import UIKit

extension StackScrollController {
    func addSectionHeader(_ text: String) {
        stackView.addArrangedSubviewWithMargin(
            ConfigurableSectionHeaderView().with(rawHeader: text)
        ) { $0.bottom /= 2 }
        stackView.addArrangedSubview(SeparatorView())
    }

    func addSectionFooter(_ text: String) {
        #if APPCLIP
            // The App Clip leaves the explanations to the full app.
            _ = text
        #else
            stackView.addArrangedSubviewWithMargin(
                ConfigurableSectionFooterView().with(rawFooter: text)
            ) { $0.top /= 2 }
            stackView.addArrangedSubview(SeparatorView())
        #endif
    }
}
