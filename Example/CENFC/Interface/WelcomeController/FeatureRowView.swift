//
//  FeatureRowView.swift
//  CENFC
//

import SnapKit
import UIKit

class FeatureRowView: UIView {
    private let iconView = UIImageView()
    private let titleLabel = UILabel()
    private let detailLabel = UILabel()

    init() {
        super.init(frame: .zero)
        setupViews()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    private func setupViews() {
        let contentStack = UIStackView(arrangedSubviews: [titleLabel, detailLabel])
        contentStack.axis = .vertical
        contentStack.spacing = 2
        contentStack.alignment = .leading

        let hStack = UIStackView(arrangedSubviews: [iconView, contentStack])
        hStack.axis = .horizontal
        hStack.spacing = 14
        hStack.alignment = .center

        addSubview(hStack)
        hStack.snp.makeConstraints { make in
            make.edges.equalToSuperview()
        }

        iconView.contentMode = .scaleAspectFit
        iconView.snp.makeConstraints { make in
            make.size.equalTo(28)
        }

        titleLabel.font = .preferredFont(forTextStyle: .subheadline).withTraits(.traitBold)
        titleLabel.textColor = .label
        titleLabel.numberOfLines = 1

        detailLabel.font = .preferredFont(forTextStyle: .footnote)
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 0
    }

    func configure(feature: WelcomePageViewController.Feature, accentColor: UIColor) {
        iconView.image = feature.icon.applyingSymbolConfiguration(
            .init(pointSize: 16, weight: .medium)
        )
        iconView.tintColor = accentColor
        titleLabel.text = feature.title
        detailLabel.text = feature.detail
    }
}

private extension UIFont {
    func withTraits(_ traits: UIFontDescriptor.SymbolicTraits) -> UIFont {
        guard let descriptor = fontDescriptor.withSymbolicTraits(traits) else { return self }
        return UIFont(descriptor: descriptor, size: 0)
    }
}
