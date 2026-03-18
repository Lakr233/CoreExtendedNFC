//
//  FeatureRowView.swift
//  CENFC
//

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
        hStack.translatesAutoresizingMaskIntoConstraints = false

        addSubview(hStack)
        NSLayoutConstraint.activate([
            hStack.topAnchor.constraint(equalTo: topAnchor),
            hStack.bottomAnchor.constraint(equalTo: bottomAnchor),
            hStack.leadingAnchor.constraint(equalTo: leadingAnchor),
            hStack.trailingAnchor.constraint(equalTo: trailingAnchor),
        ])

        iconView.contentMode = .scaleAspectFit
        iconView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: 28),
            iconView.heightAnchor.constraint(equalToConstant: 28),
        ])

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
        titleLabel.text = String(localized: feature.title)
        detailLabel.text = String(localized: feature.detail)
    }
}

private extension UIFont {
    func withTraits(_ traits: UIFontDescriptor.SymbolicTraits) -> UIFont {
        guard let descriptor = fontDescriptor.withSymbolicTraits(traits) else { return self }
        return UIFont(descriptor: descriptor, size: 0)
    }
}
