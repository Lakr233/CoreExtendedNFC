import ConfigurableKit
import SnapKit
import UIKit

class ConfigurableInfoView: ConfigurableView {
    var valueLabel: EasyHitButton {
        contentView as! EasyHitButton
    }

    private var onTapBlock: ((ConfigurableInfoView) -> Void) = { _ in }
    private var wrappedValueHeight: Constraint?

    override init() {
        super.init()
        valueLabel.titleLabel?.font = .preferredFont(forTextStyle: .subheadline)
        valueLabel.titleLabel?.numberOfLines = 1
        valueLabel.titleLabel?.lineBreakMode = .byTruncatingMiddle
        valueLabel.titleLabel?.textAlignment = .right
        valueLabel.contentHorizontalAlignment = .right
        valueLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        valueLabel.setContentHuggingPriority(.required, for: .horizontal)
        verticalStack.setContentCompressionResistancePriority(.required, for: .horizontal)
        verticalStack.setContentHuggingPriority(.defaultLow, for: .horizontal)
        valueLabel.addTarget(self, action: #selector(tapped), for: .touchUpInside)
        valueLabel.snp.makeConstraints {
            wrappedValueHeight = $0.height.greaterThanOrEqualTo(0).constraint
            $0.top.bottom.equalTo(contentContainer)
            $0.leading.greaterThanOrEqualTo(contentContainer)
            $0.trailing.equalTo(contentContainer)
        }
        contentContainer.snp.makeConstraints {
            $0.width.lessThanOrEqualTo(self).multipliedBy(0.5)
        }
    }

    override func layoutSubviews() {
        if let title = valueLabel.attributedTitle(for: .normal), title.length > 0,
            let font = title.attribute(.font, at: 0, effectiveRange: nil) as? UIFont,
            font.pointSize != valueFont.pointSize
        {
            let scaled = NSMutableAttributedString(attributedString: title)
            scaled.addAttribute(.font, value: valueFont, range: NSRange(location: 0, length: scaled.length))
            valueLabel.setAttributedTitle(scaled, for: .normal)
        }
        super.layoutSubviews()
        valueLabel.layoutIfNeeded()
        if let label = valueLabel.titleLabel, label.numberOfLines == 0, label.bounds.width > 0 {
            // UIButton keeps a single-line intrinsic height even when its title wraps.
            let height = label.sizeThatFits(CGSize(width: label.bounds.width, height: .greatestFiniteMagnitude)).height
            wrappedValueHeight?.update(offset: ceil(height))
        }
    }

    private var valueFont: UIFont {
        .systemFont(ofSize: UIFont.preferredFont(forTextStyle: .subheadline, compatibleWith: traitCollection).pointSize, weight: .semibold)
    }

    func configure(value: String, isDestructive: Bool = false, wrapValue: Bool = false) {
        valueLabel.titleLabel?.numberOfLines = wrapValue ? 0 : 1
        valueLabel.titleLabel?.lineBreakMode = wrapValue ? .byCharWrapping : .byTruncatingMiddle
        if wrapValue {
            valueLabel.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
            verticalStack.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        }
        let attrString = NSAttributedString(
            string: value,
            attributes: [
                .foregroundColor: isDestructive ? UIColor.systemRed : UIColor.tintColor,
                .font: valueFont,
                .underlineStyle: NSUnderlineStyle.single.rawValue,
            ])
        valueLabel.setAttributedTitle(attrString, for: .normal)
    }

    @discardableResult
    func setTapBlock(_ block: @escaping (ConfigurableInfoView) -> Void) -> Self {
        onTapBlock = block
        return self
    }

    @objc private func tapped() {
        onTapBlock(self)
    }

    override class func createContentView() -> UIView {
        EasyHitButton()
    }

    func use(menu: @escaping () -> [UIMenuElement]) {
        valueLabel.removeTarget(self, action: #selector(tapped), for: .touchUpInside)
        valueLabel.showsMenuAsPrimaryAction = true
        valueLabel.menu = .init(children: [
            UIDeferredMenuElement.uncached { completion in
                completion(menu())
            }
        ])
    }
}
