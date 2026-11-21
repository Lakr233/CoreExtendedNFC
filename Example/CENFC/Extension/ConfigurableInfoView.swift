import ConfigurableKit
import SnapKit
import UIKit

class ConfigurableInfoView: ConfigurableView {
    var valueLabel: EasyHitButton {
        contentView as! EasyHitButton
    }

    private var onTapBlock: ((ConfigurableInfoView) -> Void) = { _ in }

    override init() {
        super.init()
        valueLabel.titleLabel?.font = .preferredFont(forTextStyle: .subheadline)
        valueLabel.titleLabel?.numberOfLines = 1
        valueLabel.titleLabel?.lineBreakMode = .byTruncatingMiddle
        valueLabel.titleLabel?.textAlignment = .right
        valueLabel.contentHorizontalAlignment = .right
        // ConfigurableKit keeps the value beside the title only while it fits
        // there in full, and otherwise moves it to its own line under the title
        // where it wraps. Beside the title it gets its whole width; the title
        // and explanation take what is left.
        valueLabel.setContentCompressionResistancePriority(.required - 1, for: .horizontal)
        valueLabel.setContentHuggingPriority(.required, for: .horizontal)
        valueLabel.addTarget(self, action: #selector(tapped), for: .touchUpInside)
        valueLabel.snp.makeConstraints {
            $0.top.bottom.equalTo(contentContainer)
            $0.leading.greaterThanOrEqualTo(contentContainer)
            $0.trailing.equalTo(contentContainer)
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
    }

    private var valueFont: UIFont {
        .systemFont(ofSize: UIFont.preferredFont(forTextStyle: .subheadline, compatibleWith: traitCollection).pointSize, weight: .semibold)
    }

    func configure(value: String, isDestructive: Bool = false) {
        let attrString = NSAttributedString(
            string: value,
            attributes: [
                .foregroundColor: isDestructive ? UIColor.systemRed : UIColor.tintColor,
                .font: valueFont,
                .underlineStyle: NSUnderlineStyle.single.rawValue,
            ])
        valueLabel.setAttributedTitle(attrString, for: .normal)
        setNeedsLayout()
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
