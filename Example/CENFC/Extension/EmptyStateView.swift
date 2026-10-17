import SnapKit
import UIKit

final class EmptyStateView: UIView {
    let label = UILabel()

    init(message: String) {
        super.init(frame: .zero)
        isUserInteractionEnabled = false

        label.text = message
        label.font = .preferredFont(forTextStyle: .footnote)
        label.adjustsFontForContentSizeCategory = true
        label.numberOfLines = 0
        label.textColor = .tertiaryLabel
        label.textAlignment = .center

        addSubview(label)
        label.snp.makeConstraints { make in
            make.center.equalToSuperview()
            // Pinned (not just bounded) so the text re-wraps to the full width
            // when the list column grows, e.g. after unfolding a foldable.
            make.leading.equalToSuperview().offset(40).priority(.high)
            make.trailing.equalToSuperview().offset(-40).priority(.high)
            make.leading.greaterThanOrEqualToSuperview()
            make.trailing.lessThanOrEqualToSuperview()
        }
    }

    override func layoutSubviews() {
        // A multi-line label keeps the wrap width it measured at; after the
        // view changes width (a foldable folding or unfolding) it would stay
        // wrapped to the old, narrower width. Re-measure against the new width.
        let wrapWidth = max(0, bounds.width - 80)
        if label.preferredMaxLayoutWidth != wrapWidth {
            label.preferredMaxLayoutWidth = wrapWidth
            label.invalidateIntrinsicContentSize()
        }
        super.layoutSubviews()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func install(on tableView: UITableView) {
        tableView.addSubview(self)
    }

    /// Reposition in content space and fade based on scroll offset.
    /// Call from both `viewDidLayoutSubviews` and `scrollViewDidScroll`.
    func update(in scrollView: UIScrollView) {
        let inset = scrollView.adjustedContentInset
        let visibleHeight = scrollView.bounds.height - inset.top - inset.bottom
        let newFrame = CGRect(x: 0, y: 0, width: scrollView.bounds.width, height: visibleHeight)
        if frame != newFrame {
            frame = newFrame
            layoutIfNeeded()
        }

        let offset = scrollView.contentOffset.y + inset.top
        alpha = max(0, 1 - abs(offset) / 60)
    }

    static func scan() -> EmptyStateView {
        EmptyStateView(
            message: String(localized: "Tap Scan to add a card. Touch and hold an item for options, or swipe with two fingers to select several.")
        )
    }
}
