import ConfigurableKit
import SnapKit
import UIKit

extension StackScrollController {
    /// Re-pins scrollView top to view.topAnchor so content extends
    /// under the navigation bar, restoring the translucent blur effect.
    func enableExtendedEdge() {
        for constraint in view.constraints {
            guard constraint.firstItem === scrollView,
                  constraint.firstAnchor == scrollView.topAnchor,
                  constraint.secondItem === view.safeAreaLayoutGuide,
                  constraint.secondAnchor == view.safeAreaLayoutGuide.topAnchor
            else { continue }
            constraint.isActive = false
            break
        }
        scrollView.topAnchor.constraint(equalTo: view.topAnchor).isActive = true
    }

    /// Keeps the scroll view inside the horizontal safe area instead of the
    /// view's edges, so rows stay clear of a split view's list column (and of
    /// anything else the safe area reports). Safe to call more than once.
    func pinContentToHorizontalSafeArea() {
        let guide = view.safeAreaLayoutGuide
        var alreadyPinned = false
        for constraint in view.constraints where constraint.isActive {
            guard constraint.firstItem === scrollView else { continue }
            let anchor = constraint.firstAnchor
            guard anchor == scrollView.leadingAnchor || anchor == scrollView.trailingAnchor else { continue }
            if constraint.secondItem === guide {
                alreadyPinned = true
            } else if constraint.secondItem === view {
                constraint.isActive = false
            }
        }
        guard !alreadyPinned else { return }
        scrollView.snp.makeConstraints { make in
            make.leading.trailing.equalTo(guide)
        }
    }
}
