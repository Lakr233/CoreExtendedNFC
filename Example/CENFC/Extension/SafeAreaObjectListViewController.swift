import ConfigurableKit
import UIKit

/// `ObjectListViewController` whose separators stay inside the left and right
/// safe area and whose rows re-measure when edit mode starts or ends.
///
/// Two ConfigurableKit 4.2.0 behaviours, worked around here rather than in the
/// package (see `notes/cenfc-duo-safe-area/configurablekit-root-cause.md`):
/// - `viewDidLoad` sets `tableView.separatorInset = .zero`, measured from the
///   cell edges, so separators run the full table width, under the iPhone Duo's
///   vertical status bar and tab bar.
/// - `setEditing(_:animated:)` toggles the table's edit mode without
///   re-measuring its self-sizing rows. The selection circle and reorder
///   control narrow each row, its description wraps onto more lines, and the
///   row keeps its old height, so the title is pushed above the row and clipped.
class SafeAreaObjectListViewController<DataSource: ObjectListDataSource>: ObjectListViewController<DataSource>
    where DataSource.Item.ID == UUID
{
    override func viewSafeAreaInsetsDidChange() {
        super.viewSafeAreaInsetsDidChange()
        tableView.insetSeparatorsToHorizontalSafeArea()
    }

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
        tableView.remeasureRows(animated: animated)
    }
}

extension UITableView {
    /// Keeps edge-to-edge separators (`separatorInset == .zero`) between the
    /// left and right safe area insets; with no side insets nothing changes.
    func insetSeparatorsToHorizontalSafeArea() {
        let insets = UIEdgeInsets(top: 0, left: safeAreaInsets.left, bottom: 0, right: safeAreaInsets.right)
        guard separatorInset != insets else { return }
        separatorInset = insets
    }

    /// Asks the visible self-sizing rows for their heights again, for a change
    /// that alters their width without changing their content (edit mode).
    func remeasureRows(animated: Bool) {
        guard window != nil else { return }
        if animated {
            performBatchUpdates(nil)
        } else {
            UIView.performWithoutAnimation { performBatchUpdates(nil) }
        }
    }
}
