import UIKit

class ReorderableTableViewDiffableDataSource<SectionIdentifierType: Hashable, ItemIdentifierType: Hashable>:
    UITableViewDiffableDataSource<SectionIdentifierType, ItemIdentifierType>
{
    var canReorderItem: ((ItemIdentifierType) -> Bool)?
    var onReorderedItems: (([ItemIdentifierType]) -> Void)?

    override func tableView(_: UITableView, canMoveRowAt indexPath: IndexPath) -> Bool {
        guard let item = itemIdentifier(for: indexPath) else { return false }
        return canReorderItem?(item) ?? true
    }

    override func tableView(
        _: UITableView,
        moveRowAt sourceIndexPath: IndexPath,
        to destinationIndexPath: IndexPath
    ) {
        guard let fromItem = itemIdentifier(for: sourceIndexPath),
              sourceIndexPath != destinationIndexPath
        else { return }

        var snap = snapshot()
        snap.deleteItems([fromItem])

        if let toItem = itemIdentifier(for: destinationIndexPath) {
            let isAfter = destinationIndexPath.row > sourceIndexPath.row
            if isAfter {
                snap.insertItems([fromItem], afterItem: toItem)
            } else {
                snap.insertItems([fromItem], beforeItem: toItem)
            }
        } else if let section = snap.sectionIdentifiers[safe: sourceIndexPath.section] {
            snap.appendItems([fromItem], toSection: section)
        }

        onReorderedItems?(snap.itemIdentifiers)
        apply(snap, animatingDifferences: false)
    }
}
