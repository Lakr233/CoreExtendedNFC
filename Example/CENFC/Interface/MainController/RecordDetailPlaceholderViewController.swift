import SnapKit
import UIKit

/// Fills the detail column of a list tab's split view while no record is open.
///
/// Uses the same ``EmptyStateView`` look as the empty lists.
final class RecordDetailPlaceholderViewController: UIViewController {
    private let emptyState = EmptyStateView(
        message: String(localized: "Select a record to see its details.")
    )

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never

        view.addSubview(emptyState)
        emptyState.snp.makeConstraints { make in
            make.edges.equalTo(view.safeAreaLayoutGuide)
        }
    }
}
