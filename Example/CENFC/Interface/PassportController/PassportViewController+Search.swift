import UIKit

// MARK: - Search

extension PassportViewController: UISearchControllerDelegate, UISearchBarDelegate {
    func searchBar(_: UISearchBar, textDidChange _: String) {
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(commitSearch), object: nil)
        perform(#selector(commitSearch), with: nil, afterDelay: 0.25)
    }

    @objc private func commitSearch() {
        reloadSnapshot()
    }

    // Tapping Cancel clears the text programmatically without calling
    // `searchBar(_:textDidChange:)`, so refresh the list here as well.
    func searchBarCancelButtonClicked(_: UISearchBar) {
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(commitSearch), object: nil)
        reloadSnapshot()
    }

    func didDismissSearchController(_: UISearchController) {
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(commitSearch), object: nil)
        reloadSnapshot()
    }
}
