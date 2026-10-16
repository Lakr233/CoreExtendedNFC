import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import SPIndicator
import Then
import UIKit
import UniformTypeIdentifiers

class PassportViewController: UIViewController, PrivacySensitiveScreen {
    nonisolated enum Section { case main }

    private let tableView = UITableView(frame: .zero, style: .plain)
    private let emptyState = EmptyStateView.scan()
    private var dataSource: ReorderableTableViewDiffableDataSource<Section, UUID>!

    private var currentSearchText: String {
        navigationItem.searchController?.searchBar.text ?? ""
    }

    /// The query the visible snapshot was built with. Reordering is only allowed
    /// while the table shows every record, because the store reorders the full list.
    private var appliedSearchText = ""

    private var isShowingAllRecords: Bool {
        appliedSearchText.isEmpty && currentSearchText.isEmpty
    }

    private lazy var scanBarButton: UIBarButtonItem = {
        let importAction = UIMenu(options: .displayInline, children: [
            UIAction(
                title: String(localized: "Import from File"),
                image: UIImage(systemName: "square.and.arrow.down")
            ) { [weak self] _ in self?.presentImportPicker() },
        ])

        let sortMenu = UIMenu(
            title: String(localized: "Sort By"),
            image: UIImage(systemName: "arrow.up.arrow.down"),
            children: [
                UIAction(
                    title: String(localized: "Date (Newest First)"),
                    image: UIImage(systemName: "calendar")
                ) { [weak self] _ in
                    PassportStore.shared.sort { $0.date > $1.date }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Date (Oldest First)"),
                    image: UIImage(systemName: "calendar.badge.clock")
                ) { [weak self] _ in
                    PassportStore.shared.sort { $0.date < $1.date }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Name"),
                    image: UIImage(systemName: "textformat")
                ) { [weak self] _ in
                    PassportStore.shared.sort {
                        $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
                    }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Document Number"),
                    image: UIImage(systemName: "number")
                ) { [weak self] _ in
                    PassportStore.shared.sort { ($0.passport.mrz?.documentNumber ?? "") < ($1.passport.mrz?.documentNumber ?? "") }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Nationality"),
                    image: UIImage(systemName: "flag")
                ) { [weak self] _ in
                    PassportStore.shared.sort {
                        ($0.passport.mrz?.nationality ?? "").localizedCaseInsensitiveCompare($1.passport.mrz?.nationality ?? "") == .orderedAscending
                    }
                    self?.reloadSnapshot()
                },
            ]
        )

        let sortSection = UIMenu(options: .displayInline, children: [sortMenu])

        let scanMenu = UIMenu(children: [importAction, sortSection])

        return UIBarButtonItem(
            image: UIImage(systemName: "plus.viewfinder"),
            primaryAction: UIAction { [weak self] _ in
                self?.pushMRZInput()
            },
            menu: scanMenu
        ).accessibilityLabeled(String(localized: "Read Passport"))
    }()

    private lazy var doneBarButton = UIBarButtonItem(
        image: UIImage(systemName: "checkmark.circle"),
        style: .plain,
        target: self,
        action: #selector(exitEditingMode)
    ).accessibilityLabeled(String(localized: "Done"))

    private lazy var deleteBarButton: UIBarButtonItem = {
        let button = UIBarButtonItem(
            image: UIImage(systemName: "trash"),
            style: .plain,
            target: self,
            action: #selector(deleteSelected)
        ).accessibilityLabeled(String(localized: "Delete"))
        button.tintColor = .systemRed
        return button
    }()

    private lazy var exportSelectedBarButton = UIBarButtonItem(
        image: UIImage(systemName: "square.and.arrow.up"),
        style: .plain,
        target: self,
        action: #selector(exportSelected)
    ).accessibilityLabeled(String(localized: "Export"))

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground

        setupTableView()
        setupDataSource()
        setupNavBar()
        setupSearch()
        emptyState.install(on: tableView)
        reloadSnapshot(animatingDifferences: false)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reloadSnapshot()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        emptyState.update(in: tableView)
    }

    // MARK: - Setup

    private func setupTableView() {
        tableView.do {
            $0.separatorStyle = .singleLine
            $0.separatorInset = .zero
            $0.backgroundColor = .clear
            $0.delegate = self
            $0.dragDelegate = self
            $0.dropDelegate = self
            $0.dragInteractionEnabled = true
            $0.allowsMultipleSelectionDuringEditing = true
            $0.register(PassportRecordCell.self, forCellReuseIdentifier: PassportRecordCell.reuseIdentifier)
        }
        view.addSubview(tableView)
        tableView.snp.makeConstraints { $0.edges.equalToSuperview() }
    }

    private func setupDataSource() {
        dataSource = .init(tableView: tableView) { tableView, indexPath, recordID in
            let cell = tableView.dequeueReusableCell(
                withIdentifier: PassportRecordCell.reuseIdentifier, for: indexPath
            ) as! PassportRecordCell
            if let record = PassportStore.shared.record(for: recordID) {
                cell.update(with: record)
            }
            return cell
        }
        dataSource.canReorderItem = { [weak self] _ in
            self?.isShowingAllRecords == true
        }
        dataSource.onReorderedItems = { [weak self] orderedIDs in
            AppLogStore.shared.info(
                "moveRow reconciled orderedIDs=\(orderedIDs.count)",
                source: "PassportReorder"
            )
            PassportStore.shared.reorder(by: orderedIDs)
            // If the store rejected the order, put the table back in sync with it.
            if PassportStore.shared.records.map(\.id) != orderedIDs {
                self?.reloadSnapshot()
            }
        }
        dataSource.defaultRowAnimation = .fade
    }

    private func setupNavBar() {
        navigationItem.rightBarButtonItem = scanBarButton
    }

    private func setupSearch() {
        let search = UISearchController(searchResultsController: nil).then {
            $0.delegate = self
            $0.searchBar.placeholder = String(localized: "Search by name or document number")
            $0.searchBar.autocapitalizationType = .none
            $0.searchBar.autocorrectionType = .no
            $0.searchBar.delegate = self
            $0.obscuresBackgroundDuringPresentation = false
            $0.hidesNavigationBarDuringPresentation = false
        }
        navigationItem.searchController = search
        navigationItem.preferredSearchBarPlacement = .stacked
        navigationItem.hidesSearchBarWhenScrolling = false
    }

    // MARK: - Editing state (two-finger pan enters editing)

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
        tableView.setEditing(editing, animated: animated)
        updateEditingNavBar()
    }

    @objc private func exitEditingMode() {
        setEditing(false, animated: true)
    }

    private func updateEditingNavBar() {
        if tableView.isEditing {
            let hasSelection = (tableView.indexPathsForSelectedRows?.count ?? 0) > 0
            navigationItem.setLeftBarButton(hasSelection ? deleteBarButton : nil, animated: true)
            navigationItem.setRightBarButtonItems(
                hasSelection ? [doneBarButton, exportSelectedBarButton] : [doneBarButton],
                animated: true
            )
        } else {
            navigationItem.setLeftBarButton(nil, animated: true)
            navigationItem.setRightBarButtonItems([scanBarButton], animated: true)
        }
    }

    private func selectedRecords() -> [PassportRecord] {
        guard let indexPaths = tableView.indexPathsForSelectedRows else { return [] }
        return indexPaths.compactMap { indexPath in
            guard let id = dataSource.itemIdentifier(for: indexPath) else { return nil }
            return PassportStore.shared.record(for: id)
        }
    }

    @objc private func deleteSelected() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        let alert = UIAlertController(
            title: String(localized: "Delete \(records.count) Record(s)?"),
            message: String(localized: "This action cannot be undone."),
            preferredStyle: .actionSheet
        )
        alert.addAction(UIAlertAction(title: String(localized: "Delete"), style: .destructive) { [weak self] _ in
            for record in records {
                PassportStore.shared.remove(id: record.id)
            }
            self?.reloadSnapshot()
            self?.setEditing(false, animated: true)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        alert.popoverPresentationController?.barButtonItem = deleteBarButton
        present(alert, animated: true)
    }

    @objc private func exportSelected() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        do {
            let fileURLs = try records.map { try PassportDocument.exportToFile($0) }
            presentExportSheet(for: fileURLs, barButtonItem: exportSelectedBarButton)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Data Source

    func reloadSnapshot(animatingDifferences: Bool = true) {
        guard isViewLoaded else {
            AppLogStore.shared.debug(
                "reloadSnapshot deferred animated=\(animatingDifferences) viewLoaded=\(isViewLoaded)",
                source: "PassportReorder"
            )
            return
        }
        let query = currentSearchText
        let filtered = PassportStore.shared.records.filter { record in
            query.isEmpty
                || record.displayName.localizedCaseInsensitiveContains(query)
                || (record.passport.mrz?.documentNumber ?? "").localizedCaseInsensitiveContains(query)
        }
        AppLogStore.shared.debug(
            "reloadSnapshot searching=\(!query.isEmpty) total=\(PassportStore.shared.records.count) filtered=\(filtered.count) window=\(view.window != nil)",
            source: "PassportReorder"
        )
        var snapshot = NSDiffableDataSourceSnapshot<Section, UUID>()
        snapshot.appendSections([.main])
        snapshot.appendItems(filtered.map(\.id))
        // Records keep their ID when overwritten by an import, so refresh the cells too.
        snapshot.reconfigureItems(filtered.map(\.id))
        appliedSearchText = query
        dataSource.apply(snapshot, animatingDifferences: animatingDifferences)
        emptyState.isHidden = !PassportStore.shared.records.isEmpty
    }

    // MARK: - Navigation

    private func pushMRZInput() {
        let inputVC = PassportMRZInputViewController()
        inputVC.onPassportRead = { [weak self, weak inputVC] record in
            guard let self else { return }
            PassportStore.shared.add(record)
            reloadSnapshot()
            // Only replace the MRZ screen when it is still on top; the user may have
            // navigated elsewhere while the chip was being read.
            guard let navigationController,
                  let inputVC,
                  navigationController.topViewController === inputVC
            else { return }
            var stack = navigationController.viewControllers
            stack.removeLast()
            stack.append(PassportDetailViewController(record: record))
            navigationController.setViewControllers(stack, animated: true)
        }
        navigationController?.pushViewController(inputVC, animated: true)
    }

    // MARK: - Import

    private func presentImportPicker() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.cenfcPassport, .propertyList])
        picker.delegate = self
        picker.allowsMultipleSelection = true
        present(picker, animated: true)
    }

    func importFile(at url: URL) {
        Task {
            do {
                let record = try await ImportFileReader.readInBackground(url) { data in
                    try PassportDocument.importRecord(from: data)
                }
                importRecord(record)
            } catch {
                presentErrorAlert(for: error)
            }
        }
    }

    /// Adds an imported record, asking first when it would replace a stored
    /// record with the same document number.
    private func importRecord(_ record: PassportRecord) {
        guard let existing = PassportStore.shared.importConflict(for: record) else {
            PassportStore.shared.importRecord(record)
            reloadSnapshot()
            return
        }
        let alert = UIAlertController(
            title: String(localized: "Replace Passport Record?"),
            message: String(localized: "A record for \(existing.displayName) with the same document number is already saved. Replacing it discards the saved record, including its security results from reading the chip."),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Replace"), style: .destructive) { [weak self] _ in
            PassportStore.shared.importRecord(record, replacingExisting: true)
            self?.reloadSnapshot()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Keep Both"), style: .default) { [weak self] _ in
            PassportStore.shared.importRecord(record, replacingExisting: false)
            self?.reloadSnapshot()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        presentQueued(alert)
    }

    // MARK: - Export

    private func exportRecord(_ record: PassportRecord) {
        do {
            let fileURL = try PassportDocument.exportToFile(record)
            presentExportSheet(for: [fileURL])
        } catch {
            presentErrorAlert(for: error)
        }
    }
}

// MARK: - UITableViewDelegate

extension PassportViewController: UITableViewDelegate {
    func scrollViewDidScroll(_ scrollView: UIScrollView) {
        emptyState.update(in: scrollView)
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
            return
        }
        tableView.deselectRow(at: indexPath, animated: true)
        guard let recordID = dataSource.itemIdentifier(for: indexPath),
              let record = PassportStore.shared.record(for: recordID)
        else { return }
        navigationController?.pushViewController(
            PassportDetailViewController(record: record), animated: true
        )
    }

    func tableView(_ tableView: UITableView, didDeselectRowAt _: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
        }
    }

    func tableView(
        _: UITableView,
        trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath
    ) -> UISwipeActionsConfiguration? {
        guard !tableView.isEditing else { return nil }
        guard let recordID = dataSource.itemIdentifier(for: indexPath) else { return nil }
        let delete = UIContextualAction(style: .destructive, title: String(localized: "Delete")) { [weak self] _, _, completion in
            PassportStore.shared.remove(id: recordID)
            self?.reloadSnapshot()
            completion(true)
        }
        delete.image = UIImage(systemName: "trash")
        return UISwipeActionsConfiguration(actions: [delete])
    }

    func tableView(
        _: UITableView,
        contextMenuConfigurationForRowAt indexPath: IndexPath,
        point _: CGPoint
    ) -> UIContextMenuConfiguration? {
        guard !tableView.isEditing else { return nil }
        guard let recordID = dataSource.itemIdentifier(for: indexPath),
              let record = PassportStore.shared.record(for: recordID)
        else { return nil }
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            UIMenu(children: [
                UIAction(
                    title: String(localized: "Copy Document Number"),
                    image: UIImage(systemName: "doc.on.doc")
                ) { _ in
                    SensitivePasteboard.copy(record.passport.mrz?.documentNumber ?? "")
                    SPIndicator.present(
                        title: String(localized: "Copied"),
                        preset: .done,
                        haptic: .success
                    )
                },
                UIAction(
                    title: String(localized: "Export"),
                    image: UIImage(systemName: "square.and.arrow.up")
                ) { _ in
                    self?.exportRecord(record)
                },
                UIAction(
                    title: String(localized: "Delete"),
                    image: UIImage(systemName: "trash"),
                    attributes: [.destructive]
                ) { [weak self] _ in
                    PassportStore.shared.remove(id: recordID)
                    self?.reloadSnapshot()
                },
            ])
        }
    }

    // Two-finger pan gesture automatically enters editing mode on UITableView
    // when allowsMultipleSelectionDuringEditing = true (iOS 13+).

    func tableView(_: UITableView, shouldBeginMultipleSelectionInteractionAt _: IndexPath) -> Bool {
        true
    }

    func tableView(_: UITableView, didBeginMultipleSelectionInteractionAt _: IndexPath) {
        setEditing(true, animated: true)
    }

    func tableViewDidEndMultipleSelectionInteraction(_: UITableView) {
        // Keep editing mode active until user explicitly exits
    }
}

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

// MARK: - UIDocumentPickerDelegate

extension PassportViewController: UIDocumentPickerDelegate {
    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            importFile(at: url)
        }
    }
}

// MARK: - UITableViewDragDelegate

extension PassportViewController: UITableViewDragDelegate {
    func tableView(
        _: UITableView,
        itemsForBeginning _: UIDragSession,
        at indexPath: IndexPath
    ) -> [UIDragItem] {
        guard view.window != nil, tableView.window != nil else {
            AppLogStore.shared.warning("drag begin blocked because table/view is not in a window", source: "PassportReorder")
            return []
        }
        guard isShowingAllRecords else {
            AppLogStore.shared.warning(
                "drag begin blocked by active search",
                source: "PassportReorder"
            )
            return []
        }
        guard let recordID = dataSource.itemIdentifier(for: indexPath) else { return [] }
        AppLogStore.shared.debug(
            "drag begin row=\(indexPath.row) id=\(recordID.uuidString)",
            source: "PassportReorder"
        )
        let provider = NSItemProvider(object: recordID.uuidString as NSString)
        let item = UIDragItem(itemProvider: provider)
        item.localObject = recordID
        return [item]
    }
}

// MARK: - UITableViewDropDelegate

extension PassportViewController: UITableViewDropDelegate {
    func tableView(
        _: UITableView,
        canHandle session: UIDropSession
    ) -> Bool {
        session.localDragSession != nil
    }

    func tableView(
        _: UITableView,
        dropSessionDidUpdate session: UIDropSession,
        withDestinationIndexPath _: IndexPath?
    ) -> UITableViewDropProposal {
        guard view.window != nil, tableView.window != nil else {
            AppLogStore.shared.warning("drop update cancelled because table/view is not in a window", source: "PassportReorder")
            return UITableViewDropProposal(operation: .cancel)
        }
        guard session.localDragSession != nil else {
            return UITableViewDropProposal(operation: .cancel)
        }
        guard isShowingAllRecords else {
            AppLogStore.shared.warning(
                "drop update forbidden due to active search",
                source: "PassportReorder"
            )
            return UITableViewDropProposal(operation: .forbidden)
        }
        AppLogStore.shared.debug("drop update local move", source: "PassportReorder")
        return UITableViewDropProposal(operation: .move, intent: .insertAtDestinationIndexPath)
    }

    func tableView(
        _: UITableView,
        performDropWith _: UITableViewDropCoordinator
    ) {
        AppLogStore.shared.debug("performDrop local noop; datasource handles reorder", source: "PassportReorder")
    }
}
