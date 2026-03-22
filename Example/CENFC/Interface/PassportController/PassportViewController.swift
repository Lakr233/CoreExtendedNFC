import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import SPIndicator
import Then
import UIKit
import UniformTypeIdentifiers

class PassportViewController: UIViewController {
    nonisolated enum Section { case main }

    private let tableView = UITableView(frame: .zero, style: .plain)
    private var dataSource: ReorderableTableViewDiffableDataSource<Section, UUID>!
    private var pendingSnapshotReload = false
    private var pendingSnapshotAnimated = true

    private var currentSearchText: String {
        navigationItem.searchController?.searchBar.text ?? ""
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
        )
    }()

    private lazy var doneBarButton = UIBarButtonItem(
        image: UIImage(systemName: "checkmark.circle"),
        style: .plain,
        target: self,
        action: #selector(exitEditingMode)
    )

    private lazy var deleteBarButton: UIBarButtonItem = {
        let button = UIBarButtonItem(
            image: UIImage(systemName: "trash"),
            style: .plain,
            target: self,
            action: #selector(deleteSelected)
        )
        button.tintColor = .systemRed
        return button
    }()

    private lazy var exportSelectedBarButton = UIBarButtonItem(
        image: UIImage(systemName: "square.and.arrow.up"),
        style: .plain,
        target: self,
        action: #selector(exportSelected)
    )

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground

        setupTableView()
        setupDataSource()
        setupNavBar()
        setupSearch()
        reloadSnapshot(animatingDifferences: false)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reloadSnapshot()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        flushPendingSnapshotReloadIfNeeded()
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
            self?.currentSearchText.isEmpty == true
        }
        dataSource.onReorderedItems = { orderedIDs in
            AppLogStore.shared.info(
                "moveRow reconciled orderedIDs=\(orderedIDs.count)",
                source: "PassportReorder"
            )
            PassportStore.shared.reorder(by: orderedIDs)
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
        alert.popoverPresentationController?.sourceView = view
        present(alert, animated: true)
    }

    @objc private func exportSelected() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        do {
            let fileURLs = try records.map { try PassportDocument.exportToFile($0) }
            let activity = UIActivityViewController(activityItems: fileURLs, applicationActivities: nil)
            activity.popoverPresentationController?.barButtonItem = exportSelectedBarButton
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Data Source

    func reloadSnapshot(animatingDifferences: Bool = true) {
        guard isViewLoaded else {
            pendingSnapshotReload = true
            pendingSnapshotAnimated = pendingSnapshotAnimated || animatingDifferences
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
            "reloadSnapshot query='\(query)' total=\(PassportStore.shared.records.count) filtered=\(filtered.count) window=\(view.window != nil)",
            source: "PassportReorder"
        )
        var snapshot = NSDiffableDataSourceSnapshot<Section, UUID>()
        snapshot.appendSections([.main])
        snapshot.appendItems(filtered.map(\.id))
        dataSource.apply(snapshot, animatingDifferences: animatingDifferences)
    }

    private func flushPendingSnapshotReloadIfNeeded() {
        guard pendingSnapshotReload, isViewLoaded else { return }
        let animated = pendingSnapshotAnimated
        pendingSnapshotReload = false
        pendingSnapshotAnimated = true
        AppLogStore.shared.debug(
            "flushing deferred snapshot animated=\(animated)",
            source: "PassportReorder"
        )
        reloadSnapshot(animatingDifferences: animated)
    }

    // MARK: - Navigation

    private func pushMRZInput() {
        let inputVC = PassportMRZInputViewController()
        inputVC.onPassportRead = { [weak self] record in
            PassportStore.shared.add(record)
            self?.reloadSnapshot()
            self?.navigationController?.popViewController(animated: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                let detail = PassportDetailViewController(record: record)
                self?.navigationController?.pushViewController(detail, animated: true)
            }
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
        do {
            let record = try PassportDocument.importRecord(from: url)
            if let existing = PassportStore.shared.record(withDocumentNumber: record.passport.mrz?.documentNumber ?? "") {
                PassportStore.shared.replace(existing.id, with: record)
            } else {
                PassportStore.shared.add(record)
            }
            reloadSnapshot()
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Export

    private func exportRecord(_ record: PassportRecord) {
        do {
            let fileURL = try PassportDocument.exportToFile(record)
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = view
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Errors

    private func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Error"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }
}

// MARK: - UITableViewDelegate

extension PassportViewController: UITableViewDelegate {
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
                    UIPasteboard.general.string = record.passport.mrz?.documentNumber ?? ""
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
        guard currentSearchText.isEmpty else {
            AppLogStore.shared.warning(
                "drag begin blocked by active search query='\(currentSearchText)'",
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
        guard currentSearchText.isEmpty else {
            AppLogStore.shared.warning(
                "drop update forbidden due to active search query='\(currentSearchText)'",
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
