import CoreExtendedNFC
import SnapKit
import SPIndicator
import Then
import UIKit
import UniformTypeIdentifiers

class DumpViewController: UIViewController {
    nonisolated enum Section { case main }

    private let tableView = UITableView(frame: .zero, style: .plain)
    private var dataSource: ReorderableTableViewDiffableDataSource<Section, UUID>!
    private var pendingSnapshotReload = false
    private var pendingSnapshotAnimated = true

    private lazy var dumpBarButton: UIBarButtonItem = {
        let protocolActions: [UIMenuElement] = [
            UIAction(
                title: String(localized: "All Protocols"),
                image: UIImage(systemName: "antenna.radiowaves.left.and.right")
            ) { [weak self] _ in self?.performDump(targets: [.all]) },
        ]

        let specificProtocols = UIMenu(options: .displayInline, children: [
            UIAction(
                title: String(localized: "ISO 14443"),
                image: UIImage(systemName: "wave.3.right")
            ) { [weak self] _ in self?.performDump(targets: [.iso14443]) },
            UIAction(
                title: String(localized: "ISO 18092"),
                image: UIImage(systemName: "dot.radiowaves.right")
            ) { [weak self] _ in self?.performDump(targets: [.iso18092]) },
            UIAction(
                title: String(localized: "ISO 15693"),
                image: UIImage(systemName: "barcode")
            ) { [weak self] _ in self?.performDump(targets: [.iso15693]) },
        ])

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
                    DumpStore.shared.sort { $0.date > $1.date }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Date (Oldest First)"),
                    image: UIImage(systemName: "calendar.badge.clock")
                ) { [weak self] _ in
                    DumpStore.shared.sort { $0.date < $1.date }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "Card Type"),
                    image: UIImage(systemName: "textformat")
                ) { [weak self] _ in
                    DumpStore.shared.sort { $0.dump.cardInfo.type.description.localizedCaseInsensitiveCompare($1.dump.cardInfo.type.description) == .orderedAscending }
                    self?.reloadSnapshot()
                },
                UIAction(
                    title: String(localized: "UID"),
                    image: UIImage(systemName: "number")
                ) { [weak self] _ in
                    DumpStore.shared.sort { $0.dump.cardInfo.uid.hexString < $1.dump.cardInfo.uid.hexString }
                    self?.reloadSnapshot()
                },
            ]
        )

        let sortSection = UIMenu(options: .displayInline, children: [sortMenu])

        let scanMenu = UIMenu(children: protocolActions + [specificProtocols, importAction, sortSection])

        return UIBarButtonItem(
            image: UIImage(systemName: "plus.viewfinder"),
            primaryAction: UIAction { [weak self] _ in
                self?.performDump(targets: [.all])
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

    private var currentSearchText: String {
        navigationItem.searchController?.searchBar.text ?? ""
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground

        setupTableView()
        setupDataSource()
        setupNavBar()
        setupSearch()
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
            $0.register(DumpRecordCell.self, forCellReuseIdentifier: DumpRecordCell.reuseIdentifier)
        }
        view.addSubview(tableView)
        tableView.snp.makeConstraints { $0.edges.equalToSuperview() }
    }

    private func setupDataSource() {
        dataSource = .init(tableView: tableView) { tableView, indexPath, recordID in
            let cell = tableView.dequeueReusableCell(
                withIdentifier: DumpRecordCell.reuseIdentifier, for: indexPath
            ) as! DumpRecordCell
            if let record = DumpStore.shared.record(for: recordID) {
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
                source: "DumpReorder"
            )
            DumpStore.shared.reorder(by: orderedIDs)
        }
        dataSource.defaultRowAnimation = .fade
    }

    private func setupNavBar() {
        navigationItem.rightBarButtonItem = dumpBarButton
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
            navigationItem.setRightBarButtonItems([dumpBarButton], animated: true)
        }
    }

    private func selectedRecords() -> [DumpRecord] {
        guard let indexPaths = tableView.indexPathsForSelectedRows else { return [] }
        return indexPaths.compactMap { indexPath in
            guard let id = dataSource.itemIdentifier(for: indexPath) else { return nil }
            return DumpStore.shared.record(for: id)
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
                DumpStore.shared.remove(id: record.id)
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
            let fileURLs = try records.map { try CardDocument.exportToFile($0) }
            let activity = UIActivityViewController(activityItems: fileURLs, applicationActivities: nil)
            activity.popoverPresentationController?.barButtonItem = exportSelectedBarButton
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    private func setupSearch() {
        let search = UISearchController(searchResultsController: nil).then {
            $0.delegate = self
            $0.searchBar.placeholder = String(localized: "Search by card type or UID")
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

    // MARK: - Data Source

    func reloadSnapshot(animatingDifferences: Bool = true) {
        guard isViewLoaded, view.window != nil, tableView.window != nil else {
            pendingSnapshotReload = true
            pendingSnapshotAnimated = pendingSnapshotAnimated || animatingDifferences
            AppLogStore.shared.debug(
                "reloadSnapshot deferred animated=\(animatingDifferences) viewWindow=\(view.window != nil) tableWindow=\(tableView.window != nil)",
                source: "DumpReorder"
            )
            return
        }
        let query = currentSearchText
        let filtered = DumpStore.shared.records.filter { record in
            query.isEmpty
                || record.dump.cardInfo.type.description.localizedCaseInsensitiveContains(query)
                || record.dump.cardInfo.uid.hexString.localizedCaseInsensitiveContains(query)
                || record.dump.cardInfo.uid.compactHexString.localizedCaseInsensitiveContains(query)
        }
        AppLogStore.shared.debug(
            "reloadSnapshot query='\(query)' total=\(DumpStore.shared.records.count) filtered=\(filtered.count) window=\(view.window != nil)",
            source: "DumpReorder"
        )
        var snapshot = NSDiffableDataSourceSnapshot<Section, UUID>()
        snapshot.appendSections([.main])
        snapshot.appendItems(filtered.map(\.id))
        dataSource.apply(snapshot, animatingDifferences: animatingDifferences)
    }

    private func flushPendingSnapshotReloadIfNeeded() {
        guard pendingSnapshotReload, view.window != nil, tableView.window != nil else { return }
        let animated = pendingSnapshotAnimated
        pendingSnapshotReload = false
        pendingSnapshotAnimated = true
        AppLogStore.shared.debug(
            "flushing deferred snapshot animated=\(animated)",
            source: "DumpReorder"
        )
        reloadSnapshot(animatingDifferences: animated)
    }

    // MARK: - Dump

    private func performDump(targets: [NFCSessionManager.PollingTarget]) {
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: targets)
                let refinedInfo = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)

                guard refinedInfo.type.isOperableOnIOS else {
                    manager.setAlertMessage("\(refinedInfo.type.description) — \(String(localized: "not dumpable on iOS"))")
                    manager.invalidate()
                    presentInfoAlert(
                        title: refinedInfo.type.description,
                        message: String(localized: "This card type cannot be dumped on iOS. Only identification is possible.")
                    )
                    return
                }

                manager.setAlertMessage(String(localized: "Reading..."))
                let dump = try await CoreExtendedNFC.dumpCard(info: refinedInfo, transport: transport)
                manager.setAlertMessage(String(localized: "Done"))
                manager.invalidate()

                let record = DumpRecord(from: dump)
                guard record.hasMemoryData else {
                    presentInfoAlert(
                        title: refinedInfo.type.description,
                        message: String(localized: "No memory data could be read from this card.")
                    )
                    return
                }

                handleNewDump(record)
            } catch is CancellationError {
                return
            } catch {
                manager.invalidate()
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    private func handleNewDump(_ record: DumpRecord) {
        DumpStore.shared.add(record)
        reloadSnapshot()
        navigationController?.pushViewController(
            DumpDetailViewController(record: record), animated: true
        )
    }

    // MARK: - Export

    private func exportRecord(_ record: DumpRecord) {
        do {
            let fileURL = try CardDocument.exportToFile(record)
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = view
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Import

    private func presentImportPicker() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.cenfc, .propertyList])
        picker.delegate = self
        picker.allowsMultipleSelection = true
        present(picker, animated: true)
    }

    private func importFile(at url: URL) {
        do {
            let envelope = try CardDocument.importEnvelope(from: url)

            if let dumpRecord = envelope.dumpRecord, dumpRecord.hasMemoryData {
                DumpStore.shared.add(dumpRecord)
                reloadSnapshot()
                promptSaveScan(envelope.scanRecord)
            } else {
                presentInfoAlert(
                    title: String(localized: "No Dump Data"),
                    message: String(localized: "This file does not contain memory dump data. It only has card identification info.")
                )
                promptSaveScan(envelope.scanRecord)
            }
        } catch {
            presentErrorAlert(for: error)
        }
    }

    private func promptSaveScan(_ scanRecord: ScanRecord) {
        let alert = UIAlertController(
            title: String(localized: "Save to Scanner?"),
            message: String(localized: "Save card identification data (\(scanRecord.cardInfo.type.description)) to the Scanner store?"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Save"), style: .default) { _ in
            if let existing = ScanStore.shared.record(withUID: scanRecord.cardInfo.uid) {
                ScanStore.shared.replace(existing.id, with: scanRecord)
            } else {
                ScanStore.shared.add(scanRecord)
            }
        })
        alert.addAction(UIAlertAction(title: String(localized: "Skip"), style: .cancel))
        present(alert, animated: true)
    }

    // MARK: - Alerts

    private func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Error"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }

    private func presentInfoAlert(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }
}

// MARK: - UITableViewDelegate

extension DumpViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
            return
        }
        tableView.deselectRow(at: indexPath, animated: true)
        guard let recordID = dataSource.itemIdentifier(for: indexPath),
              let record = DumpStore.shared.record(for: recordID)
        else { return }
        navigationController?.pushViewController(
            DumpDetailViewController(record: record), animated: true
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
            DumpStore.shared.remove(id: recordID)
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
              let record = DumpStore.shared.record(for: recordID)
        else { return nil }
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            UIMenu(children: [
                UIAction(
                    title: String(localized: "Copy UID"),
                    image: UIImage(systemName: "doc.on.doc")
                ) { _ in
                    UIPasteboard.general.string = record.dump.cardInfo.uid.hexString
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
                    DumpStore.shared.remove(id: recordID)
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

extension DumpViewController: UISearchControllerDelegate, UISearchBarDelegate {
    func searchBar(_: UISearchBar, textDidChange _: String) {
        NSObject.cancelPreviousPerformRequests(withTarget: self, selector: #selector(commitSearch), object: nil)
        perform(#selector(commitSearch), with: nil, afterDelay: 0.25)
    }

    @objc private func commitSearch() {
        reloadSnapshot()
    }
}

// MARK: - UIDocumentPickerDelegate

extension DumpViewController: UIDocumentPickerDelegate {
    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            importFile(at: url)
        }
    }
}

// MARK: - UITableViewDragDelegate

extension DumpViewController: UITableViewDragDelegate {
    func tableView(
        _: UITableView,
        itemsForBeginning _: UIDragSession,
        at indexPath: IndexPath
    ) -> [UIDragItem] {
        guard view.window != nil, tableView.window != nil else {
            AppLogStore.shared.warning("drag begin blocked because table/view is not in a window", source: "DumpReorder")
            return []
        }
        guard currentSearchText.isEmpty else {
            AppLogStore.shared.warning(
                "drag begin blocked by active search query='\(currentSearchText)'",
                source: "DumpReorder"
            )
            return []
        }
        guard let recordID = dataSource.itemIdentifier(for: indexPath) else { return [] }
        AppLogStore.shared.debug(
            "drag begin row=\(indexPath.row) id=\(recordID.uuidString)",
            source: "DumpReorder"
        )
        let provider = NSItemProvider(object: recordID.uuidString as NSString)
        let item = UIDragItem(itemProvider: provider)
        item.localObject = recordID
        return [item]
    }
}

// MARK: - UITableViewDropDelegate

extension DumpViewController: UITableViewDropDelegate {
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
            AppLogStore.shared.warning("drop update cancelled because table/view is not in a window", source: "DumpReorder")
            return UITableViewDropProposal(operation: .cancel)
        }
        guard session.localDragSession != nil else {
            return UITableViewDropProposal(operation: .cancel)
        }
        guard currentSearchText.isEmpty else {
            AppLogStore.shared.warning(
                "drop update forbidden due to active search query='\(currentSearchText)'",
                source: "DumpReorder"
            )
            return UITableViewDropProposal(operation: .forbidden)
        }
        AppLogStore.shared.debug("drop update local move", source: "DumpReorder")
        return UITableViewDropProposal(operation: .move, intent: .insertAtDestinationIndexPath)
    }

    func tableView(
        _: UITableView,
        performDropWith _: UITableViewDropCoordinator
    ) {
        AppLogStore.shared.debug("performDrop local noop; datasource handles reorder", source: "DumpReorder")
    }
}
