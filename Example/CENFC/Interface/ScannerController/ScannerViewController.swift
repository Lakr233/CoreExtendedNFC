import ConfigurableKit
import CoreExtendedNFC
import SPIndicator
import UIKit
import UniformTypeIdentifiers

class ScannerViewController: ObjectListViewController<ScanStore>,
    ObjectListViewControllerDelegate,
    UIDocumentPickerDelegate,
    UIDropInteractionDelegate
{
    // MARK: - Bar Buttons

    private lazy var scanBarButton: UIBarButtonItem = {
        let protocolActions: [UIMenuElement] = [
            UIAction(
                title: String(localized: "All Protocols"),
                image: UIImage(systemName: "antenna.radiowaves.left.and.right")
            ) { [weak self] _ in self?.performScan(targets: [.all]) },
        ]

        let specificProtocols = UIMenu(options: .displayInline, children: [
            UIAction(
                title: String(localized: "ISO 14443"),
                image: UIImage(systemName: "wave.3.right")
            ) { [weak self] _ in self?.performScan(targets: [.iso14443]) },
            UIAction(
                title: String(localized: "ISO 18092"),
                image: UIImage(systemName: "dot.radiowaves.right")
            ) { [weak self] _ in self?.performScan(targets: [.iso18092]) },
            UIAction(
                title: String(localized: "ISO 15693"),
                image: UIImage(systemName: "barcode")
            ) { [weak self] _ in self?.performScan(targets: [.iso15693]) },
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
                ) { _ in ScanStore.shared.sort { $0.date > $1.date } },
                UIAction(
                    title: String(localized: "Date (Oldest First)"),
                    image: UIImage(systemName: "calendar.badge.clock")
                ) { _ in ScanStore.shared.sort { $0.date < $1.date } },
                UIAction(
                    title: String(localized: "Card Type"),
                    image: UIImage(systemName: "textformat")
                ) { _ in
                    ScanStore.shared.sort { $0.cardInfo.type.description.localizedCaseInsensitiveCompare($1.cardInfo.type.description) == .orderedAscending }
                },
                UIAction(
                    title: String(localized: "UID"),
                    image: UIImage(systemName: "number")
                ) { _ in ScanStore.shared.sort { $0.cardInfo.uid.hexDump < $1.cardInfo.uid.hexDump } },
                UIAction(
                    title: String(localized: "AID"),
                    image: UIImage(systemName: "creditcard")
                ) { _ in
                    ScanStore.shared.sort {
                        ($0.cardInfo.initialSelectedAID ?? "").localizedCaseInsensitiveCompare($1.cardInfo.initialSelectedAID ?? "") == .orderedAscending
                    }
                },
            ]
        )

        let sortSection = UIMenu(options: .displayInline, children: [sortMenu])

        let scanMenu = UIMenu(children: protocolActions + [specificProtocols, importAction, sortSection])

        return UIBarButtonItem(
            image: UIImage(systemName: "plus.viewfinder"),
            primaryAction: UIAction { [weak self] _ in
                self?.performScan(targets: [.all])
            },
            menu: scanMenu
        ).accessibilityLabeled(String(localized: "Scan Card"))
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
            action: #selector(deleteSelectedRecords)
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

    // MARK: - Init

    init() {
        super.init(dataSource: .shared)
        delegate = self
    }

    // MARK: - Lifecycle

    private let emptyState = EmptyStateView.scan()
    private let nfcTask = SingleTaskRunner()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        setupExternalDropInteraction()
        emptyState.install(on: tableView)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        navigationController?.setToolbarHidden(true, animated: animated)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        emptyState.isHidden = !ScanStore.shared.records.isEmpty
        emptyState.update(in: tableView)
    }

    override func scrollViewDidScroll(_ scrollView: UIScrollView) {
        emptyState.update(in: scrollView)
    }

    // MARK: - Editing

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
        // Hide ObjectList's toolbar, use nav bar instead
        navigationController?.setToolbarHidden(true, animated: false)
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

    private func selectedRecords() -> [ScanRecord] {
        guard let indexPaths = tableView.indexPathsForSelectedRows else { return [] }
        return indexPaths.compactMap { indexPath in
            guard let id = diffableItemIdentifier(for: indexPath) else { return nil }
            return ScanStore.shared.record(for: id)
        }
    }

    @objc private func deleteSelectedRecords() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        let alert = UIAlertController(
            title: String(localized: "Delete \(records.count) Record(s)?"),
            message: String(localized: "This action cannot be undone."),
            preferredStyle: .actionSheet
        )
        alert.addAction(UIAlertAction(title: String(localized: "Delete"), style: .destructive) { [weak self] _ in
            ScanStore.shared.removeItems(Set(records.map(\.id)))
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
            presentExportSheet(for: fileURLs, barButtonItem: exportSelectedBarButton)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Row Selection

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
            return
        }
        tableView.deselectRow(at: indexPath, animated: true)
        guard let recordID = diffableItemIdentifier(for: indexPath),
              let record = ScanStore.shared.record(for: recordID)
        else { return }
        navigationController?.pushViewController(
            CardDetailViewController(record: record), animated: true
        )
    }

    override func tableView(_ tableView: UITableView, didDeselectRowAt _: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
        }
    }

    // MARK: - Context Menu

    override func tableView(
        _: UITableView,
        contextMenuConfigurationForRowAt indexPath: IndexPath,
        point _: CGPoint
    ) -> UIContextMenuConfiguration? {
        guard !tableView.isEditing else { return nil }
        guard let recordID = diffableItemIdentifier(for: indexPath),
              let record = ScanStore.shared.record(for: recordID)
        else { return nil }
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            UIMenu(children: [
                UIAction(
                    title: String(localized: "Copy UID"),
                    image: UIImage(systemName: "doc.on.doc")
                ) { _ in
                    UIPasteboard.general.string = record.cardInfo.uid.hexDump
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
                ) { _ in
                    ScanStore.shared.removeItems([recordID])
                },
            ])
        }
    }

    // MARK: - Drag (external export)

    override func tableView(
        _: UITableView,
        itemsForBeginning _: UIDragSession,
        at indexPath: IndexPath
    ) -> [UIDragItem] {
        guard view.window != nil, tableView.window != nil else { return [] }
        guard let recordID = diffableItemIdentifier(for: indexPath),
              let record = ScanStore.shared.record(for: recordID)
        else { return [] }

        let provider = NSItemProvider()
        provider.registerDataRepresentation(
            forTypeIdentifier: UTType.cenfc.identifier,
            visibility: .all
        ) { completion in
            do {
                let data = try CardDocument.exportScanOnly(record)
                completion(data, nil)
            } catch {
                completion(nil, error)
            }
            return nil
        }
        provider.suggestedName = record.cardInfo.type.description

        let item = UIDragItem(itemProvider: provider)
        item.localObject = recordID
        return [item]
    }

    // MARK: - Drop (external import)

    func tableView(
        _: UITableView,
        canHandle session: UIDropSession
    ) -> Bool {
        session.hasItemsConforming(toTypeIdentifiers: [UTType.cenfc.identifier])
            || session.localDragSession != nil
    }

    override func tableView(
        _: UITableView,
        dropSessionDidUpdate session: UIDropSession,
        withDestinationIndexPath _: IndexPath?
    ) -> UITableViewDropProposal {
        guard view.window != nil, tableView.window != nil else {
            return UITableViewDropProposal(operation: .cancel)
        }
        if session.localDragSession != nil {
            return UITableViewDropProposal(operation: .move, intent: .insertAtDestinationIndexPath)
        }
        return UITableViewDropProposal(operation: .copy, intent: .insertAtDestinationIndexPath)
    }

    override func tableView(
        _: UITableView,
        performDropWith coordinator: UITableViewDropCoordinator
    ) {
        guard coordinator.session.localDragSession == nil else {
            return // local reorder handled by diffable data source
        }

        let insertionIndex = storeIndex(forDropAt: coordinator.destinationIndexPath)

        for item in coordinator.items {
            item.dragItem.itemProvider.loadDataRepresentation(
                forTypeIdentifier: UTType.cenfc.identifier
            ) { data, _ in
                guard let data else { return }
                DispatchQueue.main.async {
                    guard let envelope = try? CardDocument.importEnvelope(from: data) else { return }
                    self.importScanRecord(envelope.scanRecord, at: insertionIndex)
                    if let dump = envelope.dumpRecord, dump.hasMemoryData {
                        DumpStore.shared.add(dump)
                    }
                }
            }
        }
    }

    /// Maps a drop position in the (possibly filtered) table to an index in the full store.
    private func storeIndex(forDropAt indexPath: IndexPath?) -> Int {
        let records = ScanStore.shared.records
        guard let indexPath else { return records.count }
        if let id = diffableItemIdentifier(for: indexPath),
           let index = records.firstIndex(where: { $0.id == id })
        {
            return index
        }
        if indexPath.row > 0,
           let id = diffableItemIdentifier(for: IndexPath(row: indexPath.row - 1, section: indexPath.section)),
           let index = records.firstIndex(where: { $0.id == id })
        {
            return index + 1
        }
        return records.count
    }

    // MARK: - ObjectListViewControllerDelegate

    func objectListViewControllerDidLoad(_: UIViewController) {
        // Search placeholder
        navigationItem.searchController?.searchBar.placeholder = String(localized: "Search by card type or UID")
    }

    func objectListViewController(
        _: UIViewController,
        configureTrailingBarButtonItems items: inout [UIBarButtonItem]
    ) {
        items.removeAll()
        items.append(scanBarButton)
    }

    func objectListViewController(
        _: UIViewController,
        configureToolbarItems items: inout [UIBarButtonItem]
    ) {
        // Don't use ObjectList's toolbar, we use nav bar
        items.removeAll()
    }

    func objectListViewController(
        _: UIViewController,
        contextMenuActionsForItemWith _: UUID
    ) -> [UIMenuElement] {
        [] // We override the entire context menu
    }

    // MARK: - View-level Drop (external files)

    private func setupExternalDropInteraction() {
        let dropInteraction = UIDropInteraction(delegate: self)
        view.addInteraction(dropInteraction)
    }

    func dropInteraction(
        _: UIDropInteraction,
        canHandle session: UIDropSession
    ) -> Bool {
        session.localDragSession == nil
            && session.hasItemsConforming(toTypeIdentifiers: [UTType.cenfc.identifier])
    }

    func dropInteraction(
        _: UIDropInteraction,
        sessionDidUpdate session: UIDropSession
    ) -> UIDropProposal {
        guard session.localDragSession == nil else {
            return UIDropProposal(operation: .cancel)
        }
        return UIDropProposal(operation: .copy)
    }

    func dropInteraction(
        _: UIDropInteraction,
        performDrop session: UIDropSession
    ) {
        guard session.localDragSession == nil else { return }
        for item in session.items {
            item.itemProvider.loadDataRepresentation(
                forTypeIdentifier: UTType.cenfc.identifier
            ) { data, _ in
                guard let data else { return }
                DispatchQueue.main.async {
                    guard let envelope = try? CardDocument.importEnvelope(from: data) else { return }
                    self.importScanRecord(envelope.scanRecord)
                    if let dump = envelope.dumpRecord, dump.hasMemoryData {
                        DumpStore.shared.add(dump)
                    }
                }
            }
        }
    }

    // MARK: - Scan

    private func performScan(targets: [NFCSessionManager.PollingTarget]) {
        nfcTask.run { [weak self] in
            await self?.scan(targets: targets)
        }
    }

    private func scan(targets: [NFCSessionManager.PollingTarget]) async {
        let manager = NFCSessionManager()
        do {
            let (coarseInfo, transport) = try await manager.scan(for: targets)
            let refinedInfo = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
            manager.setAlertMessage(refinedInfo.type.description)
            manager.invalidate()
            handleNewScan(ScanRecord(cardInfo: refinedInfo))
        } catch {
            manager.invalidate(after: error)
            if !presentNFCErrorAlertIfNeeded(for: error, session: manager) {
                presentErrorAlert(for: error)
            }
        }
    }

    private func handleNewScan(_ record: ScanRecord) {
        if let existing = ScanStore.shared.record(withUID: record.cardInfo.uid) {
            promptDuplicateScan(record, existingID: existing.id)
        } else {
            ScanStore.shared.add(record)
            navigationController?.pushViewController(
                CardDetailViewController(record: record), animated: true
            )
        }
    }

    private func promptDuplicateScan(_ record: ScanRecord, existingID: UUID) {
        let alert = UIAlertController(
            title: String(localized: "Card Already Exists"),
            message: String(localized: "A card with this UID already exists in the history. What would you like to do?"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Overwrite"), style: .destructive) { [weak self] _ in
            ScanStore.shared.replace(existingID, with: record)
            self?.navigationController?.pushViewController(
                CardDetailViewController(record: record), animated: true
            )
        })
        alert.addAction(UIAlertAction(title: String(localized: "Save as New"), style: .default) { [weak self] _ in
            ScanStore.shared.add(record)
            self?.navigationController?.pushViewController(
                CardDetailViewController(record: record), animated: true
            )
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        presentQueued(alert)
    }

    // MARK: - Import

    private func presentImportPicker() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.cenfc, .propertyList])
        picker.delegate = self
        picker.allowsMultipleSelection = true
        present(picker, animated: true)
    }

    func importFile(at url: URL) {
        Task {
            do {
                let envelope = try await ImportFileReader.readInBackground(url) { data in
                    try CardDocument.importEnvelope(from: data)
                }
                self.importScanRecord(envelope.scanRecord)

                if let dumpRecord = envelope.dumpRecord, dumpRecord.hasMemoryData {
                    promptSaveDump(dumpRecord)
                }
            } catch {
                presentErrorAlert(for: error)
            }
        }
    }

    private func promptSaveDump(_ dumpRecord: DumpRecord) {
        let alert = UIAlertController(
            title: String(localized: "Dump Data Detected"),
            message: String(localized: "This file contains memory dump data (\(dumpRecord.dump.summary.technicalSummary)). Save to Dump store?"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Save"), style: .default) { _ in
            DumpStore.shared.add(dumpRecord)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Skip"), style: .cancel))
        presentQueued(alert)
    }

    // MARK: - Export

    private func exportRecord(_ record: ScanRecord) {
        do {
            let fileURL = try CardDocument.exportToFile(record)
            presentExportSheet(for: [fileURL])
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - UIDocumentPickerDelegate

    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            importFile(at: url)
        }
    }
}
