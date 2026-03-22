import ConfigurableKit
import CoreExtendedNFC
import SPIndicator
import UIKit
import UniformTypeIdentifiers

class DumpViewController: ObjectListViewController<DumpStore>,
    ObjectListViewControllerDelegate,
    UIDocumentPickerDelegate
{
    // MARK: - Bar Buttons

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
                ) { _ in DumpStore.shared.sort { $0.date > $1.date } },
                UIAction(
                    title: String(localized: "Date (Oldest First)"),
                    image: UIImage(systemName: "calendar.badge.clock")
                ) { _ in DumpStore.shared.sort { $0.date < $1.date } },
                UIAction(
                    title: String(localized: "Card Type"),
                    image: UIImage(systemName: "textformat")
                ) { _ in
                    DumpStore.shared.sort { $0.dump.cardInfo.type.description.localizedCaseInsensitiveCompare($1.dump.cardInfo.type.description) == .orderedAscending }
                },
                UIAction(
                    title: String(localized: "UID"),
                    image: UIImage(systemName: "number")
                ) { _ in DumpStore.shared.sort { $0.dump.cardInfo.uid.hexString < $1.dump.cardInfo.uid.hexString } },
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
            action: #selector(deleteSelectedRecords)
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

    // MARK: - Init

    init() {
        super.init(dataSource: .shared)
        delegate = self
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        navigationController?.setToolbarHidden(true, animated: animated)
    }

    // MARK: - Editing

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
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
            navigationItem.setRightBarButtonItems([dumpBarButton], animated: true)
        }
    }

    private func selectedRecords() -> [DumpRecord] {
        guard let indexPaths = tableView.indexPathsForSelectedRows else { return [] }
        return indexPaths.compactMap { indexPath in
            guard let id = diffableItemIdentifier(for: indexPath) else { return nil }
            return DumpStore.shared.record(for: id)
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
            DumpStore.shared.removeItems(Set(records.map(\.id)))
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

    // MARK: - Row Selection

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if tableView.isEditing {
            updateEditingNavBar()
            return
        }
        tableView.deselectRow(at: indexPath, animated: true)
        guard let recordID = diffableItemIdentifier(for: indexPath),
              let record = DumpStore.shared.record(for: recordID)
        else { return }
        navigationController?.pushViewController(
            DumpDetailViewController(record: record), animated: true
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
                ) { _ in
                    DumpStore.shared.removeItems([recordID])
                },
            ])
        }
    }

    // MARK: - Drag (local reorder only)

    override func tableView(
        _: UITableView,
        itemsForBeginning _: UIDragSession,
        at indexPath: IndexPath
    ) -> [UIDragItem] {
        guard view.window != nil, tableView.window != nil else { return [] }
        guard let recordID = diffableItemIdentifier(for: indexPath) else { return [] }
        let provider = NSItemProvider(object: recordID.uuidString as NSString)
        let item = UIDragItem(itemProvider: provider)
        item.localObject = recordID
        return [item]
    }

    override func tableView(
        _: UITableView,
        dropSessionDidUpdate session: UIDropSession,
        withDestinationIndexPath _: IndexPath?
    ) -> UITableViewDropProposal {
        guard view.window != nil, tableView.window != nil else {
            return UITableViewDropProposal(operation: .cancel)
        }
        guard session.localDragSession != nil else {
            return UITableViewDropProposal(operation: .cancel)
        }
        return UITableViewDropProposal(operation: .move, intent: .insertAtDestinationIndexPath)
    }

    override func tableView(
        _: UITableView,
        performDropWith _: UITableViewDropCoordinator
    ) {
        // local reorder handled by diffable data source
    }

    // MARK: - ObjectListViewControllerDelegate

    func objectListViewControllerDidLoad(_: UIViewController) {
        navigationItem.searchController?.searchBar.placeholder = String(localized: "Search by card type or UID")
    }

    func objectListViewController(
        _: UIViewController,
        configureTrailingBarButtonItems items: inout [UIBarButtonItem]
    ) {
        items.removeAll()
        items.append(dumpBarButton)
    }

    func objectListViewController(
        _: UIViewController,
        configureToolbarItems items: inout [UIBarButtonItem]
    ) {
        items.removeAll()
    }

    func objectListViewController(
        _: UIViewController,
        contextMenuActionsForItemWith _: UUID
    ) -> [UIMenuElement] {
        []
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

    // MARK: - UIDocumentPickerDelegate

    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            importFile(at: url)
        }
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
