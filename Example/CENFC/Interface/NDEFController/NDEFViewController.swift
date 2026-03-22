import ConfigurableKit
import CoreExtendedNFC
import SPIndicator
import UIKit
import UniformTypeIdentifiers

class NDEFViewController: ObjectListViewController<NDEFStore>,
    ObjectListViewControllerDelegate,
    UIDocumentPickerDelegate
{
    // MARK: - Bar Buttons

    private lazy var addBarButton: UIBarButtonItem = {
        let addMenu = UIMenu(children: [
            UIMenu(title: "", options: .displayInline, children: [
                UIAction(
                    title: String(localized: "Text"),
                    image: UIImage(systemName: "doc.plaintext")
                ) { [weak self] _ in self?.createRecord(type: .text) },
                UIAction(
                    title: String(localized: "URI"),
                    image: UIImage(systemName: "link")
                ) { [weak self] _ in self?.createRecord(type: .uri) },
                UIAction(
                    title: String(localized: "Smart Poster"),
                    image: UIImage(systemName: "rectangle.and.text.magnifyingglass")
                ) { [weak self] _ in self?.createRecord(type: .smartPoster) },
                UIAction(
                    title: String(localized: "MIME"),
                    image: UIImage(systemName: "doc.richtext")
                ) { [weak self] _ in self?.createRecord(type: .mime) },
                UIAction(
                    title: String(localized: "External"),
                    image: UIImage(systemName: "puzzlepiece.extension")
                ) { [weak self] _ in self?.createRecord(type: .external) },
            ]),
            UIMenu(title: "", options: .displayInline, children: [
                UIAction(
                    title: String(localized: "Scan from Card"),
                    image: UIImage(systemName: "sensor.tag.radiowaves.forward")
                ) { [weak self] _ in self?.scanNDEFFromCard() },
                UIAction(
                    title: String(localized: "Import from File"),
                    image: UIImage(systemName: "square.and.arrow.down")
                ) { [weak self] _ in self?.presentImportPicker() },
            ]),
            UIMenu(title: "", options: .displayInline, children: [
                UIAction(
                    title: String(localized: "Format Tag"),
                    image: UIImage(systemName: "tag.slash")
                ) { [weak self] _ in self?.formatTag() },
            ]),
            UIMenu(title: "", options: .displayInline, children: [
                UIMenu(
                    title: String(localized: "Sort By"),
                    image: UIImage(systemName: "arrow.up.arrow.down"),
                    children: [
                        UIAction(
                            title: String(localized: "Date (Newest First)"),
                            image: UIImage(systemName: "calendar")
                        ) { _ in NDEFStore.shared.sort { $0.date > $1.date } },
                        UIAction(
                            title: String(localized: "Date (Oldest First)"),
                            image: UIImage(systemName: "calendar.badge.clock")
                        ) { _ in NDEFStore.shared.sort { $0.date < $1.date } },
                        UIAction(
                            title: String(localized: "Name"),
                            image: UIImage(systemName: "textformat")
                        ) { _ in
                            NDEFStore.shared.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                        },
                        UIAction(
                            title: String(localized: "Type"),
                            image: UIImage(systemName: "tag")
                        ) { _ in
                            NDEFStore.shared.sort { $0.displayType.localizedCaseInsensitiveCompare($1.displayType) == .orderedAscending }
                        },
                    ]
                ),
            ]),
        ])
        return UIBarButtonItem(image: UIImage(systemName: "plus"), menu: addMenu)
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

    private func makeActionsBarButton() -> UIBarButtonItem {
        let count = tableView.indexPathsForSelectedRows?.count ?? 0
        let menu = UIMenu(children: [
            UIAction(
                title: String(localized: "Write \(count) Record(s)"),
                image: UIImage(systemName: "square.and.arrow.down.on.square")
            ) { [weak self] _ in self?.writeSelectedToCard() },
            UIAction(
                title: String(localized: "Export \(count) Record(s)"),
                image: UIImage(systemName: "square.and.arrow.up")
            ) { [weak self] _ in self?.exportSelected() },
        ])
        return UIBarButtonItem(image: UIImage(systemName: "ellipsis.circle"), menu: menu)
    }

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

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
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
                hasSelection ? [doneBarButton, makeActionsBarButton()] : [doneBarButton],
                animated: true
            )
        } else {
            navigationItem.setLeftBarButton(nil, animated: true)
            navigationItem.setRightBarButtonItems([addBarButton], animated: true)
        }
    }

    private func selectedRecords() -> [NDEFDataRecord] {
        guard let indexPaths = tableView.indexPathsForSelectedRows else { return [] }
        return indexPaths.compactMap { indexPath in
            guard let id = diffableItemIdentifier(for: indexPath) else { return nil }
            return NDEFStore.shared.record(for: id)
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
              let record = NDEFStore.shared.record(for: recordID)
        else { return }
        pushEditor(for: record)
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
              let record = NDEFStore.shared.record(for: recordID)
        else { return nil }
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            UIMenu(children: [
                UIAction(
                    title: String(localized: "Write to Card"),
                    image: UIImage(systemName: "square.and.arrow.down.on.square")
                ) { _ in
                    guard let message = record.parsedMessage else { return }
                    self?.writeMessage(message, summary: record.name)
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
                    NDEFStore.shared.removeItems([recordID])
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
        navigationItem.searchController?.searchBar.placeholder = String(localized: "Search by name or content")
    }

    func objectListViewController(
        _: UIViewController,
        configureTrailingBarButtonItems items: inout [UIBarButtonItem]
    ) {
        items.removeAll()
        items.append(addBarButton)
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

    // MARK: - Create

    enum NDEFCreateType {
        case text, uri, smartPoster, mime, external
    }

    private func createRecord(type: NDEFCreateType) {
        let (name, ndefRecord): (String, NDEFRecord) = switch type {
        case .text: ("Text", .text("", languageCode: "en"))
        case .uri: ("URI", .uri(""))
        case .smartPoster: ("Smart Poster", .smartPoster(uri: "", title: nil))
        case .mime: ("MIME", .mime(type: "", data: Data()))
        case .external: ("External", .external(type: "", data: Data()))
        }
        let message = NDEFMessage(records: [ndefRecord])
        let record = NDEFDataRecord(name: name, messageData: message.data)
        NDEFStore.shared.add(record)
        pushEditor(for: record)
    }

    // MARK: - Scan NDEF from Card

    private func scanNDEFFromCard() {
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: [.all])
                let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
                manager.setAlertMessage(String(localized: "Reading NDEF…"))

                let message = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
                manager.setAlertMessage(String(localized: "\(message.records.count) record(s)"))
                manager.invalidate()

                var imported = 0
                var duplicated = 0
                for ndefRecord in message.records {
                    let singleMessage = NDEFMessage(records: [ndefRecord])
                    let name = autoName(for: ndefRecord)
                    let record = NDEFDataRecord(name: name, messageData: singleMessage.data)
                    if NDEFStore.shared.record(withMessageData: record.messageData) != nil {
                        duplicated += 1
                    } else {
                        NDEFStore.shared.add(record)
                        imported += 1
                    }
                }
                showImportSummary(imported: imported, duplicated: duplicated)
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

    // MARK: - Format Tag

    private func formatTag() {
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: [.all])
                let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
                manager.setAlertMessage(String(localized: "Formatting…"))

                try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)
                manager.setAlertMessage(String(localized: "Format complete"))
                manager.invalidate()
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

    private func autoName(for record: NDEFRecord) -> String {
        switch record.parsedPayload {
        case let .text(_, text):
            String(text.prefix(40))
        case let .uri(uri):
            String(uri.prefix(60))
        case let .smartPoster(uri, title):
            title ?? uri ?? String(localized: "Smart Poster")
        case let .mime(type, _):
            type
        case let .external(type, _):
            type
        case .empty:
            String(localized: "Empty Record")
        case .unknown:
            String(localized: "Unknown NDEF")
        }
    }

    // MARK: - Write to Card

    private func writeSelectedToCard() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        let allNDEFRecords = records.compactMap(\.parsedMessage).flatMap(\.records)
        guard !allNDEFRecords.isEmpty else { return }
        let combined = NDEFMessage(records: allNDEFRecords)
        writeMessage(combined, summary: String(localized: "\(allNDEFRecords.count) record(s)"))
    }

    private func writeMessage(_ message: NDEFMessage, summary: String) {
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: [.all])
                let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
                manager.setAlertMessage(String(localized: "Writing NDEF…"))

                try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
                manager.setAlertMessage(String(localized: "Write complete (\(summary))"))
                manager.invalidate()
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

    // MARK: - Export

    private func exportSelected() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        do {
            let fileURLs = try records.map { try NDEFDocument.exportToFile($0) }
            let activity = UIActivityViewController(activityItems: fileURLs, applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = view
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    private func exportRecord(_ record: NDEFDataRecord) {
        do {
            let fileURL = try NDEFDocument.exportToFile(record)
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = view
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error)
        }
    }

    // MARK: - Delete

    @objc private func deleteSelectedRecords() {
        let records = selectedRecords()
        guard !records.isEmpty else { return }

        let alert = UIAlertController(
            title: String(localized: "Delete \(records.count) Record(s)?"),
            message: String(localized: "This action cannot be undone."),
            preferredStyle: .actionSheet
        )
        alert.addAction(UIAlertAction(title: String(localized: "Delete"), style: .destructive) { [weak self] _ in
            NDEFStore.shared.removeItems(Set(records.map(\.id)))
            self?.setEditing(false, animated: true)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        alert.popoverPresentationController?.sourceView = view
        present(alert, animated: true)
    }

    // MARK: - Import

    private func presentImportPicker() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.cndef, .propertyList])
        picker.delegate = self
        picker.allowsMultipleSelection = true
        present(picker, animated: true)
    }

    func importFile(at url: URL) {
        do {
            let record = try NDEFDocument.importRecord(from: url)
            if NDEFStore.shared.record(withMessageData: record.messageData) != nil {
                showImportSummary(imported: 0, duplicated: 1)
            } else {
                NDEFStore.shared.add(record)
                showImportSummary(imported: 1, duplicated: 0)
            }
        } catch {
            presentErrorAlert(for: error)
        }
    }

    func importFiles(at urls: [URL]) {
        var imported = 0
        var duplicated = 0
        for url in urls {
            do {
                let record = try NDEFDocument.importRecord(from: url)
                if NDEFStore.shared.record(withMessageData: record.messageData) != nil {
                    duplicated += 1
                } else {
                    NDEFStore.shared.add(record)
                    imported += 1
                }
            } catch {
                presentErrorAlert(for: error)
            }
        }
        showImportSummary(imported: imported, duplicated: duplicated)
    }

    private func showImportSummary(imported: Int, duplicated: Int) {
        if imported > 0, duplicated > 0 {
            SPIndicator.present(
                title: String(localized: "Imported \(imported) Record(s)"),
                message: String(localized: "\(duplicated) duplicate(s) skipped"),
                preset: .done,
                haptic: .success
            )
        } else if imported > 0 {
            SPIndicator.present(
                title: String(localized: "Imported \(imported) Record(s)"),
                preset: .done,
                haptic: .success
            )
        } else if duplicated > 0 {
            SPIndicator.present(
                title: String(localized: "All Records Already Exist"),
                message: String(localized: "\(duplicated) duplicate(s) skipped"),
                preset: .done,
                haptic: .success
            )
        }
    }

    // MARK: - Push Editor

    private func pushEditor(for record: NDEFDataRecord) {
        let editor: NDEFEditorViewController
        guard let ndefRecord = record.parsedRecord else {
            editor = NDEFTextEditorViewController()
            editor.existingRecord = record
            editor.onSave = { updated in
                NDEFStore.shared.update(updated)
            }
            navigationController?.pushViewController(editor, animated: true)
            return
        }

        switch ndefRecord.parsedPayload {
        case .text:
            editor = NDEFTextEditorViewController()
        case .uri:
            editor = NDEFURIEditorViewController()
        case .smartPoster:
            editor = NDEFSmartPosterEditorViewController()
        case .mime:
            editor = NDEFMIMEEditorViewController()
        case .external:
            editor = NDEFExternalEditorViewController()
        default:
            editor = NDEFTextEditorViewController()
        }
        editor.existingRecord = record
        editor.onSave = { updated in
            NDEFStore.shared.update(updated)
        }
        navigationController?.pushViewController(editor, animated: true)
    }

    // MARK: - UIDocumentPickerDelegate

    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        importFiles(at: urls)
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
