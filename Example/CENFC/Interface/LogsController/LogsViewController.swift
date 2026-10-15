import SnapKit
import UIKit

@MainActor
final class LogsViewController: UIViewController, UITableViewDataSource, UITableViewDelegate, UISearchResultsUpdating {
    private let tableView = UITableView(frame: .zero, style: .plain)
    private let searchController = UISearchController(searchResultsController: nil)

    private var allEntries: [AppLogEntry] = []
    private var filteredEntries: [AppLogEntry] = []

    private var selectedLevels: Set<AppLogLevel> = Set(AppLogLevel.allCases)
    private var selectedSources: Set<String> = []
    private var allSources: Set<String> = []

    private var isSearching: Bool {
        let text = searchController.searchBar.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return searchController.isActive && !text.isEmpty
    }

    private var displayEntries: [AppLogEntry] {
        isSearching ? filteredEntries : allEntries
    }

    init() {
        super.init(nibName: nil, bundle: nil)
        title = String(localized: "Logs")
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        setupDismissKeyboardOnTap()
        setupSearchController()
        setupMenuButton()
        setupTableView()
        reload()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleLogsChange),
            name: .appLogsDidChange,
            object: AppLogStore.shared
        )
    }

    // MARK: - Setup

    private func setupSearchController() {
        searchController.searchResultsUpdater = self
        searchController.obscuresBackgroundDuringPresentation = false
        searchController.searchBar.placeholder = String(localized: "Search logs...")
        searchController.searchBar.autocapitalizationType = .none
        searchController.searchBar.autocorrectionType = .no
        navigationItem.searchController = searchController
        navigationItem.hidesSearchBarWhenScrolling = false
        definesPresentationContext = true
    }

    private func setupMenuButton() {
        let button = UIButton(type: .system)
        button.setImage(UIImage(systemName: "ellipsis.circle"), for: .normal)
        button.showsMenuAsPrimaryAction = true
        button.menu = createMenu()
        button.frame = CGRect(x: 0, y: 0, width: 44, height: 44)
        // VoiceOver reads the custom view, so the label goes on the button.
        button.accessibilityLabel = String(localized: "More")
        navigationItem.rightBarButtonItem = UIBarButtonItem(customView: button)
    }

    private func setupTableView() {
        tableView.dataSource = self
        tableView.delegate = self
        tableView.estimatedRowHeight = 60
        tableView.rowHeight = UITableView.automaticDimension
        tableView.separatorStyle = .singleLine
        tableView.backgroundColor = .systemBackground
        view.addSubview(tableView)
        tableView.snp.makeConstraints { make in
            make.edges.equalToSuperview()
        }
    }

    // MARK: - Menu

    private func createMenu() -> UIMenu {
        let levelActions = AppLogLevel.allCases.map { level in
            UIAction(
                title: level.rawValue,
                image: selectedLevels.contains(level) ? UIImage(systemName: "checkmark") : nil
            ) { [weak self] _ in
                self?.toggleLevel(level)
            }
        }
        let levelMenu = UIMenu(
            title: String(localized: "Filter by Level"),
            image: UIImage(systemName: "slider.horizontal.3"),
            children: levelActions
        )

        let sourceActions: [UIAction]
        if allSources.isEmpty {
            sourceActions = [
                UIAction(title: String(localized: "No sources")) { _ in },
            ]
        } else {
            var actions = [
                UIAction(
                    title: String(localized: "All Sources"),
                    image: selectedSources.isEmpty ? UIImage(systemName: "checkmark") : nil
                ) { [weak self] _ in
                    self?.selectedSources.removeAll()
                    self?.applyFilters()
                    self?.updateMenu()
                },
            ]
            actions.append(contentsOf: allSources.sorted().map { source in
                UIAction(
                    title: source,
                    image: selectedSources.contains(source) ? UIImage(systemName: "checkmark") : nil
                ) { [weak self] _ in
                    self?.toggleSource(source)
                }
            })
            sourceActions = actions
        }
        let sourceMenu = UIMenu(
            title: String(localized: "Filter by Source"),
            image: UIImage(systemName: "tag"),
            children: sourceActions
        )

        let refreshAction = UIAction(
            title: String(localized: "Refresh"),
            image: UIImage(systemName: "arrow.clockwise")
        ) { [weak self] _ in
            self?.reload()
        }

        let shareAction = UIAction(
            title: String(localized: "Share Logs"),
            image: UIImage(systemName: "square.and.arrow.up")
        ) { [weak self] _ in
            self?.shareLogs()
        }

        let clearAction = UIAction(
            title: String(localized: "Clear"),
            image: UIImage(systemName: "trash"),
            attributes: .destructive
        ) { [weak self] _ in
            AppLogStore.shared.clear()
            self?.reload()
        }

        return UIMenu(children: [
            levelMenu,
            sourceMenu,
            UIMenu(options: .displayInline, children: [refreshAction]),
            UIMenu(options: .displayInline, children: [shareAction, clearAction]),
        ])
    }

    // MARK: - Filtering

    private func toggleLevel(_ level: AppLogLevel) {
        if selectedLevels.contains(level) {
            selectedLevels.remove(level)
        } else {
            selectedLevels.insert(level)
        }
        applyFilters()
        updateMenu()
    }

    private func toggleSource(_ source: String) {
        if selectedSources.contains(source) {
            selectedSources.remove(source)
        } else {
            selectedSources.insert(source)
        }
        applyFilters()
        updateMenu()
    }

    private func updateMenu() {
        guard let button = navigationItem.rightBarButtonItem?.customView as? UIButton else { return }
        button.menu = createMenu()
    }

    private func applyFilters() {
        var sources = Set<String>()
        var filtered: [AppLogEntry] = []

        for entry in AppLogStore.shared.entries.reversed() {
            sources.insert(entry.source)
            guard selectedLevels.contains(entry.level) else { continue }
            if !selectedSources.isEmpty, !selectedSources.contains(entry.source) {
                continue
            }
            filtered.append(entry)
        }

        allSources = sources
        allEntries = filtered

        if isSearching {
            updateSearchResults(for: searchController)
        } else {
            filteredEntries = []
        }
        updateBackgroundView()
        tableView.reloadData()
        scrollToBottom()
    }

    @objc private func handleLogsChange() {
        reload()
    }

    private func reload() {
        applyFilters()
        updateMenu()
    }

    private func updateBackgroundView() {
        guard displayEntries.isEmpty else {
            tableView.backgroundView = nil
            return
        }

        let label = UILabel()
        label.font = .preferredFont(forTextStyle: .body)
        label.textAlignment = .center
        label.textColor = .secondaryLabel
        label.numberOfLines = 0
        label.text = isSearching
            ? String(localized: "No matching logs.")
            : String(localized: "No logs yet.")
        tableView.backgroundView = label
    }

    private func scrollToBottom() {
        guard !displayEntries.isEmpty else { return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let indexPath = IndexPath(row: displayEntries.count - 1, section: 0)
            tableView.scrollToRow(at: indexPath, at: .bottom, animated: false)
        }
    }

    // MARK: - Search

    func updateSearchResults(for searchController: UISearchController) {
        guard let searchText = searchController.searchBar.text?.trimmingCharacters(in: .whitespacesAndNewlines),
              !searchText.isEmpty
        else {
            filteredEntries = []
            updateBackgroundView()
            tableView.reloadData()
            return
        }

        let query = searchText.localizedLowercase
        filteredEntries = allEntries.filter { entry in
            entry.source.localizedLowercase.contains(query)
                || entry.level.rawValue.localizedLowercase.contains(query)
                || entry.message.localizedLowercase.contains(query)
        }
        updateBackgroundView()
        tableView.reloadData()
    }

    // MARK: - UITableViewDataSource

    func numberOfSections(in _: UITableView) -> Int {
        1
    }

    func tableView(_: UITableView, numberOfRowsInSection _: Int) -> Int {
        displayEntries.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let identifier = "LogCell"
        let cell = tableView.dequeueReusableCell(withIdentifier: identifier) ?? UITableViewCell(
            style: .subtitle,
            reuseIdentifier: identifier
        )

        let entry = displayEntries[indexPath.row]

        cell.textLabel?.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        cell.textLabel?.numberOfLines = 0
        cell.textLabel?.text = entry.message
        cell.textLabel?.textColor = color(for: entry.level)

        cell.detailTextLabel?.font = .monospacedSystemFont(ofSize: 9, weight: .regular)
        cell.detailTextLabel?.numberOfLines = 1
        cell.detailTextLabel?.textColor = .secondaryLabel
        cell.detailTextLabel?.text = "\(DateFormatter.logTimestamp.string(from: entry.timestamp)) • \(entry.source) • \(entry.level.rawValue)"

        cell.backgroundColor = .systemBackground
        cell.selectionStyle = .none
        return cell
    }

    // MARK: - Share

    private func shareLogs() {
        do {
            let result = try makeShareItems()
            presentSheet(items: result.items, cleanup: result.cleanup)
        } catch {
            presentSheet(items: [AppLogStore.shared.exportText()])
        }
    }

    private func presentSheet(items: [Any], cleanup: (() -> Void)? = nil) {
        let ac = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let popover = ac.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = view.bounds
        }
        ac.completionWithItemsHandler = { _, _, _, _ in cleanup?() }
        present(ac, animated: true)
    }

    private func makeShareItems() throws -> (items: [Any], cleanup: () -> Void) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CoreExtendedNFC-Logs-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let urls: [Any] = try AppLogStore.shared.exportArtifacts().map { artifact in
            let url = directory.appendingPathComponent(artifact.suggestedFilename)
            try artifact.data.write(to: url, options: .atomic)
            return url
        }
        return (urls, { try? FileManager.default.removeItem(at: directory) })
    }

    // MARK: - Helpers

    private func color(for level: AppLogLevel) -> UIColor {
        switch level {
        case .debug: .secondaryLabel
        case .info: .label
        case .warning: .systemOrange
        case .error: .systemRed
        }
    }
}

private extension DateFormatter {
    static let logTimestamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()
}
