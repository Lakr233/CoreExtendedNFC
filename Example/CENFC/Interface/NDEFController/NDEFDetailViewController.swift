import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

// MARK: - Base Editor

class NDEFEditorViewController: StackScrollController {
    var existingRecord: NDEFDataRecord?
    var onSave: ((NDEFDataRecord) -> Void)?

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupNavButtons()
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isMovingFromParent {
            save()
        }
    }

    private func setupNavButtons() {
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.down.on.square"),
            style: .plain,
            target: self,
            action: #selector(writeToCard)
        )
    }

    func buildNDEFRecord() -> NDEFRecord? {
        nil
    }

    func recordName() -> String {
        "NDEF"
    }

    private func save() {
        guard let ndefRecord = buildNDEFRecord() else { return }
        let message = NDEFMessage(records: [ndefRecord])
        let name = recordName()
        if let existing = existingRecord {
            let updated = existing.withName(name).withMessageData(message.data)
            onSave?(updated)
        } else {
            let newRecord = NDEFDataRecord(name: name, messageData: message.data)
            onSave?(newRecord)
        }
    }

    @objc private func writeToCard() {
        guard let ndefRecord = buildNDEFRecord() else {
            let alert = UIAlertController(
                title: String(localized: "Cannot Write"),
                message: String(localized: "Fill in the required fields first."),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
            present(alert, animated: true)
            return
        }

        let message = NDEFMessage(records: [ndefRecord])
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: [.all])
                let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
                manager.setAlertMessage("Writing NDEF…")
                try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
                manager.setAlertMessage("Write complete")
                manager.invalidate()
            } catch is CancellationError {
                return
            } catch {
                manager.invalidate()
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    let alert = UIAlertController(
                        title: String(localized: "Error"),
                        message: String(describing: error),
                        preferredStyle: .alert
                    )
                    alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
                    present(alert, animated: true)
                }
            }
        }
    }

    // MARK: - Shared UI helpers

    func makeTextField(
        placeholder: String,
        text: String = "",
        keyboardType: UIKeyboardType = .default
    ) -> UITextField {
        UITextField().then {
            $0.placeholder = placeholder
            $0.text = text
            $0.borderStyle = .roundedRect
            $0.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
            $0.keyboardType = keyboardType
            $0.autocapitalizationType = .none
            $0.autocorrectionType = .no
            $0.spellCheckingType = .no
            $0.smartQuotesType = .no
            $0.smartDashesType = .no
            $0.smartInsertDeleteType = .no
            $0.clearButtonMode = .whileEditing
            $0.snp.makeConstraints { $0.height.greaterThanOrEqualTo(44) }
        }
    }

    func makeTextView(text: String = "") -> UITextView {
        UITextView().then {
            $0.text = text
            $0.font = .monospacedSystemFont(ofSize: 16, weight: .regular)
            $0.isScrollEnabled = false
            $0.backgroundColor = .secondarySystemBackground
            $0.layer.cornerRadius = 8
            $0.layer.cornerCurve = .continuous
            $0.textContainerInset = UIEdgeInsets(top: 16, left: 12, bottom: 16, right: 12)
            $0.autocapitalizationType = .none
            $0.autocorrectionType = .no
            $0.spellCheckingType = .no
            $0.smartQuotesType = .no
            $0.smartDashesType = .no
            $0.smartInsertDeleteType = .no
            $0.snp.makeConstraints { $0.height.greaterThanOrEqualTo(88) }
        }
    }
}

// MARK: - Text Editor

class NDEFTextEditorViewController: NDEFEditorViewController {
    private lazy var textField = makeTextView()
    private lazy var languageField = makeTextField(
        placeholder: String(localized: "Language code"),
        text: "en"
    )

    override func viewDidLoad() {
        title = String(localized: "Text")
        super.viewDidLoad()
    }

    override func setupContentViews() {
        super.setupContentViews()

        if let record = existingRecord?.parsedRecord,
           case let .text(lang, text) = record.parsedPayload
        {
            textField.text = text
            languageField.text = lang
        }

        addSectionHeader(String(localized: "Content"))
        stackView.addArrangedSubviewWithMargin(textField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Language"))
        stackView.addArrangedSubviewWithMargin(languageField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum Text Record (Well-Known Type \"T\")."))
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let text = textField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !text.isEmpty else { return nil }
        let lang = languageField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "en"
        return .text(text, languageCode: lang)
    }

    override func recordName() -> String {
        let text = textField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return String(text.prefix(40)).isEmpty ? "Text" : String(text.prefix(40))
    }
}

// MARK: - URI Editor

class NDEFURIEditorViewController: NDEFEditorViewController {
    private static let uriPrefixes: [(code: UInt8, prefix: String)] = [
        (0x00, "(No prefix)"),
        (0x04, "https://"),
        (0x03, "http://"),
        (0x02, "https://www."),
        (0x01, "http://www."),
        (0x05, "tel:"),
        (0x06, "mailto:"),
        (0x09, "ftps://"),
        (0x0D, "ftp://"),
        (0x1D, "file://"),
    ]

    private var selectedPrefixIndex: Int = 1 // default: https://

    private lazy var prefixButton: UIButton = {
        var config = UIButton.Configuration.gray()
        config.cornerStyle = .medium
        config.buttonSize = .medium
        config.baseForegroundColor = .label
        let button = UIButton(configuration: config)
        button.showsMenuAsPrimaryAction = true
        button.changesSelectionAsPrimaryAction = true
        updatePrefixButton(button)
        return button
    }()

    private lazy var uriField = makeTextField(
        placeholder: "example.com/path",
        keyboardType: .URL
    )

    override func viewDidLoad() {
        title = String(localized: "URI")
        super.viewDidLoad()
    }

    override func setupContentViews() {
        super.setupContentViews()

        if let record = existingRecord?.parsedRecord,
           case let .uri(fullURI) = record.parsedPayload
        {
            // Match the longest known prefix
            var matchedIndex = 0
            for (index, entry) in Self.uriPrefixes.enumerated() where entry.code != 0x00 {
                if fullURI.hasPrefix(entry.prefix) {
                    matchedIndex = index
                    break
                }
            }
            selectedPrefixIndex = matchedIndex
            let prefix = Self.uriPrefixes[matchedIndex]
            if prefix.code == 0x00 {
                uriField.text = fullURI
            } else {
                uriField.text = String(fullURI.dropFirst(prefix.prefix.count))
            }
            updatePrefixButton(prefixButton)
        }

        addSectionHeader(String(localized: "URI"))
        let row = UIStackView(arrangedSubviews: [prefixButton, uriField]).then {
            $0.axis = .horizontal
            $0.spacing = 8
            $0.alignment = .center
        }
        prefixButton.setContentCompressionResistancePriority(.required, for: .horizontal)
        prefixButton.setContentHuggingPriority(.required, for: .horizontal)
        stackView.addArrangedSubviewWithMargin(row) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum URI Record (Well-Known Type \"U\"). The prefix is compressed into a single byte to save space on the tag."))
    }

    private func updatePrefixButton(_ button: UIButton) {
        let actions = Self.uriPrefixes.enumerated().map { index, entry in
            UIAction(
                title: entry.prefix,
                state: index == selectedPrefixIndex ? .on : .off
            ) { [weak self] _ in
                self?.selectedPrefixIndex = index
                self?.updatePrefixButton(self!.prefixButton)
            }
        }
        button.menu = UIMenu(children: actions)

        let selected = Self.uriPrefixes[selectedPrefixIndex]
        var config = button.configuration ?? .gray()
        config.title = selected.code == 0x00 ? "(none)" : selected.prefix
        button.configuration = config
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let suffix = uriField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !suffix.isEmpty else { return nil }
        let prefix = Self.uriPrefixes[selectedPrefixIndex]
        let fullURI = prefix.code == 0x00 ? suffix : prefix.prefix + suffix
        return .uri(fullURI)
    }

    override func recordName() -> String {
        let suffix = uriField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let prefix = Self.uriPrefixes[selectedPrefixIndex]
        let fullURI = prefix.code == 0x00 ? suffix : prefix.prefix + suffix
        return String(fullURI.prefix(60)).isEmpty ? "URI" : String(fullURI.prefix(60))
    }
}

// MARK: - Smart Poster Editor

class NDEFSmartPosterEditorViewController: NDEFEditorViewController {
    private lazy var uriField = makeTextField(
        placeholder: "https://example.com",
        keyboardType: .URL
    )
    private lazy var titleField = makeTextField(
        placeholder: String(localized: "Title (optional)")
    )

    override func viewDidLoad() {
        title = String(localized: "Smart Poster")
        super.viewDidLoad()
    }

    override func setupContentViews() {
        super.setupContentViews()

        if let record = existingRecord?.parsedRecord,
           case let .smartPoster(uri, spTitle) = record.parsedPayload
        {
            uriField.text = uri
            titleField.text = spTitle
        }

        addSectionHeader(String(localized: "URI"))
        stackView.addArrangedSubviewWithMargin(uriField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Title"))
        stackView.addArrangedSubviewWithMargin(titleField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum Smart Poster Record. Contains a URI and an optional title for display."))
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let uri = uriField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !uri.isEmpty else { return nil }
        let spTitle = titleField.text?.trimmingCharacters(in: .whitespacesAndNewlines)
        return .smartPoster(uri: uri, title: spTitle?.isEmpty == true ? nil : spTitle)
    }

    override func recordName() -> String {
        let spTitle = titleField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !spTitle.isEmpty { return spTitle }
        let uri = uriField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return String(uri.prefix(60)).isEmpty ? "Smart Poster" : String(uri.prefix(60))
    }
}

// MARK: - MIME Editor

class NDEFMIMEEditorViewController: NDEFEditorViewController {
    private lazy var typeField = makeTextField(
        placeholder: "text/plain"
    )
    private lazy var dataView = makeTextView()

    override func viewDidLoad() {
        title = String(localized: "MIME")
        super.viewDidLoad()
    }

    override func setupContentViews() {
        super.setupContentViews()

        if let record = existingRecord?.parsedRecord,
           case let .mime(type, data) = record.parsedPayload
        {
            typeField.text = type
            dataView.text = String(data: data, encoding: .utf8)
                ?? data.map { String(format: "%02X", $0) }.joined(separator: " ")
        }

        addSectionHeader(String(localized: "MIME Type"))
        stackView.addArrangedSubviewWithMargin(typeField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Data"))
        stackView.addArrangedSubviewWithMargin(dataView) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum MIME Media Record. Carries a MIME content type and raw payload data."))
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let dataText = dataView.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !type.isEmpty, !dataText.isEmpty else { return nil }
        return .mime(type: type, data: Data(dataText.utf8))
    }

    override func recordName() -> String {
        typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "MIME"
    }
}

// MARK: - External Type Editor

class NDEFExternalEditorViewController: NDEFEditorViewController {
    private lazy var typeField = makeTextField(
        placeholder: "example.com:mytype"
    )
    private lazy var dataView = makeTextView()

    override func viewDidLoad() {
        title = String(localized: "External")
        super.viewDidLoad()
    }

    override func setupContentViews() {
        super.setupContentViews()

        if let record = existingRecord?.parsedRecord,
           case let .external(type, data) = record.parsedPayload
        {
            typeField.text = type
            dataView.text = String(data: data, encoding: .utf8)
                ?? data.map { String(format: "%02X", $0) }.joined(separator: " ")
        }

        addSectionHeader(String(localized: "Type"))
        stackView.addArrangedSubviewWithMargin(typeField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Data"))
        stackView.addArrangedSubviewWithMargin(dataView) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum External Type Record. Uses a reverse-domain type identifier."))
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let dataText = dataView.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !type.isEmpty else { return nil }
        return .external(type: type, data: Data(dataText.utf8))
    }

    override func recordName() -> String {
        typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "External"
    }
}
