import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

// MARK: - Base Editor

class NDEFEditorViewController: StackScrollController {
    /// The stored record being edited, or `nil` for a record that has not been saved yet.
    /// Set to the saved record after the first save.
    var existingRecord: NDEFDataRecord?
    var onSave: ((NDEFDataRecord) -> Void)?
    private let nfcTask = SingleTaskRunner()

    /// What the fields built right after they were filled from ``existingRecord``.
    /// While the fields still build this, the user has not edited anything and the
    /// stored message is kept byte for byte, including the parts this editor cannot
    /// show (further records, record IDs, Smart Poster actions and icons, text
    /// encodings, whitespace).
    private var untouchedBuild: Data?

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupNavButtons()
        untouchedBuild = buildNDEFRecord().map { NDEFMessage(records: [$0]).data }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isMovingFromParent {
            nfcTask.cancel()
            save()
        }
    }

    private func setupNavButtons() {
        let writeButton = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.down.on.square"),
            style: .plain,
            target: self,
            action: #selector(writeToCard)
        )
        writeButton.accessibilityLabel = String(localized: "Write to Tag")
        navigationItem.rightBarButtonItem = writeButton
    }

    func buildNDEFRecord() -> NDEFRecord? {
        nil
    }

    func recordName() -> String {
        String(localized: "NDEF")
    }

    /// The message the editor currently describes, or `nil` when the fields cannot
    /// be turned into a record.
    ///
    /// When nothing was edited this is the stored message unchanged. After an
    /// edit, only the first record is rebuilt: it keeps its record ID, and any
    /// further records of the stored message are kept as they were.
    func currentMessage() -> NDEFMessage? {
        guard let built = buildNDEFRecord() else { return nil }
        guard let existing = existingRecord, let original = existing.parsedMessage else {
            return NDEFMessage(records: [built])
        }
        if NDEFMessage(records: [built]).data == untouchedBuild {
            return original
        }
        let first = NDEFRecord(
            typeNameFormat: built.typeNameFormat,
            type: built.type,
            identifier: original.records.first?.identifier ?? Data(),
            payload: built.payload
        )
        return NDEFMessage(records: [first] + original.records.dropFirst())
    }

    /// Hands the edited record to ``onSave``.
    ///
    /// Nothing is saved when the fields cannot be turned into a record or when the
    /// message is byte-for-byte the stored one, so opening a record and leaving
    /// never rewrites it. A new record is created on its first save only.
    func save() {
        guard let message = currentMessage() else { return }
        let name = recordName()
        let saved: NDEFDataRecord
        if let existing = existingRecord {
            guard message.data != existing.messageData else { return }
            saved = existing.withName(name).withMessageData(message.data)
        } else {
            saved = NDEFDataRecord(name: name, messageData: message.data)
        }
        onSave?(saved)
        existingRecord = saved
        untouchedBuild = buildNDEFRecord().map { NDEFMessage(records: [$0]).data }
    }

    @objc private func writeToCard() {
        guard let message = currentMessage() else {
            let alert = UIAlertController(
                title: String(localized: "Cannot Write"),
                message: String(localized: "Fill in the required fields first."),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
            presentQueued(alert)
            return
        }

        nfcTask.run { [weak self] in
            await self?.write(message)
        }
    }

    private func write(_ message: NDEFMessage) async {
        let manager = NFCSessionManager()
        do {
            let (coarseInfo, transport) = try await manager.scan(for: [.all])
            // The screen may have been closed while the system sheet was up.
            try Task.checkCancellation()
            let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Writing NDEF…"))
            try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
            manager.setAlertMessage(String(localized: "Write complete"))
            manager.invalidate()
        } catch {
            manager.invalidate(after: error)
            if !presentNFCErrorAlertIfNeeded(for: error) {
                presentErrorAlert(for: error)
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
        let text = textField.text ?? ""
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        let lang = languageField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "en"
        return .text(text, languageCode: lang)
    }

    override func recordName() -> String {
        let text = textField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return String(text.prefix(40)).isEmpty ? String(localized: "Text") : String(text.prefix(40))
    }
}

// MARK: - URI Editor

class NDEFURIEditorViewController: NDEFEditorViewController {
    static let uriPrefixes: [(code: UInt8, prefix: String)] = [
        (0x00, ""),
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
            let matchedIndex = Self.longestPrefixIndex(for: fullURI)
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

    /// Index into ``uriPrefixes`` of the longest prefix that `uri` starts with
    /// (NFC Forum URI RTD), or 0 ("no prefix") when none matches.
    static func longestPrefixIndex(for uri: String) -> Int {
        uriPrefixes.indices
            .filter { uriPrefixes[$0].code != 0x00 && uri.hasPrefix(uriPrefixes[$0].prefix) }
            .max { uriPrefixes[$0].prefix.count < uriPrefixes[$1].prefix.count } ?? 0
    }

    private static func menuTitle(for entry: (code: UInt8, prefix: String)) -> String {
        entry.code == 0x00 ? String(localized: "(No prefix)") : entry.prefix
    }

    private func updatePrefixButton(_ button: UIButton) {
        let actions = Self.uriPrefixes.enumerated().map { index, entry in
            UIAction(
                title: Self.menuTitle(for: entry),
                state: index == selectedPrefixIndex ? .on : .off
            ) { [weak self] _ in
                guard let self else { return }
                selectedPrefixIndex = index
                updatePrefixButton(prefixButton)
            }
        }
        button.menu = UIMenu(children: actions)

        let selected = Self.uriPrefixes[selectedPrefixIndex]
        var config = button.configuration ?? .gray()
        config.title = selected.code == 0x00 ? String(localized: "(none)") : selected.prefix
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
        return String(fullURI.prefix(60)).isEmpty ? String(localized: "URI") : String(fullURI.prefix(60))
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
        return String(uri.prefix(60)).isEmpty ? String(localized: "Smart Poster") : String(uri.prefix(60))
    }
}

// MARK: - MIME Editor

class NDEFMIMEEditorViewController: NDEFEditorViewController {
    private lazy var typeField = makeTextField(
        placeholder: "text/plain"
    )
    private lazy var dataView = makeTextView()
    private var payloadText = NDEFPayloadText(data: Data())

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
            payloadText = NDEFPayloadText(data: data)
            dataView.text = payloadText.displayedText
        }

        addSectionHeader(String(localized: "MIME Type"))
        stackView.addArrangedSubviewWithMargin(typeField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Data"))
        stackView.addArrangedSubviewWithMargin(dataView) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum MIME Media Record. Carries a MIME content type and raw payload data."))
        if payloadText.isHex {
            addSectionFooter(String(localized: "The payload is binary and is shown as hex bytes. Edit it as hex."))
        }
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !type.isEmpty,
              let data = payloadText.data(from: dataView.text ?? ""),
              !data.isEmpty
        else { return nil }
        return .mime(type: type, data: data)
    }

    override func recordName() -> String {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return type.isEmpty ? String(localized: "MIME") : type
    }
}

// MARK: - External Type Editor

class NDEFExternalEditorViewController: NDEFEditorViewController {
    private lazy var typeField = makeTextField(
        placeholder: "example.com:mytype"
    )
    private lazy var dataView = makeTextView()
    private var payloadText = NDEFPayloadText(data: Data())

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
            payloadText = NDEFPayloadText(data: data)
            dataView.text = payloadText.displayedText
        }

        addSectionHeader(String(localized: "Type"))
        stackView.addArrangedSubviewWithMargin(typeField) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionHeader(String(localized: "Data"))
        stackView.addArrangedSubviewWithMargin(dataView) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())

        addSectionFooter(String(localized: "NFC Forum External Type Record. Uses a reverse-domain type identifier."))
        if payloadText.isHex {
            addSectionFooter(String(localized: "The payload is binary and is shown as hex bytes. Edit it as hex."))
        }
    }

    override func buildNDEFRecord() -> NDEFRecord? {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !type.isEmpty, let data = payloadText.data(from: dataView.text ?? "") else { return nil }
        return .external(type: type, data: data)
    }

    override func recordName() -> String {
        let type = typeField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return type.isEmpty ? String(localized: "External") : type
    }
}

// MARK: - Payload Text

/// How a MIME / External payload is shown in a text view and turned back into bytes.
///
/// Payloads that are not plain UTF-8 text (images, Wi-Fi credentials, CRLF text)
/// are shown as hex and parsed back from hex. Text the user did not change maps
/// back to the original bytes exactly, so viewing a record never alters it.
nonisolated struct NDEFPayloadText: Equatable {
    let originalData: Data
    let displayedText: String
    let isHex: Bool

    init(data: Data) {
        originalData = data
        if let text = String(data: data, encoding: .utf8),
           Data(text.utf8) == data,
           !text.unicodeScalars.contains(where: { $0.value < 0x20 && $0 != "\n" && $0 != "\t" })
        {
            displayedText = text
            isHex = false
        } else {
            displayedText = data.map { String(format: "%02X", $0) }.joined(separator: " ")
            isHex = true
        }
    }

    /// The payload bytes for `text`, or `nil` when hex input is malformed.
    func data(from text: String) -> Data? {
        if text == displayedText {
            return originalData
        }
        guard isHex else {
            return Data(text.utf8)
        }
        let digits = text.filter { !$0.isWhitespace }
        guard digits.count.isMultiple(of: 2) else { return nil }
        var bytes = Data()
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            guard let byte = UInt8(digits[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}
