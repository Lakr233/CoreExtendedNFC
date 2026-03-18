import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class ATQASAKLookupViewController: StackScrollController {
    private lazy var atqaField = UITextField().then {
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.placeholder = "00 44"
        $0.autocapitalizationType = .allCharacters
        $0.autocorrectionType = .no
        $0.clearButtonMode = .whileEditing
        $0.addTarget(self, action: #selector(inputChanged), for: .editingChanged)
    }

    private lazy var sakField = UITextField().then {
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.placeholder = "00"
        $0.autocapitalizationType = .allCharacters
        $0.autocorrectionType = .no
        $0.clearButtonMode = .whileEditing
        $0.addTarget(self, action: #selector(inputChanged), for: .editingChanged)
    }

    private var resultSentinel = UIView()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupPresetsMenu()
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "ATQA (2 bytes hex)"))
        stackView.addArrangedSubviewWithMargin(atqaField)

        addSectionHeader(String(localized: "SAK (1 byte hex)"))
        stackView.addArrangedSubviewWithMargin(sakField)

        addSectionFooter(String(localized: "Enter ATQA and SAK values to identify the card type."))

        stackView.addArrangedSubview(resultSentinel)
    }

    private func setupPresetsMenu() {
        let presets: [(String, String, String)] = [
            ("MIFARE Ultralight", "00 44", "00"),
            ("MIFARE Classic 1K", "00 04", "08"),
            ("MIFARE Classic 4K", "00 02", "18"),
            ("MIFARE DESFire", "03 44", "20"),
            ("MIFARE Mini", "00 04", "09"),
        ]

        let actions = presets.map { name, atqa, sak in
            UIAction(title: name) { [weak self] _ in
                self?.atqaField.text = atqa
                self?.sakField.text = sak
                self?.inputChanged()
            }
        }

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "text.book.closed"),
            menu: UIMenu(title: String(localized: "Presets"), children: actions)
        )
    }

    @objc private func inputChanged() {
        rebuildResults()
    }

    private func rebuildResults() {
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            toRemove.forEach { $0.removeFromSuperview() }
        }

        guard let atqaText = atqaField.text, !atqaText.isEmpty,
              let sakText = sakField.text, !sakText.isEmpty
        else { return }

        guard let atqaData = parseHexInput(atqaText), atqaData.count == 2 else {
            addSectionFooter(String(localized: "ATQA must be exactly 2 bytes."))
            return
        }

        let sakCleaned = sakText.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "0X", with: "")
        guard let sakValue = UInt8(sakCleaned, radix: 16) else {
            addSectionFooter(String(localized: "SAK must be a valid hex byte."))
            return
        }

        let cardType = CardIdentifier.identify(atqa: atqaData, sak: sakValue)

        addSectionHeader(String(localized: "Identification"))

        addInfoRow(
            icon: "rectangle.badge.checkmark",
            title: String(localized: "Card Type"),
            description: String(localized: "Specific chip variant identified via ATQA/SAK lookup."),
            value: cardType.description
        )
        addInfoRow(
            icon: "square.stack.3d.up",
            title: String(localized: "Card Family"),
            description: String(localized: "Product family this chip belongs to."),
            value: cardType.family.description
        )
        addInfoRow(
            icon: cardType.isOperableOnIOS ? "checkmark.circle" : "xmark.circle",
            title: String(localized: "Operable on iOS"),
            description: String(localized: "Whether CoreNFC can perform read/write operations on this chip."),
            value: cardType.isOperableOnIOS ? String(localized: "Yes") : String(localized: "No"),
            isDestructive: !cardType.isOperableOnIOS
        )

        addSectionFooter(String(localized: "Card identification based on NXP AN10833 ATQA/SAK lookup tables. Some chips share ATQA/SAK and require GET_VERSION for precise identification."))
    }
}
