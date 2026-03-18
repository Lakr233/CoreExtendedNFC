import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class AccessBitsDecoderViewController: StackScrollController {
    private lazy var inputField = UITextField().then {
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.placeholder = "FF 07 80"
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
        setupDefaultMenu()
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "Access Bytes (Hex)"))
        stackView.addArrangedSubviewWithMargin(inputField)
        addSectionFooter(String(localized: "Enter bytes 6-8 of the MIFARE Classic sector trailer."))

        stackView.addArrangedSubview(resultSentinel)
    }

    private func setupDefaultMenu() {
        let actions = [
            UIAction(title: String(localized: "Factory Default (FF 07 80)")) { [weak self] _ in
                self?.inputField.text = "FF 07 80"
                self?.inputChanged()
            },
            UIAction(title: String(localized: "Read-Only Data (78 77 88)")) { [weak self] _ in
                self?.inputField.text = "78 77 88"
                self?.inputChanged()
            },
        ]

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

        guard let text = inputField.text, !text.isEmpty else { return }

        guard let data = parseHexInput(text), data.count >= 3 else {
            addSectionFooter(String(localized: "Enter at least 3 hex bytes."))
            return
        }

        guard let blocks = AccessBits.decode(data) else {
            addErrorFooter(String(localized: "Invalid access bits — complement check failed."))
            return
        }

        let blockNames = [
            String(localized: "Block 0 (Data)"),
            String(localized: "Block 1 (Data)"),
            String(localized: "Block 2 (Data)"),
            String(localized: "Sector Trailer"),
        ]

        for (i, access) in blocks.enumerated() {
            addSectionHeader(blockNames[i])

            let bits = "\(access.c1 ? 1 : 0) \(access.c2 ? 1 : 0) \(access.c3 ? 1 : 0)"
            addInfoRow(
                icon: "number",
                title: "C1 C2 C3",
                value: bits
            )
            addInfoRow(
                icon: "gearshape",
                title: String(localized: "Condition"),
                value: "\(access.condition)"
            )

            let meaning = i < 3
                ? dataBlockMeaning(access.condition)
                : trailerBlockMeaning(access.condition)
            addInfoRow(
                icon: "text.alignleft",
                title: String(localized: "Permission"),
                value: meaning
            )
        }

        addSectionFooter(String(localized: "Access conditions per MIFARE Classic datasheet. Bytes 6-8 of the sector trailer encode permissions for all 4 blocks using C1/C2/C3 bits with complement verification."))
    }

    private func dataBlockMeaning(_ condition: UInt8) -> String {
        switch condition {
        case 0: String(localized: "Read/Write with Key A or B")
        case 1: String(localized: "Read-only with Key A or B")
        case 2: String(localized: "Read/Write with Key A, Read with Key B")
        case 3: String(localized: "Read/Write with Key B, Read with Key A|B")
        case 4: String(localized: "Read/Write with Key B")
        case 5: String(localized: "Read with Key B only")
        case 6: String(localized: "Read/Write with Key B (decrement with A|B)")
        case 7: String(localized: "No access (transport configuration)")
        default: String(localized: "Unknown")
        }
    }

    private func trailerBlockMeaning(_ condition: UInt8) -> String {
        switch condition {
        case 0: String(localized: "Key A: write A|B. Access: read A|B, write never. Key B: read/write A|B")
        case 1: String(localized: "Key A: write never. Access: read A|B, write never. Key B: read/write never")
        case 2: String(localized: "Key A: write never. Access: read A, write never. Key B: read A, write never")
        case 3: String(localized: "Key A: write B. Access: read A|B, write B. Key B: read never, write B")
        case 4: String(localized: "Key A: write B. Access: read A|B, write never. Key B: read never, write B")
        case 5: String(localized: "Key A: write never. Access: read A|B, write never. Key B: read never, write never")
        case 6: String(localized: "Key A: write never. Access: read A|B, write B. Key B: read never, write never")
        case 7: String(localized: "Key A: write never. Access: read A|B, write never. Key B: read never, write never")
        default: String(localized: "Unknown")
        }
    }

    private func addErrorFooter(_ text: String) {
        let label = UILabel().then {
            $0.text = text
            $0.font = .preferredFont(forTextStyle: .footnote)
            $0.textColor = .systemRed
            $0.numberOfLines = 0
        }
        stackView.addArrangedSubviewWithMargin(label)
    }
}
