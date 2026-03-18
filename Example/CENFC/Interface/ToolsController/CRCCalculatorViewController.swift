import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class CRCCalculatorViewController: StackScrollController {
    private lazy var inputField = UITextField().then {
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.placeholder = "01 02 03 04"
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
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "Input Data (Hex)"))
        stackView.addArrangedSubviewWithMargin(inputField)
        addSectionFooter(String(localized: "Enter hex bytes to compute CRC. Results update automatically."))

        stackView.addArrangedSubview(resultSentinel)
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

        guard let data = parseHexInput(text) else {
            addSectionFooter(String(localized: "Invalid hex input."))
            return
        }

        let (crcALo, crcAHi) = ISO14443.crcA(data)
        let (crcBLo, crcBHi) = ISO14443.crcB(data)

        addSectionHeader(String(localized: "Results"))

        addInfoRow(
            icon: "a.circle",
            title: "CRC_A",
            description: String(localized: "ISO 14443-3 Type A CRC (initial 0x6363)"),
            value: String(format: "%02X %02X", crcALo, crcAHi)
        )

        addInfoRow(
            icon: "b.circle",
            title: "CRC_B",
            description: String(localized: "ISO 14443-3 Type B CRC (initial 0xFFFF, final NOT)"),
            value: String(format: "%02X %02X", crcBLo, crcBHi)
        )

        var dataWithCrcA = data
        dataWithCrcA.append(crcALo)
        dataWithCrcA.append(crcAHi)
        addInfoRow(
            icon: "plus.circle",
            title: String(localized: "Data + CRC_A"),
            value: dataWithCrcA.map { String(format: "%02X", $0) }.joined(separator: " ")
        )

        var dataWithCrcB = data
        dataWithCrcB.append(crcBLo)
        dataWithCrcB.append(crcBHi)
        addInfoRow(
            icon: "plus.circle",
            title: String(localized: "Data + CRC_B"),
            value: dataWithCrcB.map { String(format: "%02X", $0) }.joined(separator: " ")
        )

        addSectionFooter(String(localized: "CRC computed per ISO/IEC 14443-3 using polynomial 0x8408."))
    }
}
