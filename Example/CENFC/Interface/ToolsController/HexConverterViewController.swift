import ConfigurableKit
import SnapKit
import Then
import UIKit

class HexConverterViewController: StackScrollController {
    private enum InputFormat: Int, CaseIterable {
        case hex = 0, decimal, binary, ascii

        var title: String {
            switch self {
            case .hex: "Hex"
            case .decimal: "Dec"
            case .binary: "Bin"
            case .ascii: "ASCII"
            }
        }
    }

    private lazy var inputField = UITextField().then {
        $0.borderStyle = .roundedRect
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.placeholder = "48 65 6C 6C 6F"
        $0.autocapitalizationType = .allCharacters
        $0.autocorrectionType = .no
        $0.clearButtonMode = .whileEditing
        $0.addTarget(self, action: #selector(inputChanged), for: .editingChanged)
    }

    private lazy var formatSegment = UISegmentedControl(items: InputFormat.allCases.map(\.title)).then {
        $0.selectedSegmentIndex = 0
        $0.addTarget(self, action: #selector(inputChanged), for: .valueChanged)
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

        addSectionHeader(String(localized: "Input"))
        stackView.addArrangedSubviewWithMargin(formatSegment)
        stackView.addArrangedSubviewWithMargin(inputField)
        addSectionFooter(String(localized: "Enter data in the selected format. Results update automatically."))

        stackView.addArrangedSubview(resultSentinel)
    }

    @objc private func inputChanged() {
        rebuildResults()
    }

    private func rebuildResults() {
        // Remove all views after sentinel
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            toRemove.forEach { $0.removeFromSuperview() }
        }

        guard let text = inputField.text, !text.isEmpty else { return }
        guard let format = InputFormat(rawValue: formatSegment.selectedSegmentIndex) else { return }

        guard let data = parseInput(text, format: format) else {
            addSectionFooter(String(localized: "Invalid input for the selected format."))
            return
        }

        guard !data.isEmpty else { return }

        addSectionHeader(String(localized: "Results"))

        // Hex
        addInfoRow(
            icon: "number",
            title: "Hex",
            value: data.map { String(format: "%02X", $0) }.joined(separator: " ")
        )

        // Decimal
        addInfoRow(
            icon: "textformat.123",
            title: "Decimal",
            value: data.map { String($0) }.joined(separator: " ")
        )

        // Binary
        addInfoRow(
            icon: "01.square",
            title: "Binary",
            value: data.map { String($0, radix: 2).leftPadded(toLength: 8, with: "0") }.joined(separator: " ")
        )

        // ASCII
        let ascii = String(data.map { (0x20 ... 0x7E).contains($0) ? Character(UnicodeScalar($0)) : "." }, separator: "")
        addInfoRow(
            icon: "textformat.abc",
            title: "ASCII",
            value: ascii
        )

        // Byte-reversed
        addInfoRow(
            icon: "arrow.uturn.right",
            title: String(localized: "Reversed"),
            value: Data(data.reversed()).map { String(format: "%02X", $0) }.joined(separator: " ")
        )

        addSectionFooter(String(localized: "\(data.count) byte(s)"))
    }

    private func parseInput(_ text: String, format: InputFormat) -> Data? {
        switch format {
        case .hex:
            return parseHexInput(text)
        case .decimal:
            let parts = text.split(whereSeparator: { $0 == " " || $0 == "," })
            var data = Data()
            for part in parts {
                guard let value = UInt8(part) else { return nil }
                data.append(value)
            }
            return data
        case .binary:
            let parts = text.split(whereSeparator: { $0 == " " })
            var data = Data()
            for part in parts {
                guard let value = UInt8(part, radix: 2) else { return nil }
                data.append(value)
            }
            return data
        case .ascii:
            return text.data(using: .utf8)
        }
    }
}

// MARK: - Hex Parser

func parseHexInput(_ string: String) -> Data? {
    let cleaned = string
        .replacingOccurrences(of: " ", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "0x", with: "")
        .replacingOccurrences(of: "0X", with: "")
    guard !cleaned.isEmpty, cleaned.count % 2 == 0 else { return nil }
    var data = Data()
    var index = cleaned.startIndex
    while index < cleaned.endIndex {
        let nextIndex = cleaned.index(index, offsetBy: 2)
        guard let byte = UInt8(cleaned[index ..< nextIndex], radix: 16) else { return nil }
        data.append(byte)
        index = nextIndex
    }
    return data
}

private extension String {
    func leftPadded(toLength length: Int, with pad: String) -> String {
        let deficit = length - count
        guard deficit > 0 else { return self }
        return String(repeating: pad, count: deficit) + self
    }

    init(_ characters: [Character], separator _: String) {
        self = String(characters)
    }
}
