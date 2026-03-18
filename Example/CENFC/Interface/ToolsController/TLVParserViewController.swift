import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class TLVParserViewController: StackScrollController {
    private lazy var hexInputView = UITextView().then {
        $0.font = .monospacedSystemFont(ofSize: 15, weight: .regular)
        $0.autocapitalizationType = .allCharacters
        $0.autocorrectionType = .no
        $0.layer.borderColor = UIColor.separator.cgColor
        $0.layer.borderWidth = 0.5
        $0.layer.cornerRadius = 8
        $0.layer.cornerCurve = .continuous
        $0.textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
        $0.isScrollEnabled = false
        $0.delegate = self
    }

    private var resultSentinel = UIView()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "text.book.closed"),
            menu: UIMenu(title: String(localized: "Examples"), children: [
                UIAction(title: String(localized: "NDEF App Select Response")) { [weak self] _ in
                    self?.hexInputView.text = "6F 0A 84 07 D2 76 00 00 85 01 01"
                    self?.rebuildResults()
                },
                UIAction(title: String(localized: "Simple Constructed TLV")) { [weak self] _ in
                    self?.hexInputView.text = "E1 08 C0 02 00 7A C1 02 00 00"
                    self?.rebuildResults()
                },
            ])
        )
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "TLV Data (Hex)"))
        stackView.addArrangedSubviewWithMargin(hexInputView)
        hexInputView.snp.makeConstraints { $0.height.greaterThanOrEqualTo(80) }
        addSectionFooter(String(localized: "Enter BER-TLV hex data. Constructed tags are expanded recursively."))

        stackView.addArrangedSubview(resultSentinel)
    }

    private func rebuildResults() {
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            toRemove.forEach { $0.removeFromSuperview() }
        }

        guard let text = hexInputView.text, !text.isEmpty else { return }

        guard let data = parseHexInput(text) else {
            addErrorFooter(String(localized: "Invalid hex input."))
            return
        }

        do {
            let nodes = try ASN1Parser.parseTLV(data)
            if nodes.isEmpty {
                addSectionFooter(String(localized: "No TLV nodes found."))
                return
            }

            addSectionHeader(String(localized: "Parsed Structure"))
            for node in nodes {
                addTLVNode(node, level: 0)
            }
            addSectionFooter(String(localized: "BER-TLV parser per ITU-T X.690. Constructed tags (bit 6 set) are expanded recursively."))
        } catch {
            addErrorFooter(String(localized: "Parse error: \(error.localizedDescription)"))
        }
    }

    private func addTLVNode(_ node: TLVNode, level: Int) {
        let indent = min(level, 5)
        let prefix = String(repeating: "  ", count: indent)
        let tagHex = String(format: "0x%02X", node.tag)
        let typeLabel = node.isConstructed ? " [C]" : " [P]"

        let title = "\(prefix)\(tagHex)\(typeLabel)  Len: \(node.length)"
        let valueHex = node.value.prefix(32).map { String(format: "%02X", $0) }.joined(separator: " ")
        let truncated = node.value.count > 32 ? "\(valueHex)…" : valueHex

        let infoView = ConfigurableInfoView().then {
            $0.configure(icon: UIImage(systemName: node.isConstructed ? "folder" : "doc"))
            $0.configure(title: String.LocalizationValue(stringLiteral: title))
            if !truncated.isEmpty {
                $0.configure(value: truncated)
            }
        }

        if !truncated.isEmpty {
            let fullHex = node.value.map { String(format: "%02X", $0) }.joined(separator: " ")
            infoView.setTapBlock { [weak self] _ in
                UIPasteboard.general.string = fullHex
                self?.showCopiedBanner()
            }
        }

        let wrapper = UIView()
        wrapper.addSubview(infoView)
        infoView.snp.makeConstraints {
            $0.top.bottom.trailing.equalToSuperview()
            $0.leading.equalToSuperview().offset(CGFloat(indent) * 16)
        }

        stackView.addArrangedSubviewWithMargin(wrapper)
        stackView.addArrangedSubview(SeparatorView())

        if node.isConstructed, let children = try? node.children() {
            for child in children {
                addTLVNode(child, level: level + 1)
            }
        }
    }

    // MARK: - Section Builders

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

// MARK: - UITextViewDelegate

extension TLVParserViewController: UITextViewDelegate {
    func textViewDidChange(_: UITextView) {
        rebuildResults()
    }
}
