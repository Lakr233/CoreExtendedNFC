import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class DumpDetailViewController: StackScrollController {
    private let record: DumpRecord

    private let dateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .medium
    }

    init(record: DumpRecord) {
        self.record = record
        super.init(nibName: nil, bundle: nil)
        title = record.dump.cardInfo.type.description
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupExportButton()
    }

    override func setupContentViews() {
        super.setupContentViews()
        buildSummarySection()
        buildFactsSection()
        buildNDEFRecordsSection()
        buildMemorySection()
        buildExportSection()
        buildFooter()
    }

    // MARK: - Export Button

    private func setupExportButton() {
        var menuItems: [UIAction] = []

        if record.dump.cardInfo.type.isOperableOnIOS {
            menuItems.append(UIAction(
                title: String(localized: "Raw Communication"),
                image: UIImage(systemName: "terminal")
            ) { [weak self] _ in
                self?.openRawCommunication()
            })
        }

        if menuItems.isEmpty {
            navigationItem.rightBarButtonItem = UIBarButtonItem(
                image: UIImage(systemName: "square.and.arrow.up"),
                style: .plain,
                target: self,
                action: #selector(exportTapped)
            )
        } else {
            let menu = UIMenu(children: menuItems)
            navigationItem.rightBarButtonItem = UIBarButtonItem(
                image: UIImage(systemName: "square.and.arrow.up"),
                primaryAction: UIAction { [weak self] _ in
                    self?.exportTapped()
                },
                menu: menu
            )
        }
    }

    private func openRawCommunication() {
        let vc = RawCommunicationViewController(cardInfo: record.dump.cardInfo)
        navigationController?.pushViewController(vc, animated: true)
    }

    @objc private func exportTapped() {
        do {
            let fileURL = try CardDocument.exportToFile(record)
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = view
            present(activity, animated: true)
        } catch {
            let alert = UIAlertController(
                title: String(localized: "Export Error"),
                message: String(describing: error),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
            present(alert, animated: true)
        }
    }

    // MARK: - Summary

    private func buildSummarySection() {
        addSectionHeader(String(localized: "Summary"))

        addInfoRow(
            icon: "rectangle.badge.checkmark",
            title: String(localized: "Card Type"),
            description: String(localized: "Specific chip variant identified via ATQA/SAK and protocol probing."),
            value: record.dump.cardInfo.type.description
        )
        addInfoRow(
            icon: "square.stack.3d.up",
            title: String(localized: "Card Family"),
            description: String(localized: "Product family this chip belongs to, determines available commands."),
            value: record.dump.cardInfo.type.family.description
        )
        addInfoRow(
            icon: "number",
            title: String(localized: "UID"),
            description: String(localized: "Unique identifier burned into the chip at manufacturing."),
            value: record.dump.cardInfo.uid.hexString
        )
        addInfoRow(
            icon: "calendar",
            title: String(localized: "Dump Date"),
            description: String(localized: "When the full memory dump was captured from this tag."),
            value: dateFormatter.string(from: record.date)
        )
        addInfoRow(
            icon: "text.justify.left",
            title: String(localized: "Technical"),
            description: String(localized: "Memory layout and page/block count read from the card."),
            value: record.dump.summary.technicalSummary
        )

        if !record.dump.summary.capabilities.isEmpty {
            addInfoRow(
                icon: "checkmark.seal",
                title: String(localized: "Capabilities"),
                description: String(localized: "Features supported by this chip variant."),
                value: record.dump.summary.capabilities.map(\.rawValue).joined(separator: ", ")
            )
        }

        addSectionFooter(record.dump.summary.userSummary)
    }

    // MARK: - Facts

    private func buildFactsSection() {
        guard !record.dump.facts.isEmpty else { return }

        addSectionHeader(String(localized: "Card Details"))

        for fact in record.dump.facts {
            addInfoRow(icon: "info.circle", title: fact.key, value: fact.value)
        }

        addSectionFooter(String(localized: "Family-specific parameters detected during the dump."))
    }

    // MARK: - NDEF Records

    private func buildNDEFRecordsSection() {
        guard let ndefMessage = record.dump.parsedNDEFMessage, !ndefMessage.records.isEmpty else { return }

        addSectionHeader(String(localized: "NDEF Records"))

        for record in ndefMessage.records {
            addInfoRow(icon: record.parsedPayload.icon, title: record.displayType, value: record.displayValue)
        }
    }

    // MARK: - Memory

    private func buildMemorySection() {
        guard record.dump.pages.count > 0 || record.dump.blocks.count > 0 || record.dump.files.count > 0 || record.dump.ndefMessage != nil else { return }

        addSectionHeader(String(localized: "Memory Dump"))

        let hexView = UITextView().then {
            $0.text = record.dump.exportHex()
            $0.isEditable = false
            $0.isScrollEnabled = false
            $0.backgroundColor = .secondarySystemBackground
            $0.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            $0.textColor = .label
            $0.textContainerInset = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
            $0.layer.cornerRadius = 8
            $0.layer.cornerCurve = .continuous
        }
        stackView.addArrangedSubviewWithMargin(hexView) { $0.bottom = 4 }

        let copyButton = UIButton(type: .system).then {
            $0.setTitle(String(localized: "Copy Hex Dump"), for: .normal)
            $0.titleLabel?.font = .preferredFont(forTextStyle: .footnote)
        }
        copyButton.addAction(UIAction { [weak self] _ in
            guard let self else { return }
            UIPasteboard.general.string = record.dump.exportHex()
            showCopiedBanner()
        }, for: .touchUpInside)
        stackView.addArrangedSubviewWithMargin(copyButton) { $0.top = 0 }

        stackView.addArrangedSubview(SeparatorView())
    }

    // MARK: - Export

    private func buildExportSection() {
        addSectionHeader(String(localized: "Export Data"))

        addInfoRow(
            icon: "doc.text",
            title: String(localized: "Hex Dump Size"),
            description: String(localized: "Human-readable hexadecimal representation of raw memory."),
            value: "\(record.dump.exportHex().count) \(String(localized: "characters"))"
        )
        addInfoRow(
            icon: "doc.richtext",
            title: String(localized: "JSON Size"),
            description: String(localized: "Structured JSON with page/block metadata and parsed fields."),
            value: "\(((try? record.dump.exportStructuredJSON()) ?? "{}").count) \(String(localized: "characters"))"
        )
        addInfoRow(
            icon: "doc.zipper",
            title: String(localized: "Binary Size"),
            description: String(localized: "Raw binary data suitable for flashing or forensic analysis."),
            value: "\(record.dump.exportBinary().count) \(String(localized: "bytes"))"
        )

        addSectionFooter(String(localized: "Tap the share button to export all formats."))
    }

    // MARK: - Footer

    private func buildFooter() {
        stackView.addArrangedSubviewWithMargin(UIView())

        let uidLabel = UILabel().then {
            $0.font = .monospacedSystemFont(
                ofSize: UIFont.preferredFont(forTextStyle: .footnote).pointSize,
                weight: .regular
            )
            $0.textColor = .label.withAlphaComponent(0.25)
            $0.numberOfLines = 0
            $0.text = record.dump.cardInfo.uid.compactHexString
            $0.textAlignment = .center
        }
        stackView.addArrangedSubviewWithMargin(uidLabel)
        stackView.addArrangedSubviewWithMargin(UIView())
    }
}
