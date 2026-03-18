import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import SPIndicator
import Then
import UIKit

class CardDetailViewController: StackScrollController {
    private let record: ScanRecord

    private let dateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .medium
    }

    init(record: ScanRecord) {
        self.record = record
        super.init(nibName: nil, bundle: nil)
        title = record.cardInfo.type.description
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
        setupShareButton()
    }

    override func setupContentViews() {
        super.setupContentViews()
        buildIdentificationSection()
        buildProtocolDetailsSection()
        buildTechnologySection()
        buildFooter()
    }

    // MARK: - Share Button

    private func setupShareButton() {
        var menuItems: [UIAction] = [
            UIAction(
                title: String(localized: "Copy All Info"),
                image: UIImage(systemName: "doc.on.doc")
            ) { [weak self] _ in
                self?.copyAllInfo()
            },
            UIAction(
                title: String(localized: "View Raw Data"),
                image: UIImage(systemName: "doc.plaintext")
            ) { [weak self] _ in
                self?.viewRawData()
            },
        ]

        if record.cardInfo.type.isOperableOnIOS {
            menuItems.append(UIAction(
                title: String(localized: "Raw Communication"),
                image: UIImage(systemName: "terminal")
            ) { [weak self] _ in
                self?.openRawCommunication()
            })
        }

        let shareMenu = UIMenu(children: menuItems)

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.up"),
            primaryAction: UIAction { [weak self] _ in
                self?.exportFile()
            },
            menu: shareMenu
        )
    }

    private func openRawCommunication() {
        let vc = RawCommunicationViewController(cardInfo: record.cardInfo)
        navigationController?.pushViewController(vc, animated: true)
    }

    private func exportFile() {
        do {
            let fileURL = try ScanRecordDocument.exportToFile(record)
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItem
            present(activity, animated: true)
        } catch {
            let alert = UIAlertController(title: String(localized: "Export Failed"), message: String(describing: error), preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
            present(alert, animated: true)
        }
    }

    private func copyAllInfo() {
        var lines: [String] = []
        lines.append("\(String(localized: "Card Type")): \(record.cardInfo.type.description)")
        lines.append("\(String(localized: "Card Family")): \(String(describing: record.cardInfo.type.family))")
        lines.append("\(String(localized: "UID")): \(record.cardInfo.uid.hexString)")
        lines.append("\(String(localized: "Operable on iOS")): \(record.cardInfo.type.isOperableOnIOS ? String(localized: "Yes") : String(localized: "No"))")
        lines.append("\(String(localized: "Scan Date")): \(dateFormatter.string(from: record.date))")
        if let atqa = record.cardInfo.atqa { lines.append("\(String(localized: "ATQA")): \(atqa.hexString)") }
        if let sak = record.cardInfo.sak { lines.append("\(String(localized: "SAK")): \(String(format: "0x%02X", sak))") }
        if let ats = record.cardInfo.ats {
            lines.append("\(String(localized: "ATS FSCI")): \(ats.fsci) (max \(ats.maxFrameSize) bytes)")
            if let ta = ats.ta { lines.append("\(String(localized: "ATS TA")): \(String(format: "0x%02X", ta))") }
            if let tb = ats.tb { lines.append("\(String(localized: "ATS TB")): \(String(format: "0x%02X", tb))") }
            if let tc = ats.tc { lines.append("\(String(localized: "ATS TC")): \(String(format: "0x%02X", tc))") }
            if !ats.historicalBytes.isEmpty { lines.append("\(String(localized: "ATS Historical Bytes")): \(ats.historicalBytes.hexString)") }
        }
        if let hist = record.cardInfo.historicalBytes, !hist.isEmpty { lines.append("\(String(localized: "Historical Bytes")): \(hist.hexString)") }
        if let aid = record.cardInfo.initialSelectedAID, !aid.isEmpty { lines.append("\(String(localized: "Initial Selected AID")): \(aid)") }
        if let sysCode = record.cardInfo.systemCode { lines.append("\(String(localized: "System Code")): \(sysCode.hexString)") }
        if let idm = record.cardInfo.idm { lines.append("\(String(localized: "IDm")): \(idm.hexString)") }
        if let icMfr = record.cardInfo.icManufacturer { lines.append("\(String(localized: "IC Manufacturer")): \(String(format: "0x%02X (%d)", icMfr, icMfr))") }
        UIPasteboard.general.string = lines.joined(separator: "\n")
        SPIndicator.present(
            title: String(localized: "Copied"),
            preset: .done,
            haptic: .success
        )
    }

    private func viewRawData() {
        let data: Data
        do {
            data = try ScanRecordDocument.export(record)
        } catch { return }
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let prettyData = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
              let text = String(data: prettyData, encoding: .utf8)
        else { return }
        let viewer = TextViewerController(title: String(localized: "Raw Data"), text: text)
        navigationController?.pushViewController(viewer, animated: true)
    }

    // MARK: - Identification

    private func buildIdentificationSection() {
        addSectionHeader(String(localized: "Identification"))

        addInfoRow(
            icon: "rectangle.badge.checkmark", title: String(localized: "Card Type"),
            description: String(localized: "Specific chip variant identified via ATQA/SAK and protocol probing."),
            value: record.cardInfo.type.description
        )
        addInfoRow(
            icon: "square.stack.3d.up", title: String(localized: "Card Family"),
            description: String(localized: "Product family this chip belongs to, determines available commands."),
            value: String(describing: record.cardInfo.type.family)
        )
        addInfoRow(
            icon: "number", title: String(localized: "UID"),
            description: String(localized: "Unique identifier burned into the chip at manufacturing."),
            value: record.cardInfo.uid.hexString
        )
        addInfoRow(
            icon: record.cardInfo.type.isOperableOnIOS ? "checkmark.circle" : "xmark.circle",
            title: String(localized: "Operable on iOS"),
            description: String(localized: "Whether CoreNFC can perform read/write operations on this chip."),
            value: record.cardInfo.type.isOperableOnIOS ? String(localized: "Yes") : String(localized: "No"),
            isDestructive: !record.cardInfo.type.isOperableOnIOS
        )
        addInfoRow(
            icon: "calendar", title: String(localized: "Scan Date"),
            description: String(localized: "When this tag was last scanned by the reader."),
            value: dateFormatter.string(from: record.date)
        )

        addSectionFooter(String(localized: "Basic identification from ATQA/SAK lookup and card probing."))
    }

    // MARK: - Protocol Details

    private func buildProtocolDetailsSection() {
        guard record.cardInfo.atqa != nil
            || record.cardInfo.sak != nil
            || record.cardInfo.ats != nil
            || record.cardInfo.historicalBytes != nil
            || record.cardInfo.initialSelectedAID != nil
        else { return }

        addSectionHeader(String(localized: "Protocol Details"))

        if let atqa = record.cardInfo.atqa {
            addInfoRow(
                icon: "arrow.right.arrow.left", title: String(localized: "ATQA"),
                description: String(localized: "Answer To Request Type A, encodes anticollision and bit-frame info."),
                value: atqa.hexString
            )
        }
        if let sak = record.cardInfo.sak {
            addInfoRow(
                icon: "arrow.right.arrow.left", title: String(localized: "SAK"),
                description: String(localized: "Select Acknowledge byte, indicates ISO 14443-4 compliance and chip family."),
                value: String(format: "0x%02X", sak)
            )
        }
        if let ats = record.cardInfo.ats {
            addInfoRow(
                icon: "doc.plaintext", title: String(localized: "ATS FSCI"),
                description: String(localized: "Frame Size for proximity Coupling device Integer, max frame the card accepts."),
                value: "\(ats.fsci) (max \(ats.maxFrameSize) bytes)"
            )
            if let ta = ats.ta {
                addInfoRow(
                    icon: "gauge.medium", title: String(localized: "ATS TA"),
                    description: String(localized: "Interface byte encoding supported bitrates for both directions."),
                    value: String(format: "0x%02X", ta)
                )
            }
            if let tb = ats.tb {
                addInfoRow(
                    icon: "timer", title: String(localized: "ATS TB"),
                    description: String(localized: "Interface byte encoding frame waiting time and startup guard time."),
                    value: String(format: "0x%02X", tb)
                )
            }
            if let tc = ats.tc {
                addInfoRow(
                    icon: "gearshape", title: String(localized: "ATS TC"),
                    description: String(localized: "Interface byte indicating support for NAD and CID in protocol frames."),
                    value: String(format: "0x%02X", tc)
                )
            }
            if !ats.historicalBytes.isEmpty {
                addInfoRow(
                    icon: "doc.text", title: String(localized: "ATS Historical Bytes"),
                    description: String(localized: "Optional data from the card providing chip or application info."),
                    value: ats.historicalBytes.hexString
                )
            }
        }
        if let hist = record.cardInfo.historicalBytes, !hist.isEmpty {
            addInfoRow(
                icon: "doc.text", title: String(localized: "Historical Bytes"),
                description: String(localized: "Manufacturer-defined data returned during anticollision or selection."),
                value: hist.hexString
            )
        }
        if let aid = record.cardInfo.initialSelectedAID, !aid.isEmpty {
            addInfoRow(
                icon: "app.badge", title: String(localized: "Initial Selected AID"),
                description: String(localized: "Application Identifier that responded to ISO 7816 SELECT on first contact."),
                value: aid
            )
        }

        addSectionFooter(String(localized: "ISO 14443 protocol parameters detected during card identification."))
    }

    // MARK: - Technology

    private func buildTechnologySection() {
        guard record.cardInfo.systemCode != nil || record.cardInfo.idm != nil || record.cardInfo.icManufacturer != nil else { return }

        addSectionHeader(String(localized: "Technology Details"))

        if let sysCode = record.cardInfo.systemCode {
            addInfoRow(
                icon: "cpu", title: String(localized: "System Code"),
                description: String(localized: "FeliCa system code identifying the card's service configuration."),
                value: sysCode.hexString
            )
        }
        if let idm = record.cardInfo.idm {
            addInfoRow(
                icon: "cpu", title: String(localized: "IDm"),
                description: String(localized: "FeliCa Manufacture ID, 8-byte unique identifier assigned at production."),
                value: idm.hexString
            )
        }
        if let icMfr = record.cardInfo.icManufacturer {
            addInfoRow(
                icon: "building.2", title: String(localized: "IC Manufacturer"),
                description: String(localized: "ISO 15693 IC manufacturer code registered with ISO/IEC 7816-6."),
                value: String(format: "0x%02X (%d)", icMfr, icMfr)
            )
        }

        addSectionFooter(String(localized: "Technology-specific parameters for FeliCa and ISO 15693 tags."))
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
            $0.text = record.cardInfo.uid.compactHexString
            $0.textAlignment = .center
        }
        stackView.addArrangedSubviewWithMargin(uidLabel)
        stackView.addArrangedSubviewWithMargin(UIView())
    }
}
