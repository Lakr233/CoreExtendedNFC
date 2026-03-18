import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import UIKit

class CardInfoDetailViewController: StackScrollController {
    private let cardInfo: CardInfo
    private let capturedAt: Date?

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    init(cardInfo: CardInfo, capturedAt: Date? = nil) {
        self.cardInfo = cardInfo
        self.capturedAt = capturedAt
        super.init(nibName: nil, bundle: nil)
        title = cardInfo.type.description
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
    }

    override func setupContentViews() {
        super.setupContentViews()
        buildIdentificationSection()
        buildProtocolDetailsSection()
        buildTechnologySection()
        buildFooter()
    }

    private func buildIdentificationSection() {
        addSectionHeader(String(localized: "Identification"))

        addInfoRow(
            icon: "rectangle.badge.checkmark", title: String(localized: "Card Type"),
            description: String(localized: "Specific chip variant identified via ATQA/SAK and protocol probing."),
            value: cardInfo.type.description
        )
        addInfoRow(
            icon: "square.stack.3d.up", title: String(localized: "Card Family"),
            description: String(localized: "Product family this chip belongs to, determines available commands."),
            value: cardInfo.type.family.description
        )
        addInfoRow(
            icon: "number", title: String(localized: "UID"),
            description: String(localized: "Unique identifier burned into the chip at manufacturing."),
            value: cardInfo.uid.hexDump
        )
        addInfoRow(
            icon: cardInfo.type.isOperableOnIOS ? "checkmark.circle" : "xmark.circle",
            title: String(localized: "Operable on iOS"),
            description: String(localized: "Whether CoreNFC can perform read/write operations on this chip."),
            value: cardInfo.type.isOperableOnIOS ? String(localized: "Yes") : String(localized: "No"),
            isDestructive: !cardInfo.type.isOperableOnIOS
        )
        if let capturedAt {
            addInfoRow(
                icon: "calendar", title: String(localized: "Captured"),
                description: String(localized: "When this tag was last scanned by the reader."),
                value: dateFormatter.string(from: capturedAt)
            )
        }

        addSectionFooter(String(localized: "Basic identification from ATQA/SAK lookup and family-specific probing."))
    }

    private func buildProtocolDetailsSection() {
        guard cardInfo.atqa != nil
            || cardInfo.sak != nil
            || cardInfo.ats != nil
            || cardInfo.historicalBytes != nil
            || cardInfo.initialSelectedAID != nil
        else { return }

        addSectionHeader(String(localized: "Protocol Details"))

        if let atqa = cardInfo.atqa {
            addInfoRow(
                icon: "arrow.right.arrow.left", title: String(localized: "ATQA"),
                description: String(localized: "Answer To Request Type A, encodes anticollision and bit-frame info."),
                value: atqa.hexDump
            )
        }
        if let sak = cardInfo.sak {
            addInfoRow(
                icon: "arrow.right.arrow.left", title: String(localized: "SAK"),
                description: String(localized: "Select Acknowledge byte, indicates ISO 14443-4 compliance and chip family."),
                value: String(format: "0x%02X", sak)
            )
        }
        if let ats = cardInfo.ats {
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
                    value: ats.historicalBytes.hexDump
                )
            }
        }
        if let historicalBytes = cardInfo.historicalBytes, !historicalBytes.isEmpty {
            addInfoRow(
                icon: "doc.text", title: String(localized: "Historical Bytes"),
                description: String(localized: "Manufacturer-defined data returned during anticollision or selection."),
                value: historicalBytes.hexDump
            )
        }
        if let initialSelectedAID = cardInfo.initialSelectedAID, !initialSelectedAID.isEmpty {
            addInfoRow(
                icon: "app.badge", title: String(localized: "Initial Selected AID"),
                description: String(localized: "Application Identifier that responded to ISO 7816 SELECT on first contact."),
                value: initialSelectedAID
            )
        }

        addSectionFooter(String(localized: "ISO 14443 and ISO 7816 protocol parameters detected during card identification."))
    }

    private func buildTechnologySection() {
        guard cardInfo.systemCode != nil || cardInfo.idm != nil || cardInfo.icManufacturer != nil else { return }

        addSectionHeader(String(localized: "Technology Details"))

        if let systemCode = cardInfo.systemCode {
            addInfoRow(
                icon: "cpu", title: String(localized: "System Code"),
                description: String(localized: "FeliCa system code identifying the card's service configuration."),
                value: systemCode.hexDump
            )
        }
        if let idm = cardInfo.idm {
            addInfoRow(
                icon: "cpu", title: String(localized: "IDm"),
                description: String(localized: "FeliCa Manufacture ID, 8-byte unique identifier assigned at production."),
                value: idm.hexDump
            )
        }
        if let icManufacturer = cardInfo.icManufacturer {
            addInfoRow(
                icon: "building.2", title: String(localized: "IC Manufacturer"),
                description: String(localized: "ISO 15693 IC manufacturer code registered with ISO/IEC 7816-6."),
                value: String(format: "0x%02X (%d)", icManufacturer, icManufacturer)
            )
        }

        addSectionFooter(String(localized: "Technology-specific parameters for FeliCa and ISO 15693 tags."))
    }

    private func buildFooter() {
        stackView.addArrangedSubviewWithMargin(UIView())

        let uidLabel = UILabel()
        uidLabel.font = .monospacedSystemFont(
            ofSize: UIFont.preferredFont(forTextStyle: .footnote).pointSize,
            weight: .regular
        )
        uidLabel.textColor = .label.withAlphaComponent(0.25)
        uidLabel.numberOfLines = 0
        uidLabel.text = cardInfo.uid.hexString
        uidLabel.textAlignment = .center
        stackView.addArrangedSubviewWithMargin(uidLabel)
        stackView.addArrangedSubviewWithMargin(UIView())
    }
}
