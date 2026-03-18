import ConfigurableKit
import CoreExtendedNFC
import SnapKit
import Then
import UIKit

class PassportDetailViewController: StackScrollController {
    private let record: PassportRecord

    private let dateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .medium
    }

    init(record: PassportRecord) {
        self.record = record
        super.init(nibName: nil, bundle: nil)
        title = record.displayName
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
        buildFaceSection()
        buildPersonalSection()
        buildSecuritySection()
        buildTechnicalSection()
        buildExportSection()
        buildFooter()
    }

    // MARK: - Export Button

    private func setupExportButton() {
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.up"),
            style: .plain,
            target: self,
            action: #selector(exportTapped)
        )
    }

    @objc private func exportTapped() {
        do {
            let fileURL = try PassportDocument.exportToFile(record)
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

    // MARK: - Face Photo

    private func buildFaceSection() {
        guard let faceData = record.passport.faceImageData, let image = UIImage(data: faceData) else { return }

        addSectionHeader(String(localized: "Photo"))

        let imageView = UIImageView(image: image).then {
            $0.contentMode = .scaleAspectFit
            $0.clipsToBounds = true
            $0.layer.cornerRadius = 12
            $0.layer.cornerCurve = .continuous
            $0.backgroundColor = .secondarySystemBackground
        }
        imageView.snp.makeConstraints { $0.height.equalTo(180) }
        stackView.addArrangedSubviewWithMargin(imageView) { $0.top = 8; $0.bottom = 8 }
        stackView.addArrangedSubview(SeparatorView())
    }

    // MARK: - Personal Information

    private func buildPersonalSection() {
        addSectionHeader(String(localized: "Personal Information"))

        addInfoRow(
            icon: "person.fill",
            title: String(localized: "Full Name"),
            description: String(localized: "Name as printed in the MRZ of the travel document."),
            value: record.displayName
        )
        addInfoRow(
            icon: "doc.text",
            title: String(localized: "Document Number"),
            description: String(localized: "Unique document number assigned by the issuing authority."),
            value: record.passport.mrz?.documentNumber ?? ""
        )
        addInfoRow(
            icon: "doc.badge.gearshape",
            title: String(localized: "Document Code"),
            description: String(localized: "ICAO document type code (P for passport, I for ID card)."),
            value: record.passport.mrz?.documentCode ?? ""
        )
        addInfoRow(
            icon: "globe",
            title: String(localized: "Nationality"),
            description: String(localized: "Three-letter country code of the holder's nationality."),
            value: record.passport.mrz?.nationality ?? ""
        )
        addInfoRow(
            icon: "building.columns",
            title: String(localized: "Issuing State"),
            description: String(localized: "Three-letter code of the state that issued this document."),
            value: record.passport.mrz?.issuingState ?? ""
        )
        addInfoRow(
            icon: "calendar",
            title: String(localized: "Date of Birth"),
            description: String(localized: "Holder's date of birth in YYMMDD format from the MRZ."),
            value: record.formattedDOB
        )
        addInfoRow(
            icon: "person.crop.circle",
            title: String(localized: "Sex"),
            description: String(localized: "Sex of the document holder as recorded in the MRZ."),
            value: (record.passport.mrz?.sex ?? "").isEmpty ? "-" : (record.passport.mrz?.sex ?? "")
        )
        addInfoRow(
            icon: "calendar.badge.clock",
            title: String(localized: "Date of Expiry"),
            description: String(localized: "Expiration date of the travel document from the MRZ."),
            value: record.formattedExpiry
        )
        addInfoRow(
            icon: "clock",
            title: String(localized: "Scan Date"),
            description: String(localized: "When this passport chip was last read by the reader."),
            value: dateFormatter.string(from: record.date)
        )

        addSectionFooter(String(localized: "Personal data parsed from DG1 (Machine Readable Zone) of the eMRTD chip."))
    }

    // MARK: - Security Report

    private func buildSecuritySection() {
        addSectionHeader(String(localized: "Security Report"))

        let report = record.passport.securityReport
        addSecurityRow(title: String(localized: "Card Access"), stage: report.cardAccess)
        addSecurityRow(title: String(localized: "PACE"), stage: report.pace)
        addSecurityRow(title: String(localized: "BAC"), stage: report.bac)
        addSecurityRow(title: String(localized: "Chip Authentication"), stage: report.chipAuthentication)
        addSecurityRow(title: String(localized: "Passive Authentication"), stage: report.passiveAuthentication)
        addSecurityRow(title: String(localized: "Active Authentication"), stage: report.activeAuthentication)

        addSectionFooter(String(localized: "ICAO 9303 security mechanism results. BAC authenticates the reader using MRZ data. Passive Authentication verifies data group hashes against the SOD. Active Authentication proves the chip is genuine."))
    }

    // MARK: - Technical

    private func buildTechnicalSection() {
        addSectionHeader(String(localized: "Technical"))

        if let ldsVersion = record.passport.ldsVersion {
            addInfoRow(
                icon: "doc.badge.gearshape",
                title: String(localized: "LDS Version"),
                description: String(localized: "Logical Data Structure version from the COM data group."),
                value: ldsVersion
            )
        }
        if let unicodeVersion = record.passport.unicodeVersion {
            addInfoRow(
                icon: "textformat",
                title: String(localized: "Unicode Version"),
                description: String(localized: "Unicode version used for text encoding on this chip."),
                value: unicodeVersion
            )
        }
        addInfoRow(
            icon: "square.stack.3d.up",
            title: String(localized: "Available Data Groups"),
            description: String(localized: "Data groups present on the chip as advertised by COM."),
            value: record.dataGroupsSummary
        )
        addInfoRow(
            icon: "internaldrive",
            title: String(localized: "Total Raw Size"),
            description: String(localized: "Combined size of all raw data group bytes read from the chip."),
            value: "\(record.totalRawSize) bytes"
        )

        let mrzString = record.passport.mrz?.mrzString ?? ""
        if !mrzString.isEmpty {
            addInfoRow(
                icon: "barcode",
                title: String(localized: "MRZ String"),
                description: String(localized: "Complete Machine Readable Zone text as read from DG1."),
                value: mrzString
            )
        }

        addSectionFooter(String(localized: "eMRTD chip metadata and raw data group information."))
    }

    // MARK: - Export Info

    private func buildExportSection() {
        addSectionHeader(String(localized: "Export Data"))

        let dgOrder = DataGroupId.allCases
        for (dgId, data) in record.passport.rawDataGroups.sorted(by: {
            (dgOrder.firstIndex(of: $0.key) ?? 0) < (dgOrder.firstIndex(of: $1.key) ?? 0)
        }) {
            addInfoRow(
                icon: "doc.zipper",
                title: dgId.name,
                description: String(localized: "Raw binary data for this data group."),
                value: "\(data.count) bytes"
            )
        }

        addSectionFooter(String(localized: "Tap the share button to export the full passport record."))
    }

    // MARK: - Footer

    private func buildFooter() {
        stackView.addArrangedSubviewWithMargin(UIView())

        let docLabel = UILabel().then {
            $0.font = .monospacedSystemFont(
                ofSize: UIFont.preferredFont(forTextStyle: .footnote).pointSize,
                weight: .regular
            )
            $0.textColor = .label.withAlphaComponent(0.25)
            $0.numberOfLines = 0
            $0.text = record.passport.mrz?.documentNumber ?? ""
            $0.textAlignment = .center
        }
        stackView.addArrangedSubviewWithMargin(docLabel)
        stackView.addArrangedSubviewWithMargin(UIView())
    }

    private func addSecurityRow(
        title: String,
        stage: PassportSecurityStageResult
    ) {
        let (icon, isDestructive) = securityIcon(for: stage.status.rawValue)
        let displayValue = stage.detail.isEmpty ? stage.status.rawValue : stage.detail
        addInfoRow(
            icon: icon,
            title: title,
            description: String(localized: "Security mechanism status and result detail."),
            value: displayValue,
            isDestructive: isDestructive
        )
    }

    private func securityIcon(for status: String) -> (String, Bool) {
        switch status {
        case "succeeded": ("checkmark.circle.fill", false)
        case "failed": ("xmark.circle.fill", true)
        case "fallback": ("exclamationmark.triangle.fill", false)
        case "skipped", "notAdvertised", "notSupported": ("minus.circle", false)
        default: ("circle.dotted", false)
        }
    }
}
