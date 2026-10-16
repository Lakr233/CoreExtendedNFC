import ConfigurableKit
import CoreExtendedNFC
import ImageIO
import QuickLook
import SnapKit
import Then
import UIKit
import UniformTypeIdentifiers

class PassportDetailViewController: StackScrollController, PrivacySensitiveScreen {
    private let record: PassportRecord
    private var previewURL: URL?
    private var previews: DecodedPreviews?
    private var decodeTask: Task<Void, Never>?
    /// Marks where the photo section goes once the image has been decoded.
    private let facePlaceholder = UIView()
    /// Security stages re-derived for an imported record; `nil` until it finishes.
    private var reverifiedSecurity: PassportRecord.ReverifiedSecurity?
    private var reverifyTask: Task<Void, Never>?
    /// The Passive and Active Authentication rows, replaced once re-verification finishes.
    private weak var passiveAuthenticationRow: UIView?
    private weak var activeAuthenticationRow: UIView?

    private var previewDirectoryURL: URL {
        Self.previewDirectory(for: record.id)
    }

    nonisolated static let previewRootDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("cenfc-passport-preview", isDirectory: true)

    nonisolated static func previewDirectory(for id: UUID) -> URL {
        previewRootDirectory.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    /// Removes every extracted portrait/signature preview file.
    nonisolated static func purgeAllPreviews() {
        try? FileManager.default.removeItem(at: previewRootDirectory)
    }

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

    deinit {
        decodeTask?.cancel()
        reverifyTask?.cancel()
        // deinit is nonisolated; only touch Sendable state here.
        try? FileManager.default.removeItem(at: Self.previewDirectory(for: record.id))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        cleanupPreviewArtifacts()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
        setupExportButton()
        startDecodingPreviews()
        startReverifyingImportedRecord()
    }

    /// Re-runs passive authentication for an imported record off the main thread
    /// and re-judges its stored Active Authentication result (cached per record),
    /// then updates both rows.
    private func startReverifyingImportedRecord() {
        guard record.isImported, reverifiedSecurity == nil else { return }
        let record = record
        reverifyTask = Task { [weak self] in
            let result = await PassportReverificationCache.shared.security(for: record)
            guard !Task.isCancelled, let self else { return }
            reverifiedSecurity = result
            let rows = Self.securityRows(for: record, reverified: result)
            if let row = rows.first(where: { $0.isPassiveAuthentication }) {
                passiveAuthenticationRow = replaceSecurityRow(passiveAuthenticationRow, with: row)
            }
            if let row = rows.first(where: { $0.isActiveAuthentication }) {
                activeAuthenticationRow = replaceSecurityRow(activeAuthenticationRow, with: row)
            }
        }
    }

    /// Replaces `oldRow` in the stack with a row for `row`.
    /// - Returns: The new row view, or `oldRow` when it is not in the stack.
    private func replaceSecurityRow(_ oldRow: UIView?, with row: SecurityRow) -> UIView? {
        guard let oldRow, let index = stackView.arrangedSubviews.firstIndex(of: oldRow) else { return oldRow }
        let firstNewIndex = stackView.arrangedSubviews.count
        addSecurityRow(row)
        let added = Array(stackView.arrangedSubviews[firstNewIndex...])
        // `addInfoRow` appends the row and a separator; the old row keeps its own separator.
        added.dropFirst().forEach { $0.removeFromSuperview() }
        guard let newRow = added.first else { return oldRow }
        stackView.insertArrangedSubview(newRow, at: index)
        oldRow.removeFromSuperview()
        return newRow
    }

    /// Decodes DG2/DG7 (often JPEG 2000) once, off the main thread, then fills in the photo.
    private func startDecodingPreviews() {
        let passport = record.passport
        decodeTask = Task { [weak self] in
            let previews = await Task.detached(priority: .userInitiated) {
                Self.decodePreviews(for: passport)
            }.value
            guard !Task.isCancelled, let self else { return }
            self.previews = previews
            showFaceImage(previews)
            logPreviewDiagnostics(previews)
        }
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
        ).accessibilityLabeled(String(localized: "Export"))
    }

    @objc private func exportTapped() {
        do {
            let fileURL = try PassportDocument.exportToFile(record)
            presentExportSheet(for: [fileURL], barButtonItem: navigationItem.rightBarButtonItem)
        } catch {
            presentErrorAlert(for: error, title: String(localized: "Unable to Export Passport"))
        }
    }

    // MARK: - Face Photo

    private func buildFaceSection() {
        guard record.passport.resolvedFaceImageData != nil else { return }
        stackView.addArrangedSubview(facePlaceholder)
        if let previews {
            showFaceImage(previews)
        }
    }

    /// Builds the photo section at the placeholder once the portrait has been decoded.
    private func showFaceImage(_ previews: DecodedPreviews) {
        guard let placeholderIndex = stackView.arrangedSubviews.firstIndex(of: facePlaceholder) else { return }
        let firstNewIndex = stackView.arrangedSubviews.count
        buildFaceRows(previews)
        let added = Array(stackView.arrangedSubviews[firstNewIndex...])
        for (offset, view) in added.enumerated() {
            stackView.insertArrangedSubview(view, at: placeholderIndex + offset)
        }
        facePlaceholder.removeFromSuperview()
    }

    private func buildFaceRows(_ previews: DecodedPreviews) {
        guard let previewPayload = previews.payloads[.dg2] else { return }

        addSectionHeader(String(localized: "Photo"))

        if let image = previews.faceImage {
            let imageView = UIImageView(image: image).then {
                $0.contentMode = .scaleAspectFit
                $0.clipsToBounds = true
                $0.layer.cornerRadius = 12
                $0.layer.cornerCurve = .continuous
                $0.backgroundColor = .secondarySystemBackground
            }
            imageView.snp.makeConstraints { $0.height.equalTo(180) }
            stackView.addArrangedSubviewWithMargin(imageView) { $0.top = 8; $0.bottom = 8 }
        } else {
            addInfoRow(
                icon: "photo",
                title: String(localized: "Open Photo Preview"),
                description: String(localized: "This photo cannot be shown here. Tap to open a preview."),
                value: previewPayload.sourceFormatName,
                extraMenuActions: [
                    UIAction(
                        title: String(localized: "Open Preview"),
                        image: UIImage(systemName: "eye")
                    ) { [weak self] _ in
                        self?.previewImage(previewPayload, name: DataGroupId.dg2.name)
                    },
                ]
            )
        }
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
            description: String(localized: "Holder's date of birth from the MRZ."),
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
        let dateRow = Self.dateRowText(for: record)
        addInfoRow(
            icon: record.isImported ? "square.and.arrow.down" : "clock",
            title: dateRow.title,
            description: dateRow.description,
            value: dateFormatter.string(from: record.date)
        )

        addSectionFooter(Self.personalDataFooter(for: record))
    }

    /// Title and description of the date row: when the chip was read, or, for
    /// a record imported from a file, when it was imported.
    static func dateRowText(for record: PassportRecord) -> (title: String, description: String) {
        if record.isImported {
            return (
                String(localized: "Imported"),
                String(localized: "When this record was imported from a file. The chip was not read on this device.")
            )
        }
        return (
            String(localized: "Scan Date"),
            String(localized: "When this passport chip was last read by the reader.")
        )
    }

    static func personalDataFooter(for record: PassportRecord) -> String {
        if record.isImported {
            return String(localized: "Personal data parsed from DG1 (Machine Readable Zone) in the imported file. It was not read from a chip on this device.")
        }
        return String(localized: "Personal data parsed from DG1 (Machine Readable Zone) of the eMRTD chip.")
    }

    // MARK: - Security Report

    private func buildSecuritySection() {
        addSectionHeader(String(localized: "Security Report"))

        if record.isImported, reverifiedSecurity == nil {
            reverifiedSecurity = PassportReverificationCache.shared.cachedSecurity(for: record)
        }
        for row in Self.securityRows(for: record, reverified: reverifiedSecurity) {
            let firstNewIndex = stackView.arrangedSubviews.count
            addSecurityRow(row)
            if row.isPassiveAuthentication {
                passiveAuthenticationRow = stackView.arrangedSubviews[firstNewIndex]
            }
            if row.isActiveAuthentication {
                activeAuthenticationRow = stackView.arrangedSubviews[firstNewIndex]
            }
        }

        if record.isImported {
            addSectionFooter(String(localized: "This record was imported from a file. Passive Authentication is checked again on this device; checks that need the chip are not repeated. Read the chip again to verify it fully."))
        } else {
            addSectionFooter(String(localized: "ICAO 9303 security mechanism results. BAC authenticates the reader using MRZ data. Passive Authentication verifies data group hashes against the SOD. Active Authentication proves the chip is genuine."))
        }
    }

    private func addSecurityRow(_ row: SecurityRow) {
        addInfoRow(
            icon: row.icon,
            title: row.title,
            description: String(localized: "Security mechanism status and result detail."),
            value: row.value,
            isDestructive: row.isDestructive
        )
    }

    // MARK: - Technical

    private func buildTechnicalSection() {
        addSectionHeader(String(localized: "Technical"))

        if let ldsVersion = record.passport.ldsVersion {
            addInfoRow(
                icon: "doc.badge.gearshape",
                title: String(localized: "LDS Version"),
                description: String(localized: "Logical Data Structure version from EF.COM."),
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
            description: String(localized: "Data groups listed in EF.COM."),
            value: record.dataGroupsSummary
        )
        if let unread = Self.unreadDataGroupsSummary(record.passport) {
            addInfoRow(
                icon: "exclamationmark.triangle",
                title: String(localized: "Data Groups Not Read"),
                description: String(localized: "Data groups listed by the chip that were not read in this session."),
                value: unread
            )
        }
        addInfoRow(
            icon: "internaldrive",
            title: String(localized: "Total Raw Size"),
            description: String(localized: "Combined size of all raw data group bytes read from the chip."),
            value: String(localized: "\(String(record.totalRawSize)) bytes")
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

    /// "DG2 (Face Image): Not read; DG3 (Fingerprints): Unavailable" for the data groups that were not read,
    /// or `nil` when every listed data group was read (or no status was recorded).
    static func unreadDataGroupsSummary(_ passport: PassportModel) -> String? {
        guard let status = passport.dataGroupReadStatus else { return nil }
        let entries: [String] = DataGroupId.allCases.compactMap { dataGroup in
            guard let result = status[dataGroup] else { return nil }
            let state: String? = switch result.state {
            case .read, .notPresent: nil
            case .unavailable: String(localized: "Unavailable")
            case .failed: String(localized: "Failed")
            case .notRead: String(localized: "Not read")
            }
            return state.map { "\(dataGroup.name): \($0)" }
        }
        return entries.isEmpty ? nil : entries.joined(separator: "; ")
    }

    // MARK: - Export Info

    private func buildExportSection() {
        addSectionHeader(String(localized: "Export Data"))

        let dgOrder = DataGroupId.allCases
        for (dgId, data) in record.passport.rawDataGroups.sorted(by: {
            (dgOrder.firstIndex(of: $0.key) ?? 0) < (dgOrder.firstIndex(of: $1.key) ?? 0)
        }) {
            let isImage = (dgId == .dg2 && record.passport.resolvedFaceImageData != nil)
                || (dgId == .dg7 && record.passport.resolvedSignatureImageData != nil)
            let icon = isImage ? "photo.fill" : "doc.zipper"

            var actions: [UIMenuElement] = []

            actions.append(UIAction(
                title: String(localized: "View Hex Dump"),
                image: UIImage(systemName: "text.viewfinder")
            ) { [weak self] _ in
                let viewer = TextViewerController(
                    title: dgId.name,
                    text: data.hexDumpFormatted,
                    copiesSensitively: true
                )
                self?.navigationController?.pushViewController(viewer, animated: true)
            })

            if isImage {
                actions.append(UIAction(
                    title: String(localized: "Open Preview"),
                    image: UIImage(systemName: "eye")
                ) { [weak self] _ in
                    // Decoding finishes long before a user can open this menu; until then there is nothing to show.
                    guard let self, let payload = previews?.payloads[dgId] else { return }
                    previewImage(payload, name: dgId.name)
                })
            }

            addInfoRow(
                icon: icon,
                title: dgId.name,
                description: String(localized: "Raw binary data for this data group."),
                value: String(localized: "\(String(data.count)) bytes"),
                extraMenuActions: actions
            )
        }

        addSectionFooter(String(localized: "Tap the share button to export the full passport record."))
    }

    private func previewImage(_ payload: PreviewPayload, name: String) {
        let sanitizedName = name.replacingOccurrences(of: "/", with: "-")
        let url = previewDirectoryURL.appendingPathComponent("\(sanitizedName).\(payload.fileExtension)")

        AppLogStore.shared.debug(
            "Opening \(name) preview sourceFormat=\(payload.sourceFormatName) output=\(payload.fileExtension) bytes=\(payload.fileData.count) rendered=\(payload.hasRenderedPreview) size=\(Int(payload.imageSize.width))x\(Int(payload.imageSize.height))",
            source: "PassportDetail"
        )
        do {
            cleanupPreviewArtifacts()
            try FileManager.default.createDirectory(at: previewDirectoryURL, withIntermediateDirectories: true)
            try payload.fileData.write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            AppLogStore.shared.error(
                "Failed to write preview file for \(name): \(error.localizedDescription)",
                source: "PassportDetail"
            )
            return
        }
        let ql = QLPreviewController()
        previewURL = url
        ql.dataSource = self
        ql.delegate = self
        present(ql, animated: true)
    }

    private func cleanupPreviewArtifacts() {
        previewURL = nil

        guard FileManager.default.fileExists(atPath: previewDirectoryURL.path) else { return }

        do {
            try FileManager.default.removeItem(at: previewDirectoryURL)
            AppLogStore.shared.debug(
                "Cleaned preview artifacts at \(previewDirectoryURL.lastPathComponent)",
                source: "PassportDetail"
            )
        } catch {
            AppLogStore.shared.warning(
                "Failed to clean preview artifacts: \(error.localizedDescription)",
                source: "PassportDetail"
            )
        }
    }

    private func logPreviewDiagnostics(_ previews: DecodedPreviews) {
        logPreviewDiagnostics(for: .dg2, payload: previews.payloads[.dg2])
        logPreviewDiagnostics(for: .dg7, payload: previews.payloads[.dg7])
    }

    private func logPreviewDiagnostics(for dgId: DataGroupId, payload: PreviewPayload?) {
        let rawBytes = record.passport.rawDataGroups[dgId]?.count ?? 0

        guard let payload else {
            if rawBytes > 0 {
                AppLogStore.shared.warning(
                    "\(dgId.name) raw data exists (\(rawBytes) bytes) but no extracted preview payload is available",
                    source: "PassportDetail"
                )
            }
            return
        }

        AppLogStore.shared.debug(
            "\(dgId.name) preview payload ready raw=\(rawBytes) output=\(payload.fileExtension) bytes=\(payload.fileData.count) rendered=\(payload.hasRenderedPreview) sourceFormat=\(payload.sourceFormatName) size=\(Int(payload.imageSize.width))x\(Int(payload.imageSize.height))",
            source: "PassportDetail"
        )
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
}

// MARK: - QLPreviewControllerDataSource

extension PassportDetailViewController: QLPreviewControllerDataSource, QLPreviewControllerDelegate {
    func numberOfPreviewItems(in _: QLPreviewController) -> Int {
        previewURL != nil ? 1 : 0
    }

    func previewController(_: QLPreviewController, previewItemAt _: Int) -> any QLPreviewItem {
        (previewURL ?? URL(fileURLWithPath: "/")) as NSURL
    }

    func previewControllerDidDismiss(_: QLPreviewController) {
        cleanupPreviewArtifacts()
    }
}
