import ConfigurableKit
import CoreExtendedNFC
import ImageIO
import QuickLook
import SnapKit
import Then
import UIKit
import UniformTypeIdentifiers

class PassportDetailViewController: StackScrollController {
    nonisolated struct PreviewPayload: Sendable {
        let fileData: Data
        let fileExtension: String
        let sourceFormatName: String
        let imageSize: CGSize
        let hasRenderedPreview: Bool
    }

    /// Everything derived from the portrait and signature images, decoded once off the main thread.
    nonisolated struct DecodedPreviews: Sendable {
        var payloads: [DataGroupId: PreviewPayload] = [:]
        var faceImage: UIImage?
    }

    private let record: PassportRecord
    private var previewURL: URL?
    private var previews: DecodedPreviews?
    private var decodeTask: Task<Void, Never>?
    /// Marks where the photo section goes once the image has been decoded.
    private let facePlaceholder = UIView()

    private var previewDirectoryURL: URL {
        Self.previewDirectory(for: record.id)
    }

    nonisolated static func previewDirectory(for id: UUID) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("cenfc-passport-preview", isDirectory: true)
            .appendingPathComponent(id.uuidString, isDirectory: true)
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

    nonisolated static func decodePreviews(for passport: PassportModel) -> DecodedPreviews {
        var result = DecodedPreviews()
        for (dgId, data) in [
            (DataGroupId.dg2, passport.resolvedFaceImageData),
            (DataGroupId.dg7, passport.resolvedSignatureImageData),
        ] {
            guard let data else { continue }
            let image = decodeImage(from: data)
            if dgId == .dg2 {
                result.faceImage = image
            }
            result.payloads[dgId] = previewPayload(for: data, decodedImage: image)
        }
        return result
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
            let activity = UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
            activity.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItem
            present(activity, animated: true)
        } catch {
            presentErrorAlert(for: error, title: String(localized: "Export Error"))
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
                description: String(localized: "The portrait is available, but inline decoding is not supported on this device. Tap to open the extracted image preview."),
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
                    text: data.hexDumpFormatted
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

    nonisolated private static func previewPayload(for data: Data, decodedImage: UIImage?) -> PreviewPayload? {
        let formatName = inferPreviewFormat(for: data)
        if let image = decodedImage,
           let jpegData = image.jpegData(compressionQuality: 0.95)
        {
            return PreviewPayload(
                fileData: jpegData,
                fileExtension: "jpg",
                sourceFormatName: formatName,
                imageSize: image.size,
                hasRenderedPreview: true
            )
        }

        guard let nativeExtension = nativePreviewExtension(for: data) else { return nil }
        return PreviewPayload(
            fileData: data,
            fileExtension: nativeExtension,
            sourceFormatName: formatName,
            imageSize: .zero,
            hasRenderedPreview: false
        )
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
            try payload.fileData.write(to: url)
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

    nonisolated private static func decodeImage(from data: Data) -> UIImage? {
        if let image = UIImage(data: data) {
            return image
        }

        let sourceOptions = [
            kCGImageSourceShouldCache: false,
        ] as CFDictionary

        if let source = CGImageSourceCreateWithData(data as CFData, sourceOptions),
           let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil)
        {
            return UIImage(cgImage: cgImage)
        }

        let hintedTypes = [
            "public.jpeg-2000",
            UTType.jpeg.identifier,
            UTType.png.identifier,
        ]

        for hintedType in hintedTypes {
            let hintOptions = [
                kCGImageSourceShouldCache: false,
                kCGImageSourceTypeIdentifierHint: hintedType,
            ] as CFDictionary

            if let source = CGImageSourceCreateWithData(data as CFData, hintOptions),
               let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil)
            {
                return UIImage(cgImage: cgImage)
            }
        }

        return nil
    }

    nonisolated private static func inferPreviewFormat(for data: Data) -> String {
        if data.starts(with: [0xFF, 0xD8, 0xFF]) {
            return "JPEG"
        }

        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) {
            return "PNG"
        }

        if data.starts(with: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) {
            return "JPEG2000"
        }

        if data.starts(with: [0xFF, 0x4F, 0xFF, 0x51]) {
            return "JPEG2000 Codestream"
        }

        return "Unknown"
    }

    nonisolated private static func nativePreviewExtension(for data: Data) -> String? {
        if data.starts(with: [0xFF, 0xD8, 0xFF]) {
            return "jpg"
        }

        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) {
            return "png"
        }

        if data.starts(with: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) {
            return "jp2"
        }

        if data.starts(with: [0xFF, 0x4F, 0xFF, 0x51]) {
            return "j2c"
        }

        return nil
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
        let (icon, isDestructive) = securityIcon(for: stage.status)
        let displayValue = stage.detail.isEmpty ? Self.statusTitle(stage.status) : stage.detail
        addInfoRow(
            icon: icon,
            title: title,
            description: String(localized: "Security mechanism status and result detail."),
            value: displayValue,
            isDestructive: isDestructive
        )
    }

    private func securityIcon(for status: PassportSecurityStageStatus) -> (String, Bool) {
        switch status {
        case .succeeded: ("checkmark.circle.fill", false)
        case .failed: ("xmark.circle.fill", true)
        case .fallback: ("exclamationmark.triangle.fill", false)
        case .skipped, .notAdvertised, .notSupported: ("minus.circle", false)
        case .pending: ("circle.dotted", false)
        }
    }

    static func statusTitle(_ status: PassportSecurityStageStatus) -> String {
        switch status {
        case .pending: String(localized: "Pending")
        case .succeeded: String(localized: "Succeeded")
        case .failed: String(localized: "Failed")
        case .fallback: String(localized: "Fallback")
        case .skipped: String(localized: "Skipped")
        case .notAdvertised: String(localized: "Not Advertised")
        case .notSupported: String(localized: "Not Supported")
        }
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
