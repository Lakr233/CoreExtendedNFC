import CoreExtendedNFC
import Foundation
import ObjectiveC
import UIKit
import UniformTypeIdentifiers

extension Notification.Name {
    static let appStateDidChange = Notification.Name("CENFC.AppStateDidChange")
    static let diffResultAvailable = Notification.Name("CENFC.DiffResultAvailable")
}

@MainActor
class AppState {
    static let shared = AppState()

    enum ScanProfile: String, CaseIterable {
        case all
        case iso14443
        case felica
        case iso15693

        var title: String {
            switch self {
            case .all:
                String(localized: "Universal")
            case .iso14443:
                String(localized: "ISO 14443")
            case .felica:
                String(localized: "FeliCa")
            case .iso15693:
                String(localized: "ISO 15693")
            }
        }

        var explanation: String {
            switch self {
            case .all:
                String(localized: "Poll ISO 14443, FeliCa, and ISO 15693 together. Best when you are unsure which card family is nearby.")
            case .iso14443:
                String(localized: "Focus on Type A and ISO 7816 style tags, including NTAG, Type 4, DESFire, and passports.")
            case .felica:
                String(localized: "Only poll ISO 18092 / FeliCa tags for cleaner Sony Type 3 sessions.")
            case .iso15693:
                String(localized: "Only poll vicinity cards for longer-range ISO 15693 workflows.")
            }
        }

        var pollingTargets: [NFCSessionManager.PollingTarget] {
            switch self {
            case .all:
                [.iso14443, .iso18092, .iso15693]
            case .iso14443:
                [.iso14443]
            case .felica:
                [.iso18092]
            case .iso15693:
                [.iso15693]
            }
        }
    }

    struct WorkflowStep {
        enum Status: String, Hashable {
            case pending
            case active
            case completed
            case failed
        }

        let title: String
        let detail: String
        let status: Status
    }

    enum ScanOutcome {
        case dumped(MemoryDump)
        case identifiedOnly(reason: String)
        case readFailed(message: String)
    }

    struct ScanRecord: Identifiable {
        let id: UUID
        let cardInfo: CardInfo
        let outcome: ScanOutcome
        let steps: [WorkflowStep]
        let timestamp: Date

        init(
            id: UUID = UUID(),
            cardInfo: CardInfo,
            outcome: ScanOutcome,
            steps: [WorkflowStep],
            timestamp: Date = .now
        ) {
            self.id = id
            self.cardInfo = cardInfo
            self.outcome = outcome
            self.steps = steps
            self.timestamp = timestamp
        }

        var dump: MemoryDump? {
            if case let .dumped(dump) = outcome {
                return dump
            }
            return nil
        }

        var outcomeTitle: String {
            switch outcome {
            case .dumped:
                String(localized: "Dump Complete")
            case .identifiedOnly:
                String(localized: "Identification Only")
            case .readFailed:
                String(localized: "Read Incomplete")
            }
        }

        var outcomeDetail: String {
            switch outcome {
            case let .dumped(dump):
                dump.summary.userSummary
            case let .identifiedOnly(reason):
                reason
            case let .readFailed(message):
                message
            }
        }
    }

    struct NDEFReadResult {
        let cardInfo: CardInfo
        let message: NDEFMessage
        let timestamp: Date

        init(cardInfo: CardInfo, message: NDEFMessage, timestamp: Date = .now) {
            self.cardInfo = cardInfo
            self.message = message
            self.timestamp = timestamp
        }
    }

    enum ImportFormat {
        case flipperNFC
        case proxmark3MFU
    }

    private enum PreferenceKey {
        static let scanProfile = "wiki.qaq.cenfc.scan.profile"
    }

    private let log = AppLogStore.shared
    private let defaults = UserDefaults.standard

    private(set) var records: [ScanRecord] = []
    private(set) var isBusy = false
    private(set) var statusText = String(localized: "Ready to scan and dump.")
    private(set) var errorMessage: String?
    private(set) var lastNDEFReadResult: NDEFReadResult?

    var selectedProfile: ScanProfile {
        get {
            ScanProfile(rawValue: defaults.string(forKey: PreferenceKey.scanProfile) ?? "") ?? .all
        }
        set {
            defaults.set(newValue.rawValue, forKey: PreferenceKey.scanProfile)
            publish()
        }
    }

    var latestRecord: ScanRecord? {
        records.first
    }

    func scanAndDump() async {
        guard !isBusy else { return }

        isBusy = true
        errorMessage = nil
        statusText = String(localized: "Waiting for tag…")
        publish()
        log.info("Starting unified scan and dump with profile=\(selectedProfile.rawValue)", source: "Dump")

        do {
            let manager = NFCSessionManager()
            defer {
                manager.invalidate()
            }

            let (rawInfo, transport) = try await manager.scan(for: selectedProfile.pollingTargets)
            let refinedInfo = try await CoreExtendedNFC.refineCardInfo(rawInfo, transport: transport)

            manager.setAlertMessage(refinedInfo.type.description)
            statusText = String(localized: "Connected to \(refinedInfo.type.description)")
            publish()
            log.info("Connected to \(refinedInfo.type.description) UID:\(refinedInfo.uid.hexDump)", source: "Dump")

            var steps = baseSteps(for: refinedInfo, didRefine: refinedInfo.type != rawInfo.type)

            let outcome: ScanOutcome
            if refinedInfo.type.isOperableOnIOS {
                do {
                    statusText = String(localized: "Reading memory…")
                    publish()
                    manager.setAlertMessage(String(localized: "Reading…"))
                    let dump = try await CoreExtendedNFC.dumpCard(info: refinedInfo, transport: transport)
                    steps.append(
                        WorkflowStep(
                            title: String(localized: "Read accessible memory"),
                            detail: readStepDetail(for: refinedInfo, success: true),
                            status: .completed
                        )
                    )
                    outcome = .dumped(dump)
                    log.info("Dump completed for \(refinedInfo.type.description)", source: "Dump")
                    manager.setAlertMessage(String(localized: "Dump complete"))
                } catch {
                    let message = Self.displayMessage(for: error) ?? error.localizedDescription
                    steps.append(
                        WorkflowStep(
                            title: String(localized: "Read accessible memory"),
                            detail: "\(readStepDetail(for: refinedInfo, success: false)) Error: \(message)",
                            status: .failed
                        )
                    )
                    outcome = .readFailed(message: message)
                    log.warning("Dump failed after identification: \(message)", source: "Dump")
                    manager.setAlertMessage(String(localized: "Identified, read incomplete"))
                }
            } else {
                let reason = readRestrictionDescription(for: refinedInfo.type)
                steps.append(
                    WorkflowStep(
                        title: String(localized: "Read accessible memory"),
                        detail: reason,
                        status: .failed
                    )
                )
                outcome = .identifiedOnly(reason: reason)
                log.info("Tag identified only: \(reason)", source: "Dump")
                manager.setAlertMessage(String(localized: "Identification only"))
            }

            records.insert(ScanRecord(cardInfo: refinedInfo, outcome: outcome, steps: steps), at: 0)
            statusText = records.first?.outcomeDetail ?? String(localized: "Done")
            publish()
        } catch {
            errorMessage = Self.displayMessage(for: error)
            statusText = errorMessage ?? String(localized: "Scan cancelled.")
            if let errorMessage {
                log.error("Scan failed: \(errorMessage)", source: "Dump")
            } else {
                log.info("Scan cancelled.", source: "Dump")
            }
            publish()
        }

        isBusy = false
        publish()
    }

    func readNDEF() async {
        guard !isBusy else { return }

        isBusy = true
        errorMessage = nil
        statusText = String(localized: "Waiting for tag…")
        publish()
        log.info("Starting NDEF read", source: "NDEF")

        do {
            let manager = NFCSessionManager()
            defer { manager.invalidate() }

            let (rawInfo, transport) = try await manager.scan(for: selectedProfile.pollingTargets)
            let info = try await CoreExtendedNFC.refineCardInfo(rawInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Reading NDEF…"))

            let message = try await CoreExtendedNFC.readNDEF(info: info, transport: transport)
            lastNDEFReadResult = NDEFReadResult(cardInfo: info, message: message)
            statusText = String(localized: "\(message.records.count) record(s) read from \(info.type.description)")
            log.info("NDEF read: \(message.records.count) record(s)", source: "NDEF")
            manager.setAlertMessage(String(localized: "Read \(message.records.count) record(s)"))
        } catch {
            errorMessage = Self.displayMessage(for: error)
            statusText = errorMessage ?? String(localized: "Scan cancelled.")
            if let errorMessage {
                log.error("NDEF read failed: \(errorMessage)", source: "NDEF")
            }
            publish()
        }

        isBusy = false
        publish()
    }

    func writeNDEF(_ message: NDEFMessage) async {
        guard !isBusy else { return }

        isBusy = true
        errorMessage = nil
        statusText = String(localized: "Waiting for tag…")
        publish()
        log.info("Starting NDEF write", source: "NDEF")

        do {
            let manager = NFCSessionManager()
            defer { manager.invalidate() }

            let (rawInfo, transport) = try await manager.scan(for: selectedProfile.pollingTargets)
            let info = try await CoreExtendedNFC.refineCardInfo(rawInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Writing NDEF…"))

            try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
            statusText = String(localized: "NDEF written to \(info.type.description)")
            log.info("NDEF write succeeded on \(info.type.description)", source: "NDEF")
            manager.setAlertMessage(String(localized: "Write complete"))
        } catch {
            errorMessage = Self.displayMessage(for: error)
            statusText = errorMessage ?? String(localized: "Scan cancelled.")
            if let errorMessage {
                log.error("NDEF write failed: \(errorMessage)", source: "NDEF")
            }
            publish()
        }

        isBusy = false
        publish()
    }

    func importDump(from url: URL, format: ImportFormat) {
        log.info("Importing dump from \(url.lastPathComponent)", source: "Import")

        do {
            let dump: MemoryDump
            switch format {
            case .flipperNFC:
                let text = try String(contentsOf: url, encoding: .utf8)
                dump = try CoreExtendedNFC.importFlipperNFC(text)
            case .proxmark3MFU:
                let data = try Data(contentsOf: url)
                dump = try CoreExtendedNFC.importProxmark3MFU(data)
            }

            let record = ScanRecord(
                cardInfo: dump.cardInfo,
                outcome: .dumped(dump),
                steps: [
                    WorkflowStep(
                        title: String(localized: "Import file"),
                        detail: String(localized: "Loaded from \(url.lastPathComponent)"),
                        status: .completed
                    ),
                ]
            )
            errorMessage = nil
            records.insert(record, at: 0)
            statusText = String(localized: "Imported \(url.lastPathComponent)")
            log.info("Import succeeded", source: "Import")
            publish()
        } catch {
            let message = error.localizedDescription
            errorMessage = message
            statusText = message
            log.error("Import failed: \(message)", source: "Import")
            publish()
        }
    }

    func presentImportPicker(format: ImportFormat, from controller: UIViewController) {
        let contentTypes: [UTType] = switch format {
        case .flipperNFC:
            [.plainText, .data]
        case .proxmark3MFU:
            [.data]
        }

        let picker = UIDocumentPickerViewController(forOpeningContentTypes: contentTypes)
        picker.allowsMultipleSelection = false
        let delegate = ImportPickerDelegate(format: format)
        picker.delegate = delegate
        objc_setAssociatedObject(
            picker,
            &ImportPickerDelegate.associatedKey,
            delegate,
            .OBJC_ASSOCIATION_RETAIN_NONATOMIC
        )
        controller.present(picker, animated: true)
    }

    func restoreToTag() async {
        guard !isBusy else { return }
        guard let record = latestRecord, let dump = record.dump else {
            setError(String(localized: "No dump available to restore."))
            return
        }

        isBusy = true
        errorMessage = nil
        statusText = String(localized: "Waiting for tag…")
        publish()
        log.info("Starting restore to tag", source: "Restore")

        let manager = NFCSessionManager()
        do {
            let (rawInfo, transport) = try await manager.scan(
                for: [.iso14443],
                message: String(localized: "Hold your iPhone near the target tag")
            )
            let info = try await CoreExtendedNFC.refineCardInfo(rawInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Restoring…"))
            statusText = String(localized: "Restoring pages…")
            publish()

            try await CoreExtendedNFC.restoreUltralight(dump: dump, info: info, transport: transport)
            statusText = String(localized: "Restore complete.")
            log.info("Restore to tag succeeded", source: "Restore")
            manager.setAlertMessage(String(localized: "Restore complete"))
            manager.invalidate()
        } catch {
            if let message = Self.displayMessage(for: error) {
                errorMessage = message
                statusText = message
                log.error("Restore failed: \(message)", source: "Restore")
                manager.invalidate(errorMessage: message)
            } else {
                statusText = String(localized: "Restore cancelled.")
                log.info("Restore cancelled.", source: "Restore")
                manager.invalidate()
            }
        }

        isBusy = false
        publish()
    }

    func scanAndDiff(baseline: MemoryDump, requestID: UUID = UUID()) async {
        guard !isBusy else { return }

        isBusy = true
        errorMessage = nil
        statusText = String(localized: "Scan a second tag to compare…")
        publish()
        log.info("Starting diff scan", source: "Diff")

        let manager = NFCSessionManager()
        do {
            let (rawInfo, transport) = try await manager.scan(for: selectedProfile.pollingTargets)
            let info = try await CoreExtendedNFC.refineCardInfo(rawInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Reading for comparison…"))

            let newDump = try await CoreExtendedNFC.dumpCard(info: info, transport: transport)
            let diff = CoreExtendedNFC.diffDumps(baseline, newDump)

            statusText = diff.hasDifferences
                ? String(localized: "Differences found.")
                : String(localized: "Dumps are identical.")
            log.info(
                "Diff completed: \(diff.hasDifferences ? "differences found" : "identical")",
                source: "Diff"
            )
            manager.setAlertMessage(String(localized: "Comparison complete"))
            manager.invalidate()

            publish()

            NotificationCenter.default.post(
                name: .diffResultAvailable,
                object: self,
                userInfo: [
                    "diff": diff,
                    "requestID": requestID,
                ]
            )
        } catch {
            if let message = Self.displayMessage(for: error) {
                errorMessage = message
                statusText = message
                log.error("Diff scan failed: \(message)", source: "Diff")
                manager.invalidate(errorMessage: message)
            } else {
                statusText = String(localized: "Comparison cancelled.")
                log.info("Diff scan cancelled.", source: "Diff")
                manager.invalidate()
            }
            publish()
        }

        isBusy = false
        publish()
    }

    func clearHistory() {
        records.removeAll()
        errorMessage = nil
        statusText = String(localized: "Ready to scan and dump.")
        publish()
    }

    func setError(_ message: String) {
        errorMessage = message
        publish()
    }

    func dismissError() {
        errorMessage = nil
        publish()
    }

    static func displayMessage(for error: Error) -> String? {
        guard let nfcError = error as? NFCError else {
            return error.localizedDescription
        }

        switch nfcError {
        case .nfcNotAvailable:
            return String(localized: "NFC is not available on this device. Please check that NFC is enabled in Settings.")
        case .sessionTimeout:
            return String(localized: "Session timed out. Hold the phone steady and try again.")
        case .tagConnectionLost:
            return String(localized: "Tag connection lost. Keep the top of the iPhone still on the tag.")
        case .tagNotSupported:
            return String(localized: "Tag type not supported.")
        case let .sessionInvalidated(reason):
            if reason.localizedCaseInsensitiveContains("cancel")
                || reason.localizedCaseInsensitiveContains("invalidate")
            {
                return nil
            }
            return reason
        case let .notOperableOnIOS(type):
            return String(localized: "\(type.description) can be identified, but iPhone cannot operate on it.")
        case let .unsupportedOperation(message):
            return message
        case let .desfireError(status):
            return String(localized: "DESFire error: \(status.description)")
        case let .bacFailed(message):
            return message
        case let .secureMessagingError(message):
            return message
        case let .dataGroupParseFailed(message):
            return message
        case let .dataGroupNotAvailable(message):
            return message
        default:
            return String(localized: "NFC error: \(nfcError.localizedDescription)")
        }
    }

    private func publish() {
        NotificationCenter.default.post(name: .appStateDidChange, object: self)
    }

    private func baseSteps(for info: CardInfo, didRefine: Bool) -> [WorkflowStep] {
        var steps = [
            WorkflowStep(
                title: String(localized: "Poll and anti-collision"),
                detail: String(localized: "CoreNFC negotiated a transport using the \(selectedProfile.title) polling profile."),
                status: .completed
            ),
            WorkflowStep(
                title: String(localized: "Fingerprint the card"),
                detail: fingerprintDetail(for: info),
                status: .completed
            ),
        ]

        if didRefine {
            steps.append(
                WorkflowStep(
                    title: String(localized: "Refine product family"),
                    detail: String(localized: "The demo issued family-specific probes so coarse tag identification could be narrowed to a concrete product family."),
                    status: .completed
                )
            )
        }

        return steps
    }

    private func fingerprintDetail(for info: CardInfo) -> String {
        switch info.type.family {
        case .ntag, .mifareUltralight, .mifareClassic, .mifarePlus, .mifareDesfire:
            String(localized: "Type A identification used ATQA/SAK and optional ATS bytes, following ISO/IEC 14443-3 and NXP identification tables.")
        case .type4:
            String(localized: "ISO 7816 classification used the initially selected AID plus a Type 4 Capability Container probe.")
        case .felica:
            String(localized: "FeliCa identification used System Code and IDm values from the polling response.")
        case .iso15693:
            String(localized: "ISO 15693 identification used vicinity-card inventory information and manufacturer code.")
        case .passport:
            String(localized: "The chip exposes itself as ISO 14443-4 and then enters an ICAO 9303 passport workflow.")
        case .jewelTopaz:
            String(localized: "Topaz / Type 1 tags are identifiable, but iPhone does not expose the low-level operations needed for full dumps.")
        case .iso14443B, .unknown:
            String(localized: "The app captured enough transport metadata to classify the tag family, but not enough to start a robust dump routine.")
        }
    }

    private func readRestrictionDescription(for type: CardType) -> String {
        switch type.family {
        case .mifareClassic:
            String(localized: "iPhone can identify MIFARE Classic, but it cannot perform Crypto1 authentication, so memory reads stop after identification.")
        case .mifarePlus:
            String(localized: "This MIFARE Plus security level is not exposed in a way iPhone can dump safely, so the demo preserves only identification metadata.")
        case .jewelTopaz:
            String(localized: "Topaz / Type 1 low-level read primitives are not implemented in this demo.")
        case .passport:
            String(localized: "Passport-class chips need the dedicated Passport workflow because the session must enter BAC and secure messaging before LDS files can be read.")
        default:
            String(localized: "\(type.description) is identifiable, but this demo does not yet provide a safe dump routine for it.")
        }
    }

    private func readStepDetail(for info: CardInfo, success: Bool) -> String {
        switch info.type.family {
        case .ntag, .mifareUltralight:
            if info.type == .mifareUltralightC {
                return success
                    ? String(localized: "Read Type 2 pages with READ, but stopped before Ultralight C secret key pages and any later 3DES-protected window.")
                    : String(localized: "The demo reached the Type 2 read phase, but an Ultralight C protection boundary or page read failure stopped the snapshot.")
            }
            return success
                ? String(localized: "Read pages with Type 2 style READ and FAST_READ commands, then checked the TLV area for NDEF content.")
                : String(localized: "The demo reached the Type 2 read phase, but one of the page reads failed before a stable dump could be saved.")
        case .mifareDesfire:
            return success
                ? String(localized: "Enumerated DESFire applications and files, then collected accessible file payloads.")
                : String(localized: "The demo reached the DESFire file enumeration phase, but a file operation or permission boundary stopped the dump.")
        case .type4:
            return success
                ? String(localized: "Selected the NDEF application and files, parsed the Capability Container, then saved the Type 4 NDEF payload.")
                : String(localized: "The demo reached the Type 4 file-selection phase, but an ISO 7816 APDU or file access boundary stopped the dump.")
        case .felica:
            return success
                ? String(localized: "Read the Type 3 attribute and NDEF blocks when present, then probed plain-readable FeliCa services.")
                : String(localized: "The demo reached the FeliCa probing phase, but a block or service read failed before the snapshot finished.")
        case .iso15693:
            return success
                ? String(localized: "Walked the ISO 15693 block map using system information, then checked the Type 5 user area for NDEF TLVs.")
                : String(localized: "The demo reached the ISO 15693 block-read phase, but a block or security-status read failed before the dump finished.")
        default:
            return success
                ? String(localized: "Completed the family-specific dump routine and saved the result for offline review.")
                : String(localized: "The demo identified the tag and attempted the family-specific dump routine, but did not finish cleanly.")
        }
    }
}

@MainActor
private class ImportPickerDelegate: NSObject, UIDocumentPickerDelegate {
    nonisolated(unsafe) static var associatedKey = 0
    let format: AppState.ImportFormat

    init(format: AppState.ImportFormat) {
        self.format = format
    }

    nonisolated func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else { return }
        let format = format
        Task { @MainActor in
            _ = url.startAccessingSecurityScopedResource()
            defer { url.stopAccessingSecurityScopedResource() }
            AppState.shared.importDump(from: url, format: format)
        }
    }
}
