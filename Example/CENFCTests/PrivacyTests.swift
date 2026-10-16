@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing
import UIKit

private func makeTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("cenfc-privacy-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func makePassport(succeeded: Bool) throws -> PassportModel {
    let mrzString = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    let mrz = try MRZData(mrzString: mrzString)
    // Imported records re-parse DG1, so it has to hold the same MRZ.
    let dg1 = ASN1Parser.encodeTLV(tag: 0x61, value: ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data(mrzString.utf8)))
    let ok = PassportSecurityStageResult(status: .succeeded, detail: "")
    return PassportModel(
        ldsVersion: nil, unicodeVersion: nil,
        availableDataGroups: [.dg1],
        mrz: mrz, faceImageData: nil, signatureImageData: nil,
        additionalPersonalDetails: nil, additionalDocumentDetails: nil,
        securityInfos: nil, securityInfoRaw: nil,
        activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
        sod: nil, sodRaw: nil,
        passiveAuthResult: nil, activeAuthResult: nil,
        rawDataGroups: [.dg1: dg1],
        securityReport: succeeded
            ? PassportSecurityReport(
                cardAccess: ok, pace: ok, bac: ok,
                chipAuthentication: ok, passiveAuthentication: ok, activeAuthentication: ok
            )
            : PassportSecurityReport()
    )
}

// MARK: - M1: debug logs only in Debug builds

struct LogBridgeTests {
    @Test
    func `Debug messages are dropped unless the build forwards them`() {
        #expect(!AppNFCLogBridge.shouldForward(.debug, includesDebugMessages: false))
        #expect(AppNFCLogBridge.shouldForward(.debug, includesDebugMessages: true))
        #expect(AppNFCLogBridge.shouldForward(.info, includesDebugMessages: false))
        #expect(AppNFCLogBridge.shouldForward(.error, includesDebugMessages: false))
    }
}

// MARK: - M2: store file protection and backup exclusion

@MainActor
struct StoreProtectionTests {
    @Test
    func `Passport store file is excluded from backup and completely protected`() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("passport_records.json")
        let store = PassportStore(fileURL: fileURL)
        try store.add(PassportRecord(from: makePassport(succeeded: true)))
        await store.flush()

        let values = try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(values.isExcludedFromBackup == true)
        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        if let protection = attributes[.protectionKey] as? FileProtectionType {
            #expect(protection == .completeUnlessOpen)
        }
    }

    @Test
    func `Corrupt passport backups are excluded from backup too`() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("passport_records.json")
        try Data("not json".utf8).write(to: fileURL)

        let persistence = RecordFilePersistence<PassportRecord>(fileURL: fileURL, excludedFromBackup: true)
        let result = persistence.load()
        let backupURL = try #require(result.backupURL)
        #expect(try backupURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
        // An existing store file written by an older build gets the flag on load.
        #expect(try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test
    func `Other stores stay in backups`() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("scan_records.json")
        let store = ScanStore(fileURL: fileURL)
        store.add(ScanRecord(cardInfo: CardInfo(type: .ntag215, uid: Data([0x04, 0x01, 0x02]))))
        await store.flush()
        #expect(try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == false)
    }

    @Test
    func `Store writes use complete-unless-open protection`() {
        #expect(RecordFilePersistence<PassportRecord>.writingOptions.contains(.completeFileProtectionUnlessOpen))
        #expect(RecordFilePersistence<PassportRecord>.writingOptions.contains(.atomic))
    }
}

// MARK: - M3: export files

@MainActor
struct ExportPrivacyTests {
    @Test
    func `Passport export file name carries no personal data`() throws {
        let record = try PassportRecord(from: makePassport(succeeded: true))
        let url = try PassportDocument.exportToFile(record)
        defer { ExportFileLocation.remove([url]) }

        let name = url.lastPathComponent
        #expect(name == "Passport-\(record.id.uuidString.prefix(8)).cenfcpass")
        #expect(!name.contains("L898902C3"))
        #expect(!name.contains("ERIKSSON"))
    }

    @Test
    func `Removing an export deletes its directory`() throws {
        let record = try PassportRecord(from: makePassport(succeeded: true))
        let url = try PassportDocument.exportToFile(record)
        #expect(FileManager.default.fileExists(atPath: url.path))
        ExportFileLocation.remove([url])
        #expect(!FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
    }

    @Test
    func `Remove ignores files outside the export directory`() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("keep.txt")
        try Data([0x01]).write(to: file)
        ExportFileLocation.remove([file])
        #expect(FileManager.default.fileExists(atPath: file.path))
    }
}

// MARK: - M4: imported passport records

@MainActor
struct PassportImportTests {
    @Test
    func `Imported records never show a security stage as passed`() throws {
        let record = try PassportRecord(from: makePassport(succeeded: true))
        let data = try PassportDocument.export(record)
        let imported = try PassportDocument.importRecord(from: data)
        #expect(imported.isImported)

        let rows = PassportDetailViewController.securityRows(for: imported)
        #expect(rows.count == 6)
        #expect(rows.allSatisfy { $0.icon != "checkmark.circle.fill" })
        #expect(rows.filter { !$0.isPassiveAuthentication }.allSatisfy {
            $0.value == String(localized: "Imported, not re-verified")
        })
        // Passive Authentication is re-run from the bytes; this file has no SOD.
        #expect(rows.first { $0.isPassiveAuthentication }?.value == String(localized: "Verifying…"))
        let reverified = imported.reverifiedPassiveAuthentication()
        #expect(reverified.status == .notSupported)
        let reverifiedRows = PassportDetailViewController.securityRows(
            for: imported,
            reverifiedPassiveAuthentication: reverified
        )
        #expect(reverifiedRows.allSatisfy { $0.icon != "checkmark.circle.fill" })

        // A record read from the chip still shows its results.
        let chipRows = PassportDetailViewController.securityRows(for: record)
        #expect(chipRows.allSatisfy { $0.icon == "checkmark.circle.fill" })
    }

    @Test
    func `Imported origin survives the store round trip and older files decode as chip reads`() throws {
        let record = try PassportRecord(from: makePassport(succeeded: true)).markedImported()
        let encoded = try RecordJSON.makeEncoder().encode([record])
        let decoded = try RecordJSON.makeDecoder().decode([PassportRecord].self, from: encoded)
        #expect(decoded.first?.origin == .imported)
        #expect(decoded.first?.replacingID().origin == .imported)

        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [[String: Any]])
        object[0].removeValue(forKey: "origin")
        let legacy = try JSONSerialization.data(withJSONObject: object)
        #expect(try RecordJSON.makeDecoder().decode([PassportRecord].self, from: legacy).first?.origin == .chip)
    }

    @Test
    func `Import reports a conflict with a record of the same document number`() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = PassportStore(fileURL: directory.appendingPathComponent("passport_records.json"))
        let original = try PassportRecord(from: makePassport(succeeded: true))
        let incoming = try PassportRecord(from: makePassport(succeeded: false)).markedImported()

        #expect(store.importConflict(for: incoming) == nil)
        store.add(original)
        #expect(store.importConflict(for: incoming)?.id == original.id)

        // "Keep Both" adds the import without touching the stored record.
        store.importRecord(incoming, replacingExisting: false)
        #expect(store.records.count == 2)
        #expect(store.record(for: original.id)?.isImported == false)

        // "Replace" swaps the stored record's content.
        store.importRecord(incoming, replacingExisting: true)
        #expect(store.records.count == 2)
    }
}

// MARK: - L7: import size cap

struct ImportSizeCapTests {
    @Test
    func `Files over the limit are refused before reading`() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("big.cenfcpass")
        try Data(repeating: 0xAA, count: 2048).write(to: file)

        #expect(throws: ImportFileReader.ImportError.fileTooLarge(size: 2048, limit: 1024)) {
            try ImportFileReader.read(file, limit: 1024)
        }
        #expect(try ImportFileReader.read(file, limit: 2048).count == 2048)
        #expect(ImportFileReader.maxFileSize == 50 * 1024 * 1024)
    }

    @Test
    func `Background import decodes off the main thread`() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("small.bin")
        try Data([0x01, 0x02]).write(to: file)
        let onMain = try await ImportFileReader.readInBackground(file) { _ in Thread.isMainThread }
        #expect(!onMain)
    }
}

// MARK: - L2 / L8: pasteboard and app switcher

@MainActor
struct PassportScreenPrivacyTests {
    @Test
    func `Passport copies are local only and expire after two minutes`() throws {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let options = SensitivePasteboard.options(now: now)
        #expect(options[.localOnly] as? Bool == true)
        #expect(options[.expirationDate] as? Date == now.addingTimeInterval(120))
    }

    @Test
    func `Privacy cover detects passport screens anywhere in the visible stack`() throws {
        let tabBar = UITabBarController()
        let scannerNav = UINavigationController(rootViewController: UIViewController())
        let passportNav = UINavigationController(rootViewController: PassportViewController())
        passportNav.pushViewController(TextViewerController(title: "DG1", text: "61"), animated: false)
        tabBar.viewControllers = [scannerNav, passportNav]

        tabBar.selectedIndex = 0
        #expect(!PrivacyCover.isShowingSensitiveContent(tabBar))
        tabBar.selectedIndex = 1
        #expect(PrivacyCover.isShowingSensitiveContent(tabBar))
    }
}

// MARK: - M5 / F8: format offer

struct NDEFFormatOfferTests {
    @Test
    func `Only the not-formatted write error offers Format`() {
        #expect(NDEFTagOperation.isNotFormattedError(NFCError.tagNotNDEFFormatted))
        #expect(!NDEFTagOperation.isNotFormattedError(NFCError.tagLocked))
        #expect(!NDEFTagOperation.isNotFormattedError(NFCError.ndefCapacityExceeded(required: 200, capacity: 137)))
        #expect(!NDEFTagOperation.isNotFormattedError(NFCError.ndefMessageNotFound))
        // The old reason text no longer counts: matching is on the typed case only.
        #expect(!NDEFTagOperation.isNotFormattedError(
            NFCError.unsupportedOperation("The tag is not NDEF formatted; format it first")
        ))
        #expect(!NDEFTagOperation.isNotFormattedError(CancellationError()))
    }

    @Test
    func `Format is offered only for tag families the library can format`() {
        #expect(NDEFTagOperation.canFormat(.ntag))
        #expect(NDEFTagOperation.canFormat(.mifareUltralight))
        #expect(NDEFTagOperation.canFormat(.iso15693))
        #expect(!NDEFTagOperation.canFormat(.felica))
        #expect(!NDEFTagOperation.canFormat(.type4))
    }

    @Test
    func `Format operations are destructive and plain writes are not`() {
        let message = NDEFMessage(records: [])
        #expect(NDEFTagOperation.format.isDestructive)
        #expect(NDEFTagOperation.formatAndWrite(message, summary: nil).isDestructive)
        #expect(!NDEFTagOperation.write(message, summary: nil).isDestructive)
    }
}
