@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing
import UIKit

private func makeTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("cenfc-r4-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private let mrzString = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"

private func makePassport(
    dg1Suffix: UInt8 = 0,
    sod: Data? = nil,
    active: ActiveAuthenticationResult? = nil
) throws -> PassportModel {
    let mrz = try MRZData(mrzString: mrzString)
    var dg1 = ASN1Parser.encodeTLV(tag: 0x61, value: ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data(mrzString.utf8)))
    if dg1Suffix != 0 {
        dg1.append(dg1Suffix)
    }
    return PassportModel(
        ldsVersion: nil, unicodeVersion: nil,
        availableDataGroups: [.dg1],
        mrz: mrz, faceImageData: nil, signatureImageData: nil,
        additionalPersonalDetails: nil, additionalDocumentDetails: nil,
        securityInfos: nil, securityInfoRaw: nil,
        activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
        sod: nil, sodRaw: sod,
        passiveAuthResult: nil, activeAuthResult: active,
        rawDataGroups: [.dg1: dg1]
    )
}

// MARK: - C1: sensitive text viewer

@MainActor
struct SensitiveTextViewTests {
    @Test
    func `Sensitive text view only offers copy and select`() {
        let view = SensitiveTextView()
        #expect(!view.isEditable)
        #expect(view.canPerformAction(#selector(UIResponderStandardEditActions.copy(_:)), withSender: nil))
        #expect(view.canPerformAction(#selector(UIResponderStandardEditActions.selectAll(_:)), withSender: nil))
        #expect(!view.canPerformAction(NSSelectorFromString("_share:"), withSender: nil))
        #expect(!view.canPerformAction(NSSelectorFromString("_define:"), withSender: nil))
        #expect(!view.canPerformAction(NSSelectorFromString("_translate:"), withSender: nil))
        #expect(!view.canPerformAction(#selector(UIResponderStandardEditActions.cut(_:)), withSender: nil))
        #expect(view.textDragInteraction?.isEnabled != true)

        let menu = view.textView(view, editMenuForTextIn: NSRange(location: 0, length: 1), suggestedActions: [])
        #expect(menu?.children.count == 1)
    }

    @Test
    func `Copying from the sensitive text view goes through the sensitive pasteboard`() throws {
        let pasteboard = UIPasteboard.withUniqueName()
        defer { UIPasteboard.remove(withName: pasteboard.name) }
        let view = SensitiveTextView()
        view.pasteboard = pasteboard
        view.text = "P<UTOERIKSSON"
        view.selectedRange = NSRange(location: 2, length: 3)
        #expect(view.textToCopy == "UTO")
        view.copy(nil)
        #expect(pasteboard.string == "UTO")
    }

    @Test
    func `Text viewer uses the sensitive text view only for personal data`() {
        #expect(TextViewerController(title: "DG1", text: "x", copiesSensitively: true).textView is SensitiveTextView)
        #expect(!(TextViewerController(title: "Log", text: "x").textView is SensitiveTextView))
    }
}

// MARK: - C2: Documents/Inbox copies

struct InboxCleanupTests {
    @Test
    func `Only files inside the inbox are removed`() throws {
        let root = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let inbox = root.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let inboxFile = inbox.appendingPathComponent("passport.cenfcpass")
        let outsideFile = root.appendingPathComponent("passport.cenfcpass")
        try Data([1]).write(to: inboxFile)
        try Data([1]).write(to: outsideFile)

        #expect(ImportFileReader.isInInbox(inboxFile, inbox: inbox))
        #expect(!ImportFileReader.isInInbox(outsideFile, inbox: inbox))
        #expect(!ImportFileReader.isInInbox(inbox, inbox: inbox))
        #expect(!ImportFileReader.removeIfInInbox(outsideFile, inbox: inbox))
        #expect(FileManager.default.fileExists(atPath: outsideFile.path))
        #expect(ImportFileReader.removeIfInInbox(inboxFile, inbox: inbox))
        #expect(!FileManager.default.fileExists(atPath: inboxFile.path))
    }

    @Test
    func `Purging the inbox keeps the file being opened`() throws {
        let root = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let inbox = root.appendingPathComponent("Inbox", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let stale = inbox.appendingPathComponent("old.cenfc")
        let opening = inbox.appendingPathComponent("new.cenfc")
        try Data([1]).write(to: stale)
        try Data([2]).write(to: opening)

        ImportFileReader.purgeInbox(inbox, keeping: [opening])
        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(FileManager.default.fileExists(atPath: opening.path))
    }

    @Test
    func `Reading an inbox copy deletes it whether or not the import succeeds`() throws {
        let inbox = ImportFileReader.inboxDirectory
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let good = inbox.appendingPathComponent("cenfc-test-\(UUID().uuidString).bin")
        let tooLarge = inbox.appendingPathComponent("cenfc-test-\(UUID().uuidString).bin")
        let sniffed = inbox.appendingPathComponent("cenfc-test-\(UUID().uuidString).bin")
        try Data([1, 2, 3]).write(to: good)
        try Data(repeating: 0, count: 16).write(to: tooLarge)
        try Data([4]).write(to: sniffed)
        defer { try? FileManager.default.removeItem(at: sniffed) }

        #expect(try ImportFileReader.read(good) == Data([1, 2, 3]))
        #expect(!FileManager.default.fileExists(atPath: good.path))

        #expect(throws: ImportFileReader.ImportError.self) {
            try ImportFileReader.read(tooLarge, limit: 4)
        }
        #expect(!FileManager.default.fileExists(atPath: tooLarge.path))

        // The router only sniffs the type; the import screen reads it again.
        _ = try ImportFileReader.read(sniffed, consumingInboxCopy: false)
        #expect(FileManager.default.fileExists(atPath: sniffed.path))
    }
}

// MARK: - C3: re-verification cache

@MainActor
struct PassportReverificationCacheTests {
    @Test
    func `Cache keys on a digest of the data groups and the SOD`() throws {
        let passport = try makePassport()
        let digest = PassportReverificationCache.digest(of: passport)
        #expect(digest.count == 32)
        #expect(digest == PassportReverificationCache.digest(of: try makePassport()))
        #expect(digest != PassportReverificationCache.digest(of: try makePassport(dg1Suffix: 0x01)))
        #expect(digest != PassportReverificationCache.digest(of: try makePassport(sod: Data([0x77]))))
    }

    @Test
    func `Imported Active Authentication is re-judged, never trusted as stored`() async throws {
        let stored = ActiveAuthenticationResult(success: true, details: "ok", status: .verified)
        let record = PassportRecord(from: try makePassport(active: stored), origin: .imported)
        let security = record.reverifiedSecurity()
        // Without a fully verified SOD, a valid AA signature does not prove the chip genuine.
        let active = try #require(security.activeAuthentication)
        #expect(active.status == .fallback)

        let rows = PassportDetailViewController.securityRows(for: record, reverified: security)
        let aaRow = try #require(rows.first { $0.isActiveAuthentication })
        #expect(aaRow.icon == "exclamationmark.triangle.fill")
        #expect(aaRow.value == String(localized: "Fallback"))
        // BAC, PACE and CA stay unverified.
        #expect(rows.filter { !$0.isActiveAuthentication && !$0.isPassiveAuthentication }.allSatisfy {
            $0.value == String(localized: "Imported, not re-verified")
        })
        // The digest covers the stored AA result.
        #expect(PassportReverificationCache.digest(of: record.passport)
            != PassportReverificationCache.digest(of: try makePassport()))

        let cache = PassportReverificationCache()
        #expect(await cache.security(for: record) == security)
        #expect(cache.cachedSecurity(for: record) == security)

        // No AA result in the file: the stored AA stage is not shown.
        let withoutAA = PassportRecord(from: try makePassport(), origin: .imported)
        let noAA = withoutAA.reverifiedSecurity()
        #expect(noAA.activeAuthentication == nil)
        let noAARow = try #require(PassportDetailViewController.securityRows(for: withoutAA, reverified: noAA)
            .first { $0.isActiveAuthentication })
        #expect(noAARow.value == String(localized: "Imported, not re-verified"))
    }

    @Test
    func `A cached result is dropped when the record's bytes change`() async throws {
        let cache = PassportReverificationCache()
        let record = PassportRecord(from: try makePassport(), origin: .imported)
        let result = await cache.passiveAuthentication(for: record)
        #expect(cache.cachedResult(for: record) == result)

        let changed = PassportRecord(from: try makePassport(sod: Data([0x77])), id: record.id, origin: .imported)
        #expect(cache.cachedResult(for: changed) == nil)
    }

    @Test
    func `Concurrent requests for one record share a task`() async throws {
        let cache = PassportReverificationCache()
        let record = PassportRecord(from: try makePassport(), origin: .imported)
        let first = Task { await cache.passiveAuthentication(for: record) }
        let second = Task { await cache.passiveAuthentication(for: record) }
        let results = await [first.value, second.value]
        #expect(results[0] == results[1])
        #expect(!cache.isVerifying(record.id))
        #expect(cache.cachedResult(for: record) == results[0])
    }

    @Test
    func `Removing or replacing a passport evicts its cached result`() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cache = PassportReverificationCache()
        let store = PassportStore(
            fileURL: directory.appendingPathComponent("passport_records.json"),
            reverificationCache: cache
        )
        let first = store.add(PassportRecord(from: try makePassport(), origin: .imported))
        let second = store.add(PassportRecord(from: try makePassport(sod: Data([0x77])), origin: .imported))
        _ = await cache.passiveAuthentication(for: first)
        _ = await cache.passiveAuthentication(for: second)
        #expect(cache.hasEntry(for: first.id))
        #expect(cache.hasEntry(for: second.id))

        store.remove(id: first.id)
        #expect(!cache.hasEntry(for: first.id))

        store.replace(second.id, with: PassportRecord(from: try makePassport(), origin: .imported))
        #expect(!cache.hasEntry(for: second.id))
        await store.flush()
    }
}

// MARK: - C4: scan import conflicts

@MainActor
struct ScanImportConflictTests {
    @Test
    func `Importing a known card asks before replacing it`() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ScanStore(fileURL: directory.appendingPathComponent("scan_records.json"))
        let uid = Data([0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let saved = store.add(ScanRecord(cardInfo: CardInfo(type: .ntag215, uid: uid)))
        let imported = ScanRecord(cardInfo: CardInfo(type: .ntag215, uid: uid))
        #expect(store.importConflict(for: imported)?.id == saved.id)
        #expect(store.importConflict(for: ScanRecord(cardInfo: CardInfo(type: .ntag215, uid: Data([0x04, 0x01])))) == nil)

        var choice: Bool?
        let alert = UIViewController.makeScanImportConflictAlert(existing: saved) { choice = $0 }
        #expect(alert.actions.map(\.title) == [
            String(localized: "Replace"), String(localized: "Keep Both"), String(localized: "Cancel"),
        ])
        #expect(alert.actions.map(\.style) == [.destructive, .default, .cancel])
        #expect(choice == nil)

        store.importRecord(imported, replacingExisting: false)
        #expect(store.records.count == 2)
        store.importRecord(imported, replacingExisting: true)
        #expect(store.records.count == 2)
        #expect(Set(store.records.map(\.id)).count == 2)
    }
}

// MARK: - C5: localized security rows

@MainActor
struct PassportSecurityTextTests {
    @Test
    func `Security rows show app text, not the library's English detail`() throws {
        let detail = "Library English detail"
        let failed = PassportSecurityStageResult(status: .failed, detail: detail)
        let fallback = PassportSecurityStageResult(status: .fallback, detail: detail)
        let report = PassportSecurityReport(
            cardAccess: fallback, pace: failed, bac: failed,
            chipAuthentication: failed, passiveAuthentication: fallback, activeAuthentication: failed
        )
        var passport = try makePassport()
        passport = PassportModel(
            ldsVersion: nil, unicodeVersion: nil,
            availableDataGroups: passport.availableDataGroups,
            mrz: passport.mrz, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: passport.rawDataGroups,
            securityReport: report
        )
        let rows = PassportDetailViewController.securityRows(for: PassportRecord(from: passport))
        #expect(rows.allSatisfy { $0.value != detail })
        #expect(rows.first { $0.isPassiveAuthentication }?.value
            == String(localized: "Hashes match; Document Signer certificate not validated to a trusted CSCA"))
        #expect(rows.first { $0.title == String(localized: "BAC") }?.value == String(localized: "Failed"))

        let imported = PassportDetailViewController.securityRows(
            for: PassportRecord(from: passport, origin: .imported),
            reverifiedPassiveAuthentication: failed
        )
        #expect(imported.first { $0.isPassiveAuthentication }?.value == String(localized: "Failed"))
    }

    @Test
    func `Passive authentication outcomes map to specific text`() {
        let failed = PassportSecurityStageResult(status: .failed, detail: "x")
        #expect(PassportDetailViewController.securityValue(
            for: failed, isPassiveAuthentication: true, passiveAuthStatus: .hashMismatch
        ) == String(localized: "Data group hash mismatch"))
        #expect(PassportDetailViewController.securityValue(
            for: PassportSecurityStageResult(status: .notSupported, detail: "x"),
            isPassiveAuthentication: true
        ) == String(localized: "No SOD available"))
        // A skipped stage is not described by the result's status.
        #expect(PassportDetailViewController.securityValue(
            for: PassportSecurityStageResult(status: .skipped, detail: "x"),
            isPassiveAuthentication: true,
            passiveAuthStatus: .dataGroupHashesVerified
        ) == String(localized: "Skipped"))
    }
}

// MARK: - C6: delete confirmation

@MainActor
struct PassportDeleteConfirmationTests {
    @Test
    func `Deleting a passport record asks for confirmation`() {
        var deleted = false
        var cancelled = false
        let alert = PassportViewController.makeDeleteConfirmation(
            count: 1,
            onDelete: { deleted = true },
            onCancel: { cancelled = true }
        )
        #expect(alert.preferredStyle == .actionSheet)
        #expect(alert.actions.map(\.style) == [.destructive, .cancel])
        #expect(!deleted && !cancelled)
    }
}

// MARK: - C7 / C9: export files

@MainActor
struct ExportCleanupTests {
    @Test
    func `Log exports are written under the export root with file protection`() throws {
        let artifacts = [
            AppLogExportArtifact(suggestedFilename: "cenfc-logs.txt", data: Data("a".utf8)),
            AppLogExportArtifact(suggestedFilename: "cenfc-logs.json", data: Data("{}".utf8)),
        ]
        let urls = try LogsViewController.writeExportFiles(artifacts)
        defer { ExportFileLocation.remove(urls) }
        #expect(urls.map(\.lastPathComponent) == ["cenfc-logs.txt", "cenfc-logs.json"])
        let root = ExportFileLocation.rootDirectory.standardizedFileURL.resolvingSymlinksInPath().path
        for url in urls {
            #expect(url.deletingLastPathComponent().deletingLastPathComponent()
                .standardizedFileURL.resolvingSymlinksInPath().path == root)
            #expect(FileManager.default.fileExists(atPath: url.path))
        }
        ExportFileLocation.remove(urls)
        #expect(urls.allSatisfy { !FileManager.default.fileExists(atPath: $0.path) })
    }

    @Test
    func `Export files are removed when the share sheet cannot be presented`() throws {
        let url = try ExportFileLocation.url(for: UUID(), baseName: "Card", fallbackName: "Card", pathExtension: "cenfc")
        try ExportFileLocation.write(Data([1]), to: url)
        // Not in a window: UIKit refuses the presentation.
        let controller = UIViewController()
        controller.presentExportSheet(for: [url])
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }
}

// MARK: - C8: privacy cover window

@MainActor
struct PrivacyCoverWindowTests {
    private final class SensitiveScreen: UIViewController, PrivacySensitiveScreen {}

    @Test
    func `Privacy cover is its own window above alerts`() throws {
        let scene = try #require(UIApplication.shared.connectedScenes.first as? UIWindowScene)
        let window = UIWindow(windowScene: scene)
        window.rootViewController = UINavigationController(rootViewController: SensitiveScreen())
        let cover = PrivacyCover()
        cover.show(over: window)
        defer { cover.hide() }
        let coverWindow = try #require(cover.coverWindow)
        #expect(coverWindow.windowScene === scene)
        #expect(coverWindow.windowLevel > .alert)
        #expect(!coverWindow.isHidden)
        #expect(coverWindow !== window)

        cover.hide()
        #expect(!cover.isShown)
        #expect(coverWindow.isHidden)
    }
}

// MARK: - C10: imported passport date

@MainActor
struct ImportedPassportDateTests {
    @Test
    func `Imported passports are labelled and dated by their import`() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = PassportStore(
            fileURL: directory.appendingPathComponent("passport_records.json"),
            reverificationCache: PassportReverificationCache()
        )
        let scanned = Date(timeIntervalSince1970: 1_000_000)
        let now = Date(timeIntervalSince1970: 2_000_000)
        let record = PassportRecord(from: try makePassport(), date: scanned, origin: .imported)
        store.importRecord(record, now: now)
        #expect(store.records.first?.date == now)

        let imported = try #require(store.records.first)
        #expect(PassportDetailViewController.dateRowText(for: imported).title == String(localized: "Imported"))
        #expect(PassportDetailViewController.personalDataFooter(for: imported).contains("imported")
            || Locale.current.language.languageCode != .english)

        let chip = PassportRecord(from: try makePassport())
        #expect(PassportDetailViewController.dateRowText(for: chip).title == String(localized: "Scan Date"))
        await store.flush()
    }
}

// MARK: - C11: transit log

struct TransitLogTests {
    @Test
    func `Transit read log line omits the balance`() {
        let balance = TransitBalance(
            serialNumber: "",
            balanceRaw: 987_654,
            currencyCode: "JPY",
            cardName: "Suica",
            transactions: [TransitTransaction(type: .trip, amount: 123_456)]
        )
        let message = TransitBalanceViewController.readSucceededLogMessage(for: balance)
        #expect(!message.contains("987654"))
        #expect(!message.contains("123456"))
        #expect(!message.contains("JPY"))
        #expect(message.contains("transactions=1"))
    }
}
