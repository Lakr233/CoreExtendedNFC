@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing
import UIKit

struct RawCommunicationParsingTests {
    @Test
    func `Short APDU cases 1 to 4 parse per ISO 7816-4`() throws {
        let case1 = try #require(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00])))
        #expect(case1 == CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00))

        let case2 = try #require(RawCommunicationViewController.parseAPDU(Data([0x00, 0xB0, 0x00, 0x00, 0x0F])))
        #expect(case2 == CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x0F))

        let aid = Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01])
        let case3 = try #require(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid))
        #expect(case3 == CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: aid))

        let case4 = try #require(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00, 0x07]) + aid + Data([0x00])))
        #expect(case4 == CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: aid, le: 0x00))
    }

    @Test
    func `APDU whose Lc disagrees with the data is rejected`() {
        // Lc = 7 but only 2 data bytes: used to be sent as a case-2 APDU with Le = 07.
        #expect(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76])) == nil)
        // Bytes after Le.
        #expect(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0x00, 0x00])) == nil)
        // Extended Lc (00 followed by more bytes).
        #expect(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x01, 0xAA])) == nil)
        #expect(RawCommunicationViewController.parseAPDU(Data([0x00, 0xA4, 0x04])) == nil)
    }

    @Test
    func `Random and empty UIDs are not treated as card identity`() {
        // ISO/IEC 14443-3: single-size UID0 = 0x08 means a random ID.
        #expect(!Data([0x08, 0x12, 0x34, 0x56]).isStableCardUID)
        #expect(!Data().isStableCardUID)
        #expect(Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]).isStableCardUID)
        #expect(Data([0x1A, 0x2B, 0x3C, 0x4D]).isStableCardUID)
    }
}

struct ExportFileTests {
    @Test
    func `Exporting two dumps of the same card writes two distinct files`() throws {
        let info = CardInfo(type: .ntag213, uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]))
        let first = DumpRecord(from: MemoryDump(cardInfo: info, pages: [.init(number: 0, data: Data([0x01, 0x02, 0x03, 0x04]))]))
        let second = DumpRecord(from: MemoryDump(cardInfo: info, pages: [.init(number: 0, data: Data([0x05, 0x06, 0x07, 0x08]))]))

        let firstURL = try CardDocument.exportToFile(first)
        let secondURL = try CardDocument.exportToFile(second)

        #expect(firstURL != secondURL)
        #expect(try CardDocument.importEnvelope(from: firstURL).dumpRecord?.id == first.id)
        #expect(try CardDocument.importEnvelope(from: secondURL).dumpRecord?.id == second.id)
    }

    @Test
    func `NDEF records with the same or an empty name export to distinct visible files`() throws {
        let message = NDEFMessage(records: [.text("hi", languageCode: "en")]).data
        let first = try NDEFDocument.exportToFile(NDEFDataRecord(name: "Text", messageData: message))
        let second = try NDEFDocument.exportToFile(NDEFDataRecord(name: "Text", messageData: message))
        let unnamed = try NDEFDocument.exportToFile(NDEFDataRecord(name: "", messageData: message))

        #expect(first != second)
        #expect(unnamed.lastPathComponent == "NDEF.cndef")
        #expect(ExportFileLocation.sanitized(".hidden/name") == "hidden-name")
    }
}

struct RecordPersistenceTests {
    @Test
    func `Undecodable store file is backed up and readable records are kept`() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("cenfc-persistence-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("ndef_records.json")

        let valid = NDEFDataRecord(name: "ok", messageData: Data([0xD0, 0x00, 0x00]))
        let validJSON = try RecordJSON.makeEncoder().encode(valid)
        let contents = "[" + String(decoding: validJSON, as: UTF8.self) + ", {\"id\": \"not-a-record\"}]"
        try Data(contents.utf8).write(to: fileURL)

        let result = RecordFilePersistence<NDEFDataRecord>(fileURL: fileURL).load()

        #expect(result.records.map(\.id) == [valid.id])
        #expect(result.droppedCount == 1)
        let backupURL = try #require(result.backupURL)
        #expect(try Data(contentsOf: backupURL) == Data(contents.utf8))
    }

    @Test
    func `A newer save is never overwritten by an older one`() async throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("cenfc-persistence-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let persistence = RecordFilePersistence<NDEFDataRecord>(fileURL: fileURL)
        let newer = [NDEFDataRecord(name: "new", messageData: Data())]

        await persistence.save(newer, generation: 2)
        await persistence.save([], generation: 1)

        #expect(persistence.load().records.map(\.id) == newer.map(\.id))
    }
}

@MainActor
struct SingleTaskRunnerTests {
    @Test
    func `A second NFC action is ignored while the first is running`() async {
        let runner = SingleTaskRunner()
        var started = 0
        var release: CheckedContinuation<Void, Never>?

        let first = runner.run {
            started += 1
            await withCheckedContinuation { release = $0 }
        }
        await Task.yield()
        let second = runner.run { started += 1 }

        #expect(first)
        #expect(!second)
        #expect(runner.isRunning)

        release?.resume()
        while runner.isRunning {
            await Task.yield()
        }
        #expect(started == 1)
        #expect(runner.run {})
    }
}

struct NFCErrorMessageTests {
    @Test
    func `Only user cancellation is silent`() {
        #expect(NFCErrorMessage.isCancellation(CancellationError()))
        #expect(NFCErrorMessage.isCancellation(NFCError.userCanceled))
        #expect(!NFCErrorMessage.isCancellation(NFCError.sessionInvalidated("Session invalidated unexpectedly")))
        #expect(!NFCErrorMessage.isCancellation(NFCError.sessionTimeout))
        #expect(!NFCErrorMessage.message(for: NFCError.tagLocked).contains("tagLocked"))
    }

    @Test
    @MainActor
    func `A session the user did not cancel does not silence errors`() {
        let session = NFCSessionManager()
        #expect(!session.wasCanceledByUser)
        #expect(!NFCErrorMessage.isCancellation(NFCError.tagLocked, session: session))
        #expect(NFCErrorMessage.isCancellation(NFCError.userCanceled, session: session))
        #expect(NFCErrorMessage.isCancellation(CancellationError(), session: nil))
    }

    @Test
    @MainActor
    func `Passport detail lists data groups that were not read`() {
        let passport = PassportModel(
            ldsVersion: nil, unicodeVersion: nil,
            availableDataGroups: [.dg1, .dg2, .dg3, .dg14],
            mrz: nil, faceImageData: nil, signatureImageData: nil,
            additionalPersonalDetails: nil, additionalDocumentDetails: nil,
            securityInfos: nil, securityInfoRaw: nil,
            activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
            sod: nil, sodRaw: nil,
            passiveAuthResult: nil, activeAuthResult: nil,
            rawDataGroups: [.dg1: Data([0x61])],
            dataGroupReadStatus: [
                .dg1: .init(state: .read),
                .dg2: .init(state: .notRead),
                .dg3: .init(state: .unavailable, detail: "6982"),
                .dg15: .init(state: .notPresent),
            ]
        )
        let summary = PassportDetailViewController.unreadDataGroupsSummary(passport)
        #expect(summary == "DG2 (Face Image): \(String(localized: "Not read")); DG3 (Fingerprints): \(String(localized: "Unavailable"))")
    }
}

@MainActor
@Suite(.serialized)
struct AlertQueueTests {
    @Test
    func `Back-to-back alerts are shown one after another`() async throws {
        let scene = try #require(UIApplication.shared.connectedScenes.first as? UIWindowScene)
        let window = UIWindow(windowScene: scene)
        let host = UIViewController()
        window.rootViewController = host
        window.isHidden = false
        defer { window.isHidden = true }

        let first = UIAlertController(title: "1", message: nil, preferredStyle: .alert)
        let second = UIAlertController(title: "2", message: nil, preferredStyle: .alert)
        host.presentQueued(first)
        host.presentQueued(second)

        try await waitUntil { host.presentedViewController === first }
        #expect(AlertQueue.shared.pendingCount == 1)

        await withCheckedContinuation { continuation in
            first.dismiss(animated: false) { continuation.resume() }
        }
        try await waitUntil { host.presentedViewController === second }

        await withCheckedContinuation { continuation in
            second.dismiss(animated: false) { continuation.resume() }
        }
    }

    @Test
    func `An alert for a screen that is off screen waits instead of being dropped`() async throws {
        let scene = try #require(UIApplication.shared.connectedScenes.first as? UIWindowScene)
        let window = UIWindow(windowScene: scene)
        let visible = UIViewController()
        let hidden = UIViewController()
        let tabs = UITabBarController()
        tabs.viewControllers = [visible, hidden]
        window.rootViewController = tabs
        window.isHidden = false
        defer { window.isHidden = true }
        #expect(hidden.viewIfLoaded?.window == nil)

        // An import on a tab that is not selected (e.g. opened from a URL) queues an alert there.
        let alert = UIAlertController(title: "later", message: nil, preferredStyle: .alert)
        hidden.presentQueued(alert)
        try await Task.sleep(nanoseconds: 400_000_000)
        #expect(AlertQueue.shared.pendingCount == 1)

        tabs.selectedIndex = 1
        for _ in 0 ..< 100 where alert.presentingViewController == nil {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(alert.presentingViewController != nil)
        await withCheckedContinuation { continuation in
            alert.dismiss(animated: false) { continuation.resume() }
        }
    }

    private func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0 ..< 100 where !condition() {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(condition())
    }
}
