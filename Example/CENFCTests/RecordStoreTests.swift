@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing
import UIKit

/// A temporary directory for one test's store files.
private struct TemporaryDirectory {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cenfc-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    func file(_ name: String) -> URL {
        url.appendingPathComponent(name)
    }

    func contents() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: url.path).sorted()
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

private func hasUniqueIDs(_ ids: [UUID]) -> Bool {
    Set(ids).count == ids.count
}

/// ISO/IEC 14443-3 random UID (single size, UID0 = 0x08), as used by eMRTDs.
private let randomUID = Data([0x08, 0x01, 0x02, 0x03])

private func makePassport(documentNumber: Bool) throws -> PassportModel {
    let mrz = try MRZData(
        mrzString: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    )
    return PassportModel(
        ldsVersion: nil, unicodeVersion: nil,
        availableDataGroups: [.dg1],
        mrz: documentNumber ? mrz : nil, faceImageData: nil, signatureImageData: nil,
        additionalPersonalDetails: nil, additionalDocumentDetails: nil,
        securityInfos: nil, securityInfoRaw: nil,
        activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
        sod: nil, sodRaw: nil,
        passiveAuthResult: nil, activeAuthResult: nil,
        rawDataGroups: [.dg1: Data([0x61])]
    )
}

// MARK: - Import keeps IDs unique (review D-H1 / A-M4)

@MainActor
struct RecordStoreImportTests {
    @Test
    func `Importing the same dump file twice keeps dump IDs unique`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = DumpStore(fileURL: directory.file("dump_records.json"))
        let info = CardInfo(type: .ntag213, uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]))
        let original = DumpRecord(from: MemoryDump(cardInfo: info, pages: [.init(number: 0, data: Data([1, 2, 3, 4]))]))
        store.add(original)

        let exported = try CardDocument.exportToFile(original)
        // DumpViewController.importFile / ScannerViewController.promptSaveDump and the drop handlers.
        let imported = try #require(try CardDocument.importEnvelope(from: exported).dumpRecord)
        store.add(imported)
        store.add(imported)

        #expect(store.records.count == 3)
        #expect(hasUniqueIDs(store.records.map(\.id)))
        // Used to trap in Dictionary(uniqueKeysWithValues:).
        store.reorder(by: store.records.map(\.id).reversed())
        #expect(store.records.first?.id == original.id)
    }

    @Test
    func `Re-importing a random-UID card updates it instead of duplicating its ID`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = ScanStore(fileURL: directory.file("scan_records.json"))
        let original = ScanRecord(cardInfo: CardInfo(type: .ePassport, uid: randomUID))
        store.add(original)

        let exported = try ScanRecordDocument.exportToFile(original)
        // ScannerViewController.importFile / DumpViewController.promptSaveScan and the drop handlers.
        let imported = try CardDocument.importEnvelope(from: exported).scanRecord
        store.upsert(imported)
        store.upsert(imported, at: 0)

        #expect(store.records.map(\.id) == [original.id])

        // Inserting a record that reuses an ID gives it a new one.
        store.insert(imported, at: 1)
        #expect(store.records.count == 2)
        #expect(hasUniqueIDs(store.records.map(\.id)))
    }

    @Test
    func `Importing an NDEF file whose ID is taken by different data keeps IDs unique`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = NDEFStore(fileURL: directory.file("ndef_records.json"))
        let original = NDEFDataRecord(name: "a", messageData: NDEFMessage.text("one").data)
        store.add(original)

        // The record was exported, then edited in the app; the old export is imported again.
        let exported = try NDEFDocument.exportToFile(original)
        store.update(original.withMessageData(NDEFMessage.text("two").data))
        // NDEFViewController.importFiles.
        let imported = try NDEFDocument.importRecord(from: exported)
        #expect(store.addIfNew(imported))

        #expect(store.records.count == 2)
        #expect(hasUniqueIDs(store.records.map(\.id)))
    }

    @Test
    func `Importing a passport file without a document number twice keeps IDs unique`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = PassportStore(fileURL: directory.file("passport_records.json"))
        let original = try PassportRecord(from: makePassport(documentNumber: false))
        store.add(original)

        let exported = try PassportDocument.exportToFile(original)
        // PassportViewController.importFile.
        let imported = try PassportDocument.importRecord(from: exported)
        store.importRecord(imported)
        store.importRecord(imported)

        #expect(store.records.count == 3)
        #expect(hasUniqueIDs(store.records.map(\.id)))

        // With a document number the import replaces the matching record.
        let withNumber = try PassportRecord(from: makePassport(documentNumber: true))
        store.importRecord(withNumber)
        store.importRecord(withNumber.withNewID())
        #expect(store.records.count == 4)
        #expect(hasUniqueIDs(store.records.map(\.id)))
    }
}

// MARK: - Loading repairs stores and never loses data (D-H1, D-L1, D-L2, A-L8)

@MainActor
struct RecordStoreLoadTests {
    @Test
    func `Loading a store with duplicate IDs gives them new IDs and saves the repair`() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let fileURL = directory.file("scan_records.json")
        let record = ScanRecord(cardInfo: CardInfo(type: .ePassport, uid: randomUID))
        try RecordJSON.makeEncoder().encode([record, record, record]).write(to: fileURL)

        let store = ScanStore(fileURL: fileURL)
        #expect(store.records.count == 3)
        #expect(store.records.first?.id == record.id)
        #expect(hasUniqueIDs(store.records.map(\.id)))
        store.reorder(by: store.records.map(\.id).reversed())
        #expect(store.records.last?.id == record.id)

        await store.flush()
        let onDisk = RecordFilePersistence<ScanRecord>(fileURL: fileURL).load().records
        #expect(onDisk.map(\.id) == store.records.map(\.id))
    }

    @Test
    func `Duplicate IDs are repaired in every store`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }

        let dump = DumpRecord(from: MemoryDump(cardInfo: CardInfo(type: .ntag213, uid: randomUID)))
        try RecordJSON.makeEncoder().encode([dump, dump]).write(to: directory.file("d.json"))
        #expect(hasUniqueIDs(DumpStore(fileURL: directory.file("d.json")).records.map(\.id)))

        let ndef = NDEFDataRecord(name: "n", messageData: NDEFMessage.text("x").data)
        try RecordJSON.makeEncoder().encode([ndef, ndef]).write(to: directory.file("n.json"))
        #expect(hasUniqueIDs(NDEFStore(fileURL: directory.file("n.json")).records.map(\.id)))

        let passport = try PassportRecord(from: makePassport(documentNumber: false))
        try RecordJSON.makeEncoder().encode([passport, passport]).write(to: directory.file("p.json"))
        let passports = PassportStore(fileURL: directory.file("p.json"))
        #expect(passports.records.count == 2)
        #expect(hasUniqueIDs(passports.records.map(\.id)))
    }

    @Test
    func `A partly corrupt store is backed up once, not on every launch`() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let fileURL = directory.file("ndef_records.json")
        let valid = NDEFDataRecord(name: "ok", messageData: NDEFMessage.text("x").data)
        let validJSON = try String(decoding: RecordJSON.makeEncoder().encode(valid), as: UTF8.self)
        try Data("[\(validJSON), {\"id\": \"broken\"}]".utf8).write(to: fileURL)

        let first = NDEFStore(fileURL: fileURL)
        await first.flush()
        let second = NDEFStore(fileURL: fileURL)

        #expect(first.records.map(\.id) == [valid.id])
        #expect(second.records.map(\.id) == [valid.id])
        let backups = try directory.contents().filter { $0.contains(".corrupt-") }
        #expect(backups.count == 1)
    }

    @Test
    func `A store file that exists but cannot be read is never overwritten`() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        // A directory where the file should be: reading fails with an error other than "no such file".
        let fileURL = directory.file("dump_records.json")
        try FileManager.default.createDirectory(at: fileURL, withIntermediateDirectories: false)
        let marker = fileURL.appendingPathComponent("keep")
        try Data([0x01]).write(to: marker)

        let result = RecordFilePersistence<DumpRecord>(fileURL: fileURL).load()
        #expect(result.writeBlockedReason != nil)

        let store = DumpStore(fileURL: fileURL)
        store.add(DumpRecord(from: MemoryDump(cardInfo: CardInfo(type: .ntag213, uid: randomUID))))
        await store.flush()

        var isDirectory: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: fileURL.path, isDirectory: &isDirectory))
        #expect(isDirectory.boolValue)
        #expect(try Data(contentsOf: marker) == Data([0x01]))
    }

    @Test
    func `A missing store file starts empty and can be saved`() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let fileURL = directory.file("scan_records.json")

        let result = RecordFilePersistence<ScanRecord>(fileURL: fileURL).load()
        #expect(result.writeBlockedReason == nil)
        #expect(result.records.isEmpty)

        let store = ScanStore(fileURL: fileURL)
        let record = ScanRecord(cardInfo: CardInfo(type: .ntag213, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])))
        store.add(record)
        await store.flush()
        #expect(RecordFilePersistence<ScanRecord>(fileURL: fileURL).load().records.map(\.id) == [record.id])
    }

    @Test
    func `An undecodable store whose backup fails is not overwritten`() throws {
        let directory = try TemporaryDirectory()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.url.path)
            directory.remove()
        }
        let fileURL = directory.file("scan_records.json")
        try Data("not json".utf8).write(to: fileURL)
        // A read-only directory: the backup copy cannot be created.
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: directory.url.path)

        let result = RecordFilePersistence<ScanRecord>(fileURL: fileURL).load()

        #expect(result.backupURL == nil)
        #expect(result.writeBlockedReason != nil)
        #expect(!result.needsResave)
    }
}

// MARK: - Export

@MainActor
struct CardExportTests {
    @Test
    func `Exporting a scan from its detail screen bundles the card's dump`() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let dumps = DumpStore(fileURL: directory.file("dump_records.json"))
        let info = CardInfo(type: .ntag213, uid: Data([0x04, 0x57, 0x01, 0xCA, 0x53, 0x28, 0x80]))
        let dump = DumpRecord(from: MemoryDump(cardInfo: info, pages: [.init(number: 0, data: Data([1, 2, 3, 4]))]))
        dumps.add(dump)

        let url = try CardDocument.exportToFile(ScanRecord(cardInfo: info), dumps: dumps)

        #expect(try CardDocument.importEnvelope(from: url).dumpRecord?.id == dump.id)
    }

    @Test
    func `Very long export names are shortened on a character boundary`() throws {
        // 120 × "界" is 360 UTF-8 bytes, more than the 255-byte APFS name limit.
        let name = String(repeating: "界", count: 120)
        let sanitized = ExportFileLocation.sanitized(name)

        #expect(sanitized.utf8.count <= 200)
        #expect(sanitized == String(repeating: "界", count: 66))

        let url = try ExportFileLocation.url(for: UUID(), baseName: name, fallbackName: "Card", pathExtension: "cenfc")
        try Data([0x00]).write(to: url)
        #expect(FileManager.default.fileExists(atPath: url.path))
    }
}

// MARK: - Interface

@MainActor
struct InterfaceAccessibilityTests {
    @Test
    func `Empty-state text wraps and follows Dynamic Type`() {
        let view = EmptyStateView.scan()
        #expect(view.label.numberOfLines == 0)
        #expect(view.label.adjustsFontForContentSizeCategory)
    }

    @Test
    func `Icon-only bar buttons have VoiceOver labels`() {
        let editor = NDEFTextEditorViewController()
        editor.loadViewIfNeeded()
        #expect(editor.navigationItem.rightBarButtonItem?.accessibilityLabel?.isEmpty == false)

        let mrz = PassportMRZInputViewController()
        mrz.loadViewIfNeeded()
        #expect(mrz.navigationItem.rightBarButtonItem?.accessibilityLabel?.isEmpty == false)
    }
}
