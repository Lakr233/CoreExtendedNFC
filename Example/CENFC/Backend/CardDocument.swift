import CoreExtendedNFC
import Foundation
import UniformTypeIdentifiers

nonisolated struct CardDocumentEnvelope: Codable, Sendable {
    let scanRecord: ScanRecord
    let dumpRecord: DumpRecord?
}

nonisolated enum CardDocument {
    // MARK: - Export (scan only)

    static func exportScanOnly(_ record: ScanRecord) throws -> Data {
        let envelope = CardDocumentEnvelope(scanRecord: record, dumpRecord: nil)
        return try PropertyListEncoder().encode(envelope)
    }

    // MARK: - Export (scan + dump)

    static func exportWithDump(scan: ScanRecord, dump: DumpRecord) throws -> Data {
        let envelope = CardDocumentEnvelope(scanRecord: scan, dumpRecord: dump)
        return try PropertyListEncoder().encode(envelope)
    }

    static func exportDump(_ dump: DumpRecord) throws -> Data {
        let scan = ScanRecord.synthesized(from: dump)
        return try exportWithDump(scan: scan, dump: dump)
    }

    static func exportToFile(_ dump: DumpRecord) throws -> URL {
        let url = try ExportFileLocation.url(
            for: dump.id,
            baseName: fileName(cardType: dump.dump.cardInfo.type.description, uid: dump.dump.cardInfo.uid),
            fallbackName: "Card",
            pathExtension: "cenfc"
        )
        try exportDump(dump).write(to: url, options: .atomic)
        return url
    }

    /// Exports a scan record, bundling the given dump when one is available.
    static func exportToFile(_ scan: ScanRecord, dump: DumpRecord?) throws -> URL {
        let url = try ExportFileLocation.url(
            for: scan.id,
            baseName: fileName(cardType: scan.cardInfo.type.description, uid: scan.cardInfo.uid),
            fallbackName: "Card",
            pathExtension: "cenfc"
        )
        if let dump {
            try exportWithDump(scan: scan, dump: dump).write(to: url, options: .atomic)
        } else {
            try exportScanOnly(scan).write(to: url, options: .atomic)
        }
        return url
    }

    /// Exports a scan record together with the latest dump of the same card from `dumps`.
    @MainActor
    static func exportToFile(_ scan: ScanRecord, dumps: DumpStore = .shared) throws -> URL {
        try exportToFile(scan, dump: dumps.record(withUID: scan.cardInfo.uid))
    }

    // MARK: - Import

    static func importEnvelope(from data: Data) throws -> CardDocumentEnvelope {
        let decoder = PropertyListDecoder()
        if let envelope = try? decoder.decode(CardDocumentEnvelope.self, from: data) {
            return envelope
        }
        let scan = try decoder.decode(ScanRecord.self, from: data)
        return CardDocumentEnvelope(scanRecord: scan, dumpRecord: nil)
    }

    static func importEnvelope(from url: URL) throws -> CardDocumentEnvelope {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        let data = try Data(contentsOf: url)
        return try importEnvelope(from: data)
    }

    // MARK: - Helpers

    private static func fileName(cardType: String, uid: Data) -> String {
        uid.isEmpty ? cardType : "\(cardType)_\(uid.hexString)"
    }
}
