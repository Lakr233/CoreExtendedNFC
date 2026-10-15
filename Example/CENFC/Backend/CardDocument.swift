import CoreExtendedNFC
import Foundation
import UniformTypeIdentifiers

struct CardDocumentEnvelope: Codable {
    let scanRecord: ScanRecord
    let dumpRecord: DumpRecord?
}

enum CardDocument {
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
        let name = sanitizedFileName(cardType: dump.dump.cardInfo.type.description, uid: dump.dump.cardInfo.uid)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(name)
            .appendingPathExtension("cenfc")
        try exportDump(dump).write(to: url, options: .atomic)
        return url
    }

    static func exportToFile(_ scan: ScanRecord) throws -> URL {
        let name = sanitizedFileName(cardType: scan.cardInfo.type.description, uid: scan.cardInfo.uid)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(name)
            .appendingPathExtension("cenfc")
        let dumpRecord = DumpStore.shared.record(withUID: scan.cardInfo.uid)
        if let dumpRecord {
            try exportWithDump(scan: scan, dump: dumpRecord).write(to: url, options: .atomic)
        } else {
            try exportScanOnly(scan).write(to: url, options: .atomic)
        }
        return url
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

    private static func sanitizedFileName(cardType: String, uid: Data) -> String {
        let uidHex = uid.hexString
        let type = cardType
            .replacingOccurrences(of: " ", with: "-")
            .replacingOccurrences(of: "/", with: "-")
        return "\(type)_\(uidHex)"
    }
}
