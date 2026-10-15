import CoreExtendedNFC
import Foundation
import UniformTypeIdentifiers

extension UTType {
    static let cenfc = UTType(exportedAs: "wiki.qaq.cenfc.scan-record", conformingTo: .data)
}

enum ScanRecordDocument {
    // MARK: - Export

    static func export(_ record: ScanRecord) throws -> Data {
        try PropertyListEncoder().encode(record)
    }

    static func exportToFile(_ record: ScanRecord) throws -> URL {
        let name = sanitizedFileName(for: record)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(name)
            .appendingPathExtension("cenfc")
        try export(record).write(to: url, options: .atomic)
        return url
    }

    // MARK: - Helpers

    private static func sanitizedFileName(for record: ScanRecord) -> String {
        let uid = record.cardInfo.uid.hexString
        let type = record.cardInfo.type.description
            .replacingOccurrences(of: " ", with: "-")
            .replacingOccurrences(of: "/", with: "-")
        return "\(type)_\(uid)"
    }
}
