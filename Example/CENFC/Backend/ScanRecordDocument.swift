import CoreExtendedNFC
import Foundation
import UniformTypeIdentifiers

nonisolated extension UTType {
    static let cenfc = UTType(exportedAs: "wiki.qaq.cenfc.scan-record", conformingTo: .data)
}

nonisolated enum ScanRecordDocument {
    // MARK: - Export

    static func export(_ record: ScanRecord) throws -> Data {
        try PropertyListEncoder().encode(record)
    }

    static func exportToFile(_ record: ScanRecord) throws -> URL {
        let uid = record.cardInfo.uid
        let type = record.cardInfo.type.description
        let url = try ExportFileLocation.url(
            for: record.id,
            baseName: uid.isEmpty ? type : "\(type)_\(uid.hexString)",
            fallbackName: "Card",
            pathExtension: "cenfc"
        )
        try export(record).write(to: url, options: .atomic)
        return url
    }
}
