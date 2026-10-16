import Foundation
import UniformTypeIdentifiers

nonisolated extension UTType {
    static let cndef = UTType(exportedAs: "wiki.qaq.cenfc.ndef-record", conformingTo: .data)
}

nonisolated enum NDEFDocument {
    // MARK: - Export

    static func export(_ record: NDEFDataRecord) throws -> Data {
        try PropertyListEncoder().encode(record)
    }

    static func exportToFile(_ record: NDEFDataRecord) throws -> URL {
        let url = try ExportFileLocation.url(
            for: record.id,
            baseName: record.name,
            fallbackName: "NDEF",
            pathExtension: "cndef"
        )
        try ExportFileLocation.write(export(record), to: url)
        return url
    }

    // MARK: - Import

    static func importRecord(from data: Data) throws -> NDEFDataRecord {
        try PropertyListDecoder().decode(NDEFDataRecord.self, from: data)
    }

    static func importRecord(from url: URL) throws -> NDEFDataRecord {
        let data = try ImportFileReader.read(url)
        return try importRecord(from: data)
    }
}
