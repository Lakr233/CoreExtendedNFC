import CoreExtendedNFC
import Foundation
import UniformTypeIdentifiers

nonisolated extension UTType {
    static let cenfcPassport = UTType(exportedAs: "wiki.qaq.cenfc.passport-record", conformingTo: .data)
}

nonisolated enum PassportDocument {
    // MARK: - Export

    static func export(_ record: PassportRecord) throws -> Data {
        try PropertyListEncoder().encode(record)
    }

    static func exportToFile(_ record: PassportRecord) throws -> URL {
        let docNum = record.passport.mrz?.documentNumber ?? ""
        let url = try ExportFileLocation.url(
            for: record.id,
            baseName: docNum.isEmpty ? record.displayName : "\(record.displayName)_\(docNum)",
            fallbackName: "Passport",
            pathExtension: "cenfcpass"
        )
        try export(record).write(to: url, options: .atomic)
        return url
    }

    // MARK: - Import

    static func importRecord(from data: Data) throws -> PassportRecord {
        try PropertyListDecoder().decode(PassportRecord.self, from: data)
    }

    static func importRecord(from url: URL) throws -> PassportRecord {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        let data = try Data(contentsOf: url)
        return try importRecord(from: data)
    }
}
