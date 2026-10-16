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

    /// Writes `record` to a temporary file for the share sheet.
    ///
    /// The file name carries no personal data (no name, no document number):
    /// it shows up in share targets, Files and AirDrop previews.
    static func exportToFile(_ record: PassportRecord) throws -> URL {
        let url = try ExportFileLocation.url(
            for: record.id,
            baseName: exportBaseName(for: record),
            fallbackName: "Passport",
            pathExtension: "cenfcpass"
        )
        try ExportFileLocation.write(export(record), to: url)
        return url
    }

    /// "Passport-1A2B3C4D": a neutral name derived from the record ID only.
    static func exportBaseName(for record: PassportRecord) -> String {
        "Passport-\(record.id.uuidString.prefix(8))"
    }

    // MARK: - Import

    /// Decodes an exported record and marks it as imported.
    ///
    /// The security results in a file are whatever its author wrote, so they are
    /// never shown as verified (see ``PassportRecord/Origin/imported``).
    static func importRecord(from data: Data) throws -> PassportRecord {
        try PropertyListDecoder().decode(PassportRecord.self, from: data).markedImported()
    }

    static func importRecord(from url: URL) throws -> PassportRecord {
        let data = try ImportFileReader.read(url)
        return try importRecord(from: data)
    }
}
