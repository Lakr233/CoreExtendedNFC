@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing

/// DG1 and a genuine SOD covering it, copied from the library's `SODFixtures`
/// (SHA-256, signed by a test DSC; the app configures no CSCA trust anchors).
private enum ImportFixtures {
    private static func decode(_ lines: [String]) -> Data {
        Data(base64Encoded: lines.joined())!
    }

    static let dg1 = decode(
        [
            "YVtfH1hQPFVUT0VSSUtTU09OPDxBTk5BPE1BUklBPDw8PDw8PDw8PDw8PDw8PDw8PEw4OTg5MDJDMzZVVE83NDA4MTIyRjEy",
            "MDQxNTlaRTE4NDIyNkI8PDw8PDEw",
        ]
    )

    static let genuineSOD = decode(
        [
            "MIIDWQYJKoZIhvcNAQcCoIIDSjCCA0YCAQMxDTALBglghkgBZQMEAgEwRwYGZ4EIAQEBoD0EOzA5AgEAMAsGCWCGSAFlAwQC",
            "ATAnMCUCAQEEIEMrwH0cY3eT9Nd+C3VoZfeuw3VvmNbsbrdn7aNxkEZRoIIBWjCCAVYwgf2gAwIBAgIUZyVroSi86WSN+A1A",
            "OkDqvNU1Ry4wCgYIKoZIzj0EAwIwITELMAkGA1UEBhMCVVQxEjAQBgNVBAMMCVRlc3QgQ1NDQTAgFw0yNjEwMTYwNTU4MTFa",
            "GA8yMTI2MDkyMjA1NTgxMVowIDELMAkGA1UEBhMCVVQxETAPBgNVBAMMCFRlc3QgRFNDMFkwEwYHKoZIzj0CAQYIKoZIzj0D",
            "AQcDQgAEaNhpH86bQIl+IBsCMmCPwb1J2QxoxcshUCO4b+qW/ldZsuTAUEgMcr1+//5Acoph/PWwgSrwNCedyjRLVQtMiKMS",
            "MBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCVOzXbPsOVQAHcavDjPyxEHHIbogsWU8HT9yagXSd8agIg",
            "JUvvlfb4fXyTwxKQ2cPix2Qv+z6yNL3q2qS/3WL0YRQxggGJMIIBhQIBATA5MCExCzAJBgNVBAYTAlVUMRIwEAYDVQQDDAlU",
            "ZXN0IENTQ0ECFGcla6EovOlkjfgNQDpA6rzVNUcuMAsGCWCGSAFlAwQCAaCB4TAVBgkqhkiG9w0BCQMxCAYGZ4EIAQEBMBwG",
            "CSqGSIb3DQEJBTEPFw0yNjEwMTYwNTU4MTFaMC8GCSqGSIb3DQEJBDEiBCCYpfttzf+L7PaCXi8h5aD+poWYNH+Iwbx7ojy4",
            "kTdJzzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMH",
            "MA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDAKBggqhkjOPQQDAgRIMEYC",
            "IQDfDh3BVG5jI6HmJHXxViGQ5TILx/dxkzO8HFJCnpwpxAIhALI6pN9SDkoY0NLnSaXhQHb3+tUyIeyexvWn6PsCFX99",
        ]
    )

    /// A TD3 MRZ that differs from DG1 in every displayed field.
    static func forgedMRZ() throws -> MRZData {
        let line1 = "P<UTOFORGER<<EVE".padding(toLength: 44, withPad: "<", startingAt: 0)
        let line2 = "X000000001UTO8001014F3001012".padding(toLength: 44, withPad: "<", startingAt: 0)
        return try MRZData(mrzString: line1 + line2)
    }
}

private func makePassport(
    mrz: MRZData?,
    dg1: Data = ImportFixtures.dg1,
    sod: Data? = ImportFixtures.genuineSOD,
    report: PassportSecurityReport = .init()
) -> PassportModel {
    var raw: [DataGroupId: Data] = [.dg1: dg1]
    raw[.sod] = sod
    return PassportModel(
        ldsVersion: nil, unicodeVersion: nil,
        availableDataGroups: [.dg1],
        mrz: mrz, faceImageData: Data([0xFF, 0xD8, 0xFF]), signatureImageData: nil,
        additionalPersonalDetails: ["fullName": "FORGED"], additionalDocumentDetails: nil,
        securityInfos: nil, securityInfoRaw: nil,
        activeAuthPublicKey: nil, activeAuthPublicKeyRaw: nil,
        sod: nil, sodRaw: sod,
        passiveAuthResult: nil, activeAuthResult: nil,
        rawDataGroups: raw,
        securityReport: report
    )
}

/// Round-trips `passport` through a `.cenfcpass` file, like the import screen.
private func importedRecord(_ passport: PassportModel) throws -> PassportRecord {
    try PassportDocument.importRecord(from: PassportDocument.export(PassportRecord(from: passport)))
}

@MainActor
private func passiveAuthenticationRow(
    _ record: PassportRecord,
    _ reverified: PassportSecurityStageResult? = nil
) throws -> PassportDetailViewController.SecurityRow {
    try #require(
        PassportDetailViewController.securityRows(for: record, reverifiedPassiveAuthentication: reverified)
            .first { $0.isPassiveAuthentication }
    )
}

@MainActor
struct ImportedPassportReverificationTests {
    @Test
    func `Imported record with matching DG1 and genuine SOD re-verifies as signature-only`() throws {
        let record = try importedRecord(makePassport(mrz: nil))
        let stage = record.reverifiedPassiveAuthentication()
        // No CSCA trust anchors in the app, so at best a fallback, never succeeded.
        #expect(stage.status == .fallback)
        let row = try passiveAuthenticationRow(record, stage)
        #expect(row.icon == "exclamationmark.triangle.fill")
        #expect(!row.isDestructive)
    }

    @Test
    func `Imported record with tampered DG1 fails passive authentication`() async throws {
        var tampered = ImportFixtures.dg1
        tampered[tampered.count - 1] ^= 0x01
        let ok = PassportSecurityStageResult(status: .succeeded, detail: "")
        let report = PassportSecurityReport(passiveAuthentication: ok)
        let record = try importedRecord(makePassport(mrz: nil, dg1: tampered, report: report))

        let stage = record.reverifiedPassiveAuthentication()
        #expect(stage.status == .failed)
        let row = try passiveAuthenticationRow(record, stage)
        #expect(row.isDestructive)
        #expect(row.icon == "xmark.circle.fill")
        // Before the check finishes, the file's own "succeeded" is not shown either.
        #expect(try passiveAuthenticationRow(record).value == String(localized: "Verifying…"))

        // The cache runs the same check off the main thread and keeps the result.
        let cached = await PassportReverificationCache.shared.passiveAuthentication(for: record)
        #expect(cached == stage)
        #expect(PassportReverificationCache.shared.cachedResult(for: record) == stage)
    }

    @Test
    func `Imported record without SOD shows passive authentication as not supported`() throws {
        let record = try importedRecord(makePassport(mrz: nil, sod: nil))
        let stage = record.reverifiedPassiveAuthentication()
        #expect(stage.status == .notSupported)
        #expect(try passiveAuthenticationRow(record, stage).icon == "minus.circle")
    }

    @Test
    func `Imported record shows MRZ fields from DG1, not the file's pre-parsed MRZ`() throws {
        let forged = try ImportFixtures.forgedMRZ()
        #expect(forged.documentNumber == "X00000000")
        let record = try importedRecord(makePassport(mrz: forged))

        #expect(record.passport.mrz?.documentNumber == "L898902C3")
        #expect(record.displayName == "ERIKSSON, ANNA MARIA")
        #expect(record.formattedDOB == "12/08/74")
        // Pre-parsed fields with no raw bytes behind them are dropped.
        #expect(record.passport.faceImageData == nil)
        #expect(record.passport.additionalPersonalDetails == nil)
        #expect(record.passport.passiveAuthResult == nil)

        // Imported records loaded back from the store are re-parsed too.
        let stored = try RecordJSON.makeEncoder().encode(
            [PassportRecord(from: makePassport(mrz: forged), origin: .imported)]
        )
        let decoded = try RecordJSON.makeDecoder().decode([PassportRecord].self, from: stored)
        #expect(decoded.first?.passport.mrz?.documentNumber == "L898902C3")
    }

    @Test
    func `Imported record with unparseable DG1 shows no MRZ`() throws {
        let record = try importedRecord(makePassport(mrz: ImportFixtures.forgedMRZ(), dg1: Data([0x61, 0x00])))
        #expect(record.passport.mrz == nil)
        #expect(record.displayName == String(localized: "Unknown"))
    }

    @Test
    func `Chip records keep their stored fields and security report`() throws {
        let forged = try ImportFixtures.forgedMRZ()
        let ok = PassportSecurityStageResult(status: .succeeded, detail: "")
        let report = PassportSecurityReport(
            cardAccess: ok, pace: ok, bac: ok,
            chipAuthentication: ok, passiveAuthentication: ok, activeAuthentication: ok
        )
        let record = PassportRecord(from: makePassport(mrz: forged, report: report))
        #expect(!record.isImported)
        #expect(record.passport.mrz?.documentNumber == forged.documentNumber)
        #expect(record.passport.faceImageData == Data([0xFF, 0xD8, 0xFF]))

        let rows = PassportDetailViewController.securityRows(for: record)
        #expect(rows.count == 6)
        #expect(rows.allSatisfy { $0.icon == "checkmark.circle.fill" })
        // A re-verified result is ignored for chip records.
        let failed = PassportSecurityStageResult(status: .failed, detail: "x")
        let rowsWithReverified = PassportDetailViewController.securityRows(
            for: record,
            reverifiedPassiveAuthentication: failed
        )
        #expect(rowsWithReverified == rows)
    }
}
