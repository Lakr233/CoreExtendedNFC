// PassportModel built from raw data group bytes, and the top-level
// `readPassport(transport:...)` overload for callers that already scanned.
//
// ## References
// - ICAO Doc 9303 Part 10 §4.7 (DG1 MRZ, DG11/DG12 additional details)
// - ICAO Doc 9303 Part 11 §5.1 (passive authentication)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct PassportModelParsingTests {
    private static let mrzKey = "L898902C<369080619406236"

    private static func makeDG11() -> Data {
        ASN1Parser.encodeTLV(
            tag: 0x6B,
            value: ASN1Parser.encodeTLV(tag: 0x5F0E, value: Data("ERIKSSON<<ANNA<MARIA".utf8))
                + ASN1Parser.encodeTLV(tag: 0x5F11, value: Data("ZENITH".utf8))
        )
    }

    private static func makeDG12() -> Data {
        ASN1Parser.encodeTLV(
            tag: 0x6C,
            value: ASN1Parser.encodeTLV(tag: 0x5F19, value: Data("UTOPIA PASSPORT OFFICE".utf8))
                + ASN1Parser.encodeTLV(tag: 0x5F26, value: Data("20020415".utf8))
        )
    }

    @Test
    func `Top-level readPassport over an existing transport reads and reports progress`() async throws {
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: SODFixtures.dg1,
            DataGroupId.dg11.fileID: Self.makeDG11(),
            DataGroupId.dg12.fileID: Self.makeDG12(),
        ])
        let progress = ProgressRecorder()

        let model = try await CoreExtendedNFC.readPassport(
            transport: chip,
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg11, .dg12],
            performActiveAuth: false,
            onProgress: { progress.append($0) }
        )

        #expect(model.mrz?.documentNumber == "L898902C3")
        #expect(model.additionalPersonalDetails?["fullName"] == "ERIKSSON<<ANNA<MARIA")
        #expect(model.additionalDocumentDetails?["issuingAuthority"] == "UTOPIA PASSPORT OFFICE")
        #expect(model.securityReport.bac.status == .succeeded)
        #expect(!progress.messages.isEmpty)
    }

    @Test
    func `PassportModel from raw data groups matches the model a chip read returns`() async throws {
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: SODFixtures.dg1,
            DataGroupId.dg11.fileID: Self.makeDG11(),
            DataGroupId.dg12.fileID: Self.makeDG12(),
        ])
        let read = try await CoreExtendedNFC.readPassport(
            transport: chip,
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg11, .dg12],
            performActiveAuth: false
        )

        let parsed = PassportModel(rawDataGroups: read.rawDataGroups)

        #expect(parsed.rawDataGroups == read.rawDataGroups)
        #expect(parsed.mrz == read.mrz)
        #expect(parsed.additionalPersonalDetails == read.additionalPersonalDetails)
        #expect(parsed.additionalDocumentDetails == read.additionalDocumentDetails)
        #expect(parsed.additionalPersonalDetails?["placeOfBirth"] == "ZENITH")
        #expect(parsed.additionalDocumentDetails?["dateOfIssue"] == "20020415")
        #expect(parsed.availableDataGroups == read.availableDataGroups)
        #expect(parsed.passiveAuthResult == read.passiveAuthResult)
        #expect(parsed.activeAuthResult == nil)
        // Chip-only stages are reported as not run, never as pending or succeeded.
        #expect(parsed.securityReport.bac.status == .skipped)
        #expect(parsed.securityReport.pace.status == .skipped)
        #expect(parsed.securityReport.activeAuthentication.status == .skipped)
    }

    @Test
    func `PassportModel from raw data groups runs passive authentication with trust anchors`() throws {
        let raw: [DataGroupId: Data] = [.dg1: SODFixtures.dg1, .sod: SODFixtures.genuineSOD]

        let model = PassportModel(rawDataGroups: raw, trustAnchorsDER: [SODFixtures.cscaDER])

        #expect(model.mrz?.documentNumber == "L898902C3")
        #expect(model.sod != nil)
        #expect(model.sodRaw == SODFixtures.genuineSOD)
        #expect(model.passiveAuthResult?.status == .fullyVerified)
        #expect(model.securityReport.passiveAuthentication.status == .succeeded)
        // Same outcome as re-verifying the stored bytes.
        #expect(model.passiveAuthResult == model.reverifyPassiveAuthentication(trustAnchorsDER: [SODFixtures.cscaDER]))

        let reader = PassportReader(transport: MockTransport()).assemblePassportModel(
            rawDataGroups: raw,
            trustAnchorsDER: [SODFixtures.cscaDER],
            cardAccess: nil,
            cardAccessRaw: nil,
            securityReport: PassportSecurityReport(),
            dataGroupReadStatus: [:]
        )
        #expect(reader.mrz == model.mrz)
        #expect(reader.sod == model.sod)
        #expect(reader.passiveAuthResult == model.passiveAuthResult)
    }

    @Test
    func `PassportModel from raw data groups can skip passive authentication`() throws {
        var tampered = SODFixtures.dg1
        tampered[tampered.count - 1] ^= 0x01

        let skipped = PassportModel(
            rawDataGroups: [.dg1: tampered, .sod: SODFixtures.genuineSOD],
            performPassiveAuthentication: false
        )
        #expect(skipped.passiveAuthResult == nil)
        #expect(skipped.securityReport.passiveAuthentication.status == .skipped)
        #expect(skipped.sod != nil)

        let checked = PassportModel(rawDataGroups: [.dg1: tampered, .sod: SODFixtures.genuineSOD])
        #expect(checked.passiveAuthResult?.status == .hashMismatch)
        #expect(checked.securityReport.passiveAuthentication.status == .failed)
    }

    @Test
    func `PassportModel from raw data groups leaves unparseable data groups empty`() {
        let model = PassportModel(rawDataGroups: [.dg1: Data([0x61, 0x00]), .dg11: Data([0x6B, 0x00])])
        #expect(model.mrz == nil)
        #expect(model.additionalPersonalDetails?.isEmpty ?? true)
        #expect(model.passiveAuthResult == nil)
        #expect(model.securityReport.passiveAuthentication.status == .notSupported)
    }
}

/// Collects progress messages delivered from any thread.
final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func append(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        storage.append(message)
    }
}
