@testable import CENFC
import Foundation
import Testing

struct OpenURLRouterTests {
    @Test("Known file extensions route to the matching tabs")
    func routesKnownExtensions() throws {
        let scanURL = try ScanRecordDocument.exportToFile(makeScanRecord())
        let ndefURL = try NDEFDocument.exportToFile(makeNDEFRecord())
        let passportURL = try PassportDocument.exportToFile(makePassportRecord())

        #expect(OpenURLRouter.destination(for: scanURL) == .scanner)
        #expect(OpenURLRouter.destination(for: ndefURL) == .ndef)
        #expect(OpenURLRouter.destination(for: passportURL) == .passport)
    }

    @Test("Generic property list files are detected by payload")
    func inspectsPropertyListPayload() throws {
        let directory = FileManager.default.temporaryDirectory

        let scanURL = directory.appendingPathComponent(UUID().uuidString).appendingPathExtension("plist")
        try CardDocument.exportScanOnly(makeScanRecord()).write(to: scanURL, options: .atomic)

        let ndefURL = directory.appendingPathComponent(UUID().uuidString).appendingPathExtension("plist")
        try NDEFDocument.export(makeNDEFRecord()).write(to: ndefURL, options: .atomic)

        let passportURL = directory.appendingPathComponent(UUID().uuidString).appendingPathExtension("plist")
        try PassportDocument.export(makePassportRecord()).write(to: passportURL, options: .atomic)

        #expect(OpenURLRouter.destination(for: scanURL) == .scanner)
        #expect(OpenURLRouter.destination(for: ndefURL) == .ndef)
        #expect(OpenURLRouter.destination(for: passportURL) == .passport)
    }

    @Test("Files without a recognized extension still fall back to payload inspection")
    func fallsBackWithoutRecognizedExtension() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try NDEFDocument.export(makeNDEFRecord()).write(to: url, options: .atomic)

        #expect(OpenURLRouter.destination(for: url) == .ndef)
    }
}

private func makeScanRecord() -> ScanRecord {
    ScanRecord(cardInfo: CardInfo(type: .ntag213, uid: Data([0x04, 0x57, 0x01, 0xCA])))
}

private func makeNDEFRecord() -> NDEFDataRecord {
    NDEFDataRecord(
        name: "Example Record",
        messageData: Data([0xD1, 0x01, 0x0C, 0x55, 0x03, 0x6F, 0x70, 0x65, 0x6E, 0x61, 0x69, 0x2E, 0x63, 0x6F, 0x6D])
    )
}

private func makePassportRecord() throws -> PassportRecord {
    let mrz = try MRZData(
        mrzString: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    )
    let passport = PassportModel(
        ldsVersion: "0107",
        unicodeVersion: "040000",
        availableDataGroups: [.dg1, .dg2],
        mrz: mrz,
        faceImageData: nil,
        signatureImageData: nil,
        additionalPersonalDetails: nil,
        additionalDocumentDetails: nil,
        securityInfos: nil,
        securityInfoRaw: nil,
        activeAuthPublicKey: nil,
        activeAuthPublicKeyRaw: nil,
        sod: nil,
        sodRaw: nil,
        passiveAuthResult: nil,
        activeAuthResult: nil,
        rawDataGroups: [:]
    )
    return PassportRecord(from: passport)
}
