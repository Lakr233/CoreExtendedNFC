// Passive/Active Authentication trust decisions, PACE reflection checks and secret hygiene.
//
// ## References
// - ICAO Doc 9303 Part 11 §5.1 (passive authentication: SOD signature + CSCA chain + hashes)
// - ICAO Doc 9303 Part 11 §6.1 (active authentication relies on an authenticated DG15)
// - ICAO Doc 9303 Part 11 §4.4.3.3 (PACE: reject a chip public key equal to the terminal's)
// - RFC 5652 §5.3 (SignerInfo SID identifies the signing certificate)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct PassportAuthenticationStageTests {
    // MARK: - SOD trust chain (fixtures in SODFixtures.swift)

    @Test
    func `A SOD signed by a DSC issued by the CSCA is fully verified`() throws {
        let sod = try SODParser.parse(SODFixtures.genuineSOD)
        #expect(sod.documentSignerCertificate == SODFixtures.dscDER)

        let result = SODParser.verifyPassiveAuthentication(
            sodContent: sod,
            rawDataGroups: [.dg1: SODFixtures.dg1],
            trustAnchorsDER: [SODFixtures.cscaDER]
        )
        #expect(result.status == .fullyVerified)
        #expect(PassportSecurityStageResult.passiveAuthentication(result, sodPresent: true).status == .succeeded)
    }

    @Test
    func `A SOD signed by a self-signed key next to a genuine DSC is not fully verified`() throws {
        let sod = try SODParser.parse(SODFixtures.forgedSOD)
        // The certificate the SignerInfo names, not the first one in the SET.
        #expect(sod.documentSignerCertificate == SODFixtures.rogueDER)

        let result = SODParser.verifyPassiveAuthentication(
            sodContent: sod,
            rawDataGroups: [.dg1: SODFixtures.dg1],
            trustAnchorsDER: [SODFixtures.cscaDER]
        )
        #expect(result.status == .trustChainInvalid)
        #expect(result.trustChainValid == false)
        #expect(PassportSecurityStageResult.passiveAuthentication(result, sodPresent: true).status == .failed)
    }

    @Test
    func `Re-running passive authentication on a decoded model uses only its raw bytes`() {
        // The stored result claims full verification; the bytes say otherwise.
        let forged = Self.makeModel(sod: SODFixtures.forgedSOD, claimed: .fullyVerified)
        #expect(forged.reverifyPassiveAuthentication(trustAnchorsDER: [SODFixtures.cscaDER]).status == .trustChainInvalid)

        let genuine = Self.makeModel(sod: SODFixtures.genuineSOD, claimed: .hashMismatch)
        #expect(genuine.reverifyPassiveAuthentication(trustAnchorsDER: [SODFixtures.cscaDER]).status == .fullyVerified)
        #expect(genuine.reverifyPassiveAuthentication().status == .signatureVerified)

        var tampered = SODFixtures.dg1
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        let tamperedModel = Self.makeModel(sod: SODFixtures.genuineSOD, claimed: .fullyVerified, dg1: tampered)
        #expect(tamperedModel.reverifyPassiveAuthentication(trustAnchorsDER: [SODFixtures.cscaDER]).status == .hashMismatch)

        let withoutSOD = Self.makeModel(sod: nil, claimed: .fullyVerified)
        #expect(withoutSOD.reverifyPassiveAuthentication().status == .sodNotAvailable)
    }

    // MARK: - Passive Authentication stage mapping

    @Test
    func `Passive authentication succeeds only when the signature chains to a CSCA`() {
        func stage(_ status: PassiveAuthStatus, hashes: [DataGroupId: Bool] = [.dg1: true]) -> PassportSecurityStageResult {
            .passiveAuthentication(
                PassiveAuthenticationResult(dataGroupHashResults: hashes, hasCertificate: true, status: status),
                sodPresent: true
            )
        }

        #expect(stage(.fullyVerified).status == .succeeded)

        let signatureOnly = stage(.signatureVerified)
        #expect(signatureOnly.status == .fallback)
        #expect(signatureOnly.detail.contains("not chained to a CSCA"))
        let hashesOnly = stage(.signatureNotVerified)
        #expect(hashesOnly.status == .fallback)
        #expect(hashesOnly.detail.contains("not chained to a CSCA"))

        #expect(stage(.signatureInvalid).status == .failed)
        #expect(stage(.trustChainInvalid).status == .failed)
        #expect(stage(.hashMismatch, hashes: [.dg1: false]).status == .failed)
        #expect(stage(.signatureNotVerified, hashes: [:]).status == .skipped)
    }

    @Test
    func `Without trust anchors a genuine SOD is a fallback, not a success`() throws {
        let sod = try SODParser.parse(SODFixtures.genuineSOD)
        let result = SODParser.verifyPassiveAuthentication(sodContent: sod, rawDataGroups: [.dg1: SODFixtures.dg1])
        #expect(result.status == .signatureVerified)
        #expect(PassportSecurityStageResult.passiveAuthentication(result, sodPresent: true).status == .fallback)
    }

    // MARK: - Active Authentication stage mapping

    @Test
    func `Active authentication succeeds only when DG15 is authenticated by a fully verified SOD`() {
        let verified = ActiveAuthenticationResult(success: true, details: "ECDSA verified", status: .verified)
        func stage(_ passive: PassiveAuthenticationResult?) -> PassportSecurityStageStatus {
            PassportReader.activeAuthenticationStage(
                requested: true,
                publicKeyPresent: true,
                result: verified,
                passiveAuthResult: passive
            ).status
        }

        #expect(stage(Self.passive(.fullyVerified, [.dg1: true, .dg15: true])) == .succeeded)
        // Signature valid but not chained to a CSCA: a clone can self-sign its SOD.
        #expect(stage(Self.passive(.signatureVerified, [.dg1: true, .dg15: true])) == .fallback)
        #expect(stage(Self.passive(.trustChainInvalid, [.dg1: true, .dg15: true])) == .fallback)
        // DG15 hash compared, but the SOD signature was not verified.
        #expect(stage(Self.passive(.signatureNotVerified, [.dg1: true, .dg15: true])) == .fallback)
        // SOD signature fine, but DG15 not covered by it.
        #expect(stage(Self.passive(.fullyVerified, [.dg1: true])) == .fallback)
        #expect(stage(nil) == .fallback)
        // DG15 does not match the SOD: the key was altered.
        #expect(stage(Self.passive(.hashMismatch, [.dg1: true, .dg15: false])) == .failed)

        let failed = PassportReader.activeAuthenticationStage(
            requested: true,
            publicKeyPresent: true,
            result: ActiveAuthenticationResult(success: false, details: "bad", status: .failed),
            passiveAuthResult: Self.passive(.fullyVerified, [.dg15: true])
        )
        #expect(failed.status == .failed)
    }

    @Test
    func `A valid AA signature over an unauthenticated key is never reported as verified`() {
        let signed = ActiveAuthenticationResult(success: true, details: "ECDSA verified", status: .verified)

        let unanchored = signed.classified(by: Self.passive(.signatureVerified, [.dg15: true]))
        #expect(unanchored.status == .verifiedUnauthenticatedKey)
        #expect(unanchored.success)
        #expect(signed.classified(by: nil).status == .verifiedUnauthenticatedKey)

        // Re-judging against fully verified passive authentication restores `.verified`.
        let anchored = unanchored.classified(by: Self.passive(.fullyVerified, [.dg15: true]))
        #expect(anchored.status == .verified)

        // Stage and status agree for both inputs.
        let fallback = PassportSecurityStageResult.activeAuthentication(
            unanchored,
            passiveAuthentication: Self.passive(.signatureVerified, [.dg15: true])
        )
        #expect(fallback.status == .fallback)
        let succeeded = PassportSecurityStageResult.activeAuthentication(
            unanchored,
            passiveAuthentication: Self.passive(.fullyVerified, [.dg15: true])
        )
        #expect(succeeded.status == .succeeded)
        #expect(PassportSecurityStageResult.activeAuthentication(nil, passiveAuthentication: nil).status == .skipped)

        // Failures are not re-labelled.
        let bad = ActiveAuthenticationResult(success: false, details: "bad", status: .failed)
        #expect(bad.classified(by: Self.passive(.fullyVerified, [.dg15: true])) == bad)
    }

    @Test
    func `Re-verifying security re-judges a stored AA result against the new passive result`() {
        let base = Self.makeModel(sod: SODFixtures.genuineSOD, claimed: .fullyVerified)
        let model = PassportModel(
            ldsVersion: nil,
            unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil,
            faceImageData: nil,
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: nil,
            securityInfoRaw: nil,
            activeAuthPublicKey: nil,
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: base.sodRaw,
            passiveAuthResult: base.passiveAuthResult,
            // A file claiming a genuine chip.
            activeAuthResult: ActiveAuthenticationResult(success: true, details: "ECDSA verified", status: .verified),
            rawDataGroups: base.rawDataGroups,
            securityReport: PassportSecurityReport(
                bac: PassportSecurityStageResult(status: .succeeded, detail: "BAC"),
                activeAuthentication: PassportSecurityStageResult(status: .succeeded, detail: "claimed")
            )
        )

        // The fixture SOD hashes only DG1, so DG15 is never authenticated.
        let reverified = model.reverifyingSecurity(trustAnchorsDER: [SODFixtures.cscaDER])
        #expect(reverified.passiveAuthResult?.status == .fullyVerified)
        #expect(reverified.securityReport.passiveAuthentication.status == .succeeded)
        #expect(reverified.activeAuthResult?.status == .verifiedUnauthenticatedKey)
        #expect(reverified.securityReport.activeAuthentication.status == .fallback)
        #expect(reverified.securityReport.bac == model.securityReport.bac)

        let unanchored = model.reverifyingSecurity()
        #expect(unanchored.securityReport.passiveAuthentication.status == .fallback)
        #expect(unanchored.securityReport.activeAuthentication.status == .fallback)

        // Without a stored AA result the stored AA stage (why AA did not run) is kept.
        let withoutAA = base.reverifyingSecurity(trustAnchorsDER: [SODFixtures.cscaDER])
        #expect(withoutAA.securityReport.activeAuthentication == base.securityReport.activeAuthentication)
    }

    private static func passive(_ status: PassiveAuthStatus, _ hashes: [DataGroupId: Bool]) -> PassiveAuthenticationResult {
        PassiveAuthenticationResult(dataGroupHashResults: hashes, hasCertificate: true, status: status)
    }

    // MARK: - PACE reflection (ICAO 9303-11 §4.4.3.3)

    #if canImport(OpenSSL)
        @Test
        func `PACE rejects a chip that reflects the terminal's mapping public key`() async {
            let chip = ReflectingPACEChip(reflectMapping: true)
            let error = await #expect(throws: NFCError.self) {
                _ = try await PACEHandler.performPACE(paceInfo: Self.paceInfo, mrzKey: "L898902C<369080619406236", transport: chip)
            }
            #expect(String(describing: error).contains("mapping public key reflects"))
            // MSE:Set AT, GA nonce, GA map — no key agreement step.
            #expect(chip.generalAuthenticateCount == 2)
        }

        @Test
        func `PACE rejects a chip that reflects the terminal's ephemeral public key`() async {
            let chip = ReflectingPACEChip(reflectMapping: false)
            let error = await #expect(throws: NFCError.self) {
                _ = try await PACEHandler.performPACE(paceInfo: Self.paceInfo, mrzKey: "L898902C<369080619406236", transport: chip)
            }
            #expect(String(describing: error).contains("ephemeral public key reflects"))
            // No mutual authentication token is sent.
            #expect(chip.generalAuthenticateCount == 3)
        }
    #endif

    // MARK: - Constant-time comparison and secret redaction

    @Test
    func `Constant-time comparison matches byte equality on sliced data`() {
        let buffer = Data([0xEE, 0x01, 0x02, 0x03, 0xEE])
        #expect(CryptoUtils.constantTimeEquals(buffer[1 ..< 4], Data([0x01, 0x02, 0x03])))
        #expect(!CryptoUtils.constantTimeEquals(buffer[1 ..< 4], Data([0x01, 0x02, 0x04])))
        #expect(!CryptoUtils.constantTimeEquals(buffer[1 ..< 4], Data([0x01, 0x02])))
        #expect(CryptoUtils.constantTimeEquals(Data(), Data()))
    }

    @Test
    func `Session types never print their keys`() {
        let key = Data(repeating: 0xAB, count: 16)
        let desfire = DESFireAuthenticationSession(
            scheme: .authenticateEV2First,
            keyNumber: 0,
            sessionENCKey: key,
            sessionMACKey: key
        )
        let ultralight = UltralightCAuthenticationSession(randomA: key, randomB: key)
        let secureMessaging = SecureMessagingTransport(transport: MockTransport(), ksEnc: key, ksMac: key, ssc: Data(count: 8))

        for value in [desfire, ultralight, secureMessaging] as [Any] {
            var dumped = ""
            dump(value, to: &dumped)
            for text in [String(describing: value), String(reflecting: value), dumped] {
                #expect(!text.contains("171"), "decimal key byte leaked: \(text)")
                #expect(!text.uppercased().contains("ABAB"), "hex key bytes leaked: \(text)")
                #expect(text.contains("redacted"))
            }
        }
    }

    // MARK: - Helpers

    private static let paceInfo = PACEInfo(
        protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
        securityProtocol: .paceECDHGMAESCBCCMAC128,
        version: 2,
        parameterID: 12
    )

    private static func makeModel(sod: Data?, claimed: PassiveAuthStatus, dg1: Data = SODFixtures.dg1) -> PassportModel {
        var raw: [DataGroupId: Data] = [.dg1: dg1]
        raw[.sod] = sod
        return PassportModel(
            ldsVersion: nil,
            unicodeVersion: nil,
            availableDataGroups: [],
            mrz: nil,
            faceImageData: nil,
            signatureImageData: nil,
            additionalPersonalDetails: nil,
            additionalDocumentDetails: nil,
            securityInfos: nil,
            securityInfoRaw: nil,
            activeAuthPublicKey: nil,
            activeAuthPublicKeyRaw: nil,
            sod: nil,
            sodRaw: sod,
            passiveAuthResult: PassiveAuthenticationResult(dataGroupHashResults: [.dg1: true], hasCertificate: true, status: claimed),
            activeAuthResult: nil,
            rawDataGroups: raw
        )
    }
}

#if canImport(OpenSSL)
    /// A PACE chip that echoes the terminal's mapping key, or (with `reflectMapping` false)
    /// answers the mapping step with the P-256 generator and then echoes the ephemeral key.
    private final class ReflectingPACEChip: NFCTagTransport, @unchecked Sendable {
        let identifier = Data([0x04, 0x01, 0x02, 0x03])
        private let reflectMapping: Bool
        private(set) var generalAuthenticateCount = 0

        /// P-256 generator G, uncompressed (SEC 2 §2.4.2).
        private static let generator = vectorHex(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )

        init(reflectMapping: Bool) {
            self.reflectMapping = reflectMapping
        }

        func send(_: Data) async throws -> Data {
            throw NFCError.unsupportedOperation("Raw transport is not used")
        }

        func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
            guard apdu.ins == 0x86 else {
                return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00) // MSE:Set AT
            }
            generalAuthenticateCount += 1
            guard let wrapper = try ASN1Parser.parseTLV(apdu.data ?? Data()).first else {
                throw NFCError.invalidResponse(Data())
            }
            let terminalKey = try wrapper.children().first?.value ?? Data()
            switch generalAuthenticateCount {
            case 1:
                return Self.dynamicAuthentication(tag: 0x80, value: Data(repeating: 0x5A, count: 16))
            case 2:
                return Self.dynamicAuthentication(tag: 0x82, value: reflectMapping ? terminalKey : Self.generator)
            case 3:
                return Self.dynamicAuthentication(tag: 0x84, value: terminalKey)
            default:
                return ResponseAPDU(data: Data(), sw1: 0x63, sw2: 0x00)
            }
        }

        private static func dynamicAuthentication(tag: UInt, value: Data) -> ResponseAPDU {
            ResponseAPDU(data: vectorTLV(0x7C, vectorTLV(tag, value)), sw1: 0x90, sw2: 0x00)
        }
    }
#endif
