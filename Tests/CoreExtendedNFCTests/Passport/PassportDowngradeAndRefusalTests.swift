// Regression tests for PACE nonce checks, Active Authentication refusals, PACE-to-BAC
// downgrade detection, DG2 nesting limits and DG14 INTEGER decoding.
//
// ## References
// - ICAO Doc 9303 Part 11 §4.4.3.3: the PACE nonce s is a multiple of the cipher block
//   size, encrypted in CBC mode with K_pi and an all-zero IV
// - ICAO Doc 9303 Part 11 §9.2.11: SecurityInfos of EF.CardAccess are repeated in DG14,
//   which Passive Authentication protects
// - ICAO Doc 9303 Part 11 §6.1: Active Authentication (INTERNAL AUTHENTICATE)
// - ICAO Doc 9303 Part 10 §4.7.2: DG2 biometric template nesting
// - ITU-T X.690 §8.3: INTEGER encoding
@testable import CoreExtendedNFC
import Foundation
import Testing

#if canImport(OpenSSL)
    import OpenSSL
#endif

struct PassportDowngradeAndRefusalTests {
    static let mrzKey = "L898902C<369080619406236"

    static func makeDG1() -> Data {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
            + "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        return ASN1Parser.encodeTLV(tag: 0x61, value: ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data(mrz.utf8)))
    }

    /// DG15 with a P-256 SubjectPublicKeyInfo whose point is the curve generator.
    static func makeDG15() -> Data {
        let algorithm = vectorTLV(
            0x30,
            vectorTLV(0x06, vectorHex("2A8648CE3D0201")) + vectorTLV(0x06, vectorHex("2A8648CE3D030107"))
        )
        let point = vectorHex(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        let spki = vectorTLV(0x30, algorithm + vectorTLV(0x03, Data([0x00]) + point))
        return vectorTLV(0x6F, spki)
    }

    /// EF.SOD whose LDSSecurityObject hashes `hashedDataGroups` (no SignerInfo).
    static func makeUnsignedSOD(hashedDataGroups: [UInt8]) -> Data {
        let sha256 = vectorTLV(0x30, vectorTLV(0x06, vectorHex("608648016503040201")))
        let hashes = hashedDataGroups.map { number in
            vectorTLV(0x30, vectorTLV(0x02, Data([number])) + vectorTLV(0x04, Data(repeating: number, count: 32)))
        }.reduce(Data(), +)
        let lds = vectorTLV(0x30, vectorTLV(0x02, Data([0x00])) + sha256 + vectorTLV(0x30, hashes))
        let encapContentInfo = vectorTLV(
            0x30,
            vectorTLV(0x06, vectorHex("678108010101")) + vectorTLV(0xA0, vectorTLV(0x04, lds))
        )
        let signedData = vectorTLV(0x30, vectorTLV(0x02, Data([0x03])) + vectorTLV(0x31, sha256) + encapContentInfo)
        let contentInfo = vectorTLV(0x30, vectorTLV(0x06, vectorHex("2A864886F70D010702")) + vectorTLV(0xA0, signedData))
        return vectorTLV(0x77, contentInfo)
    }

    static func makeDG14(paceProtocol: SecurityProtocol, parameterID: UInt8 = 0x0C) -> Data {
        let oid = ChipAuthenticationHandler.encodeOID(paceProtocol.rawValue)
        let paceInfo = vectorTLV(0x30, vectorTLV(0x06, oid) + vectorTLV(0x02, Data([0x02])) + vectorTLV(0x02, Data([parameterID])))
        return vectorTLV(0x6E, vectorTLV(0x31, paceInfo))
    }

    // MARK: - PACE nonce

    @Test
    func `PACE encrypted nonce must be a non-empty whole number of cipher blocks`() throws {
        for (length, mode) in [(0, SMEncryptionMode.aes128), (15, .aes128), (17, .aes256), (0, .tripleDES), (12, .tripleDES)] {
            #expect(throws: NFCError.self, "\(length) bytes in \(mode)") {
                try PACEHandler.validateEncryptedNonce(Data(count: length), mode: mode)
            }
        }
        for (length, mode) in [(16, SMEncryptionMode.aes128), (32, .aes192), (8, .tripleDES), (16, .tripleDES)] {
            try PACEHandler.validateEncryptedNonce(Data(count: length), mode: mode)
        }
    }

    #if canImport(OpenSSL)
        static let paceInfo = PACEInfo(
            protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
            securityProtocol: .paceECDHGMAESCBCCMAC128,
            version: 2,
            parameterID: 12
        )

        @Test
        func `PACE rejects an empty encrypted nonce from a chip that never used the password`() async throws {
            let chip = try PasswordlessPACEChip(
                oid: ChipAuthenticationHandler.encodeOID(Self.paceInfo.protocolOID),
                encryptedNonce: Data()
            )
            await #expect(throws: NFCError.self) {
                _ = try await PACEHandler.performPACE(
                    paceInfo: Self.paceInfo,
                    mrzKey: "TOTALLY-WRONG-PASSWORD-THE-CHIP-NEVER-SAW",
                    transport: chip
                )
            }
            // Rejected before the mapping step: no key material leaves the terminal.
            #expect(chip.generalAuthenticateCount == 1)
        }

        @Test
        func `PACE rejects a nonce that decrypts to zero`() async throws {
            let mrzKey = Self.mrzKey
            let kpi = try PACEHandler.derivePasswordKey(password: mrzKey, keyReference: .mrz, mode: .aes128)
            let zeroNonce = try CryptoUtils.aesEncrypt(key: kpi, message: Data(count: 16), iv: Data(count: 16))
            let chip = try PasswordlessPACEChip(
                oid: ChipAuthenticationHandler.encodeOID(Self.paceInfo.protocolOID),
                encryptedNonce: zeroNonce
            )
            await #expect(throws: NFCError.self) {
                _ = try await PACEHandler.performPACE(paceInfo: Self.paceInfo, mrzKey: mrzKey, transport: chip)
            }
            #expect(chip.generalAuthenticateCount == 1)
        }

        @Test
        func `Zero modulo the curve order is detected for empty, zero and n`() throws {
            let curve = try OpenSSLPACECurve(parameterID: .secp256r1)
            let order = vectorHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
            #expect(try curve.isZeroModuloOrder(Data()))
            #expect(try curve.isZeroModuloOrder(Data(count: 32)))
            #expect(try curve.isZeroModuloOrder(order))
            #expect(try !curve.isZeroModuloOrder(vectorHex("3F00C4D39D153F2B2A214A078D899B22")))
        }
    #endif

    // MARK: - Active Authentication

    @Test
    func `AA stage is failed when the chip refuses INTERNAL AUTHENTICATE with a plain SW`() async throws {
        let inner = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.dg15.fileID: Self.makeDG15(),
        ])
        let chip = PlainInternalAuthenticateRefusal(inner: inner)
        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg15],
            performActiveAuth: true
        )
        #expect(model.rawDataGroups[.dg15] != nil)
        #expect(model.securityReport.activeAuthentication.status == .failed)
        #expect(model.securityReport.activeAuthentication.detail.contains("refused INTERNAL AUTHENTICATE"))
        #expect(model.activeAuthResult?.status == .commandFailed)
        // Re-judging offline keeps the failure.
        #expect(model.reverifyingSecurity().securityReport.activeAuthentication.status == .failed)
    }

    @Test
    func `AA stage is failed when EF.SOD lists DG15 but the chip hides it`() async throws {
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.sod.fileID: Self.makeUnsignedSOD(hashedDataGroups: [1, 15]),
        ])
        chip.plainNotFoundForMissingFiles = true

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.sod, .dg1, .dg15]
        )
        #expect(model.rawDataGroups[.dg15] == nil)
        #expect(model.securityReport.activeAuthentication.status == .failed)
        #expect(model.securityReport.activeAuthentication.detail.contains("EF.SOD lists DG15"))
    }

    @Test
    func `AA stage stays notAdvertised or skipped when DG15 is genuinely absent or AA is disabled`() async throws {
        let files = [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.sod.fileID: Self.makeUnsignedSOD(hashedDataGroups: [1]),
        ]
        let absent = try await PassportReader(transport: SimulatedBACChip(files: files)).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.sod, .dg1]
        )
        #expect(absent.securityReport.activeAuthentication.status == .notAdvertised)

        let disabled = try await PassportReader(transport: SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.dg15.fileID: Self.makeDG15(),
        ])).readPassport(mrzKey: Self.mrzKey, dataGroups: [.dg1, .dg15], performActiveAuth: false)
        #expect(disabled.securityReport.activeAuthentication.status == .skipped)
    }

    @Test
    func `AA stage helper fails without a key when DG15 is known to exist`() {
        let listed = PassportReader.activeAuthenticationStage(
            requested: true,
            publicKeyPresent: false,
            dg15Evidence: "EF.COM lists DG15",
            result: nil,
            passiveAuthResult: nil
        )
        #expect(listed.status == .failed)
        let absent = PassportReader.activeAuthenticationStage(
            requested: true,
            publicKeyPresent: false,
            result: nil,
            passiveAuthResult: nil
        )
        #expect(absent.status == .notAdvertised)
        #expect(PassportReader.dg15Evidence(rawDataGroups: [:], sod: nil, com: [.dg1]) == nil)
        #expect(PassportReader.dg15Evidence(rawDataGroups: [:], sod: nil, com: [.dg15]) != nil)
    }

    // MARK: - PACE downgrade

    @Test
    func `BAC downgrade is flagged when DG14 advertises PACE but EF.CardAccess was withheld`() async throws {
        let dg14 = Self.makeDG14(paceProtocol: .paceECDHGMAESCBCCMAC128)
        #expect(try DG14Parser.parse(dg14).supportsPACE)

        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.dg14.fileID: dg14,
        ])
        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg14],
            performActiveAuth: false
        )
        let report = model.securityReport
        #expect(report.cardAccess.status == .notSupported)
        #expect(report.bac.status == .succeeded)
        #expect(report.pace.status == .failed)
        #expect(report.pace.detail.contains("downgrade"))
    }

    @Test
    func `No downgrade is flagged when DG14 only advertises PACE the reader does not support`() async throws {
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: Self.makeDG1(),
            DataGroupId.dg14.fileID: Self.makeDG14(paceProtocol: .paceECDHIMAESCBCCMAC128),
        ])
        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg14],
            performActiveAuth: false
        )
        #expect(model.securityReport.pace.status == .notSupported)
    }

    @Test
    func `PACE stage helper keeps a completed PACE and flags every other outcome`() throws {
        let infos = try DG14Parser.parse(Self.makeDG14(paceProtocol: .paceECDHGMAESCBCCMAC128))
        let succeeded = PassportSecurityStageResult(status: .succeeded, detail: "PACE completed.")
        #expect(PassportReader.paceStage(succeeded, paceCompleted: true, dg14SecurityInfos: infos, passiveAuthResult: nil) == succeeded)

        for negotiated in [PassportSecurityStageStatus.fallback, .notAdvertised, .notSupported] {
            let stage = PassportSecurityStageResult(status: negotiated, detail: "x")
            #expect(PassportReader.paceStage(stage, paceCompleted: false, dg14SecurityInfos: infos, passiveAuthResult: nil).status == .failed)
            #expect(PassportReader.paceStage(stage, paceCompleted: false, dg14SecurityInfos: nil, passiveAuthResult: nil) == stage)
        }
    }

    // MARK: - DG2 nesting

    static func nestedDG2(depth: Int, imageBytes: Int) -> Data {
        var payload = vectorTLV(0x5F2E, Data([0x00, 0x01, 0xFF, 0xD8]) + Data(repeating: 0x41, count: imageBytes))
        for _ in 0 ..< depth {
            payload = vectorTLV(0x7F61, payload)
        }
        return vectorTLV(0x75, payload)
    }

    @Test
    func `DG2 image is found up to the nesting limit and not beyond`() throws {
        // Depth counts from the content of 75: the biometric data block sits inside
        // `depth` wrappers. The ICAO layout (7F61 → 7F60 → 5F2E) is depth 2.
        for depth in 0 ..< DG2Parser.maxSearchDepth {
            let image = try DataGroupParser.parseDG2(Self.nestedDG2(depth: depth, imageBytes: 16))
            #expect(image == Data([0xFF, 0xD8]) + Data(repeating: 0x41, count: 16), "depth \(depth)")
            #expect(image.startIndex == 0)
        }
        #expect(throws: NFCError.self) {
            try DataGroupParser.parseDG2(Self.nestedDG2(depth: DG2Parser.maxSearchDepth, imageBytes: 16))
        }
        #expect(DG2Parser.maxSearchDepth == 8)
    }

    @Test
    func `Deeply nested multi-megabyte DG2 is rejected without per-level copies`() {
        // 30 wrappers around 4 MB: the old parser copied the payload once per level.
        let dg2 = Self.nestedDG2(depth: 30, imageBytes: 4 * 1024 * 1024)
        #expect(throws: NFCError.self) { try DataGroupParser.parseDG2(dg2) }

        let shallow = Self.nestedDG2(depth: 2, imageBytes: 4 * 1024 * 1024)
        #expect((try? DataGroupParser.parseDG2(shallow))?.count == 4 * 1024 * 1024 + 2)
    }

    @Test
    func `DG2 parses from a slice with a non-zero start index`() throws {
        let dg2 = Data([0xAA, 0xBB]) + Self.nestedDG2(depth: 2, imageBytes: 4)
        let slice = dg2[2...]
        #expect(try DataGroupParser.parseDG2(slice) == Data([0xFF, 0xD8, 0x41, 0x41, 0x41, 0x41]))
    }

    @Test
    func `TLV headers index into the parsed data and match parseTLV`() throws {
        let data = Data([0x99]) + vectorTLV(0x30, vectorTLV(0x04, Data([1, 2])) + Data([0x00]) + vectorTLV(0x5F1F, Data([3])))
        let slice = data[1...]
        let headers = try ASN1Parser.parseTLVHeaders(slice)
        #expect(headers.count == 1)
        #expect(headers[0].valueRange.lowerBound == 3)
        let children = try ASN1Parser.parseTLVHeaders(slice[headers[0].valueRange])
        #expect(children.map(\.tag) == [0x04, 0x5F1F])
        #expect(try ASN1Parser.parseTLV(slice[headers[0].valueRange]).map(\.value) == [Data([1, 2]), Data([3])])
        let found = try #require(ASN1Parser.findTag(0x5F1F, in: ASN1Parser.parseTLV(slice)))
        #expect(found.value == Data([3]) && found.value.startIndex == 0)
    }

    // MARK: - DG14 INTEGER decoding

    @Test
    func `DG14 INTEGER decoding rejects negative and over-wide values instead of wrapping`() {
        #expect(DG14Parser.decodeInteger(Data([0x0D])) == 13)
        #expect(DG14Parser.decodeInteger(Data([0x00, 0x80])) == 128)
        #expect(DG14Parser.decodeInteger(Data([0x00, 0x00, 0x01])) == 1)
        #expect(DG14Parser.decodeInteger(Data([0x7F] + [UInt8](repeating: 0xFF, count: 7))) == Int.max)
        #expect(DG14Parser.decodeInteger(Data()) == nil)
        #expect(DG14Parser.decodeInteger(Data([0x80])) == nil)
        #expect(DG14Parser.decodeInteger(Data([0xFF, 0xFF])) == nil)
        #expect(DG14Parser.decodeInteger(Data([0x01] + [UInt8](repeating: 0x00, count: 8))) == nil)
        #expect(DG14Parser.decodeInteger(Data([0x00, 0x80] + [UInt8](repeating: 0x00, count: 7))) == nil)
    }

    @Test
    func `A PACEInfo whose parameter ID would wrap is dropped`() throws {
        let oid = ChipAuthenticationHandler.encodeOID(SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue)
        // 2^64 + 12 used to wrap to parameter ID 12 (NIST P-256).
        let wrapping = Data([0x01] + [UInt8](repeating: 0x00, count: 7) + [0x0C])
        let paceInfo = vectorTLV(0x30, vectorTLV(0x06, oid) + vectorTLV(0x02, Data([0x02])) + vectorTLV(0x02, wrapping))
        let infos = try DG14Parser.parse(vectorTLV(0x6E, vectorTLV(0x31, paceInfo)))
        #expect(infos.paceInfos.isEmpty)
    }

    // MARK: - Parser robustness

    @Test
    func `Data group parsers never trap on mutated input`() {
        var rng = SplitMix64(seed: 0xC0FFEE)
        let seeds: [Data] = [
            Self.makeDG1(), Self.makeDG15(), SODFixtures.genuineSOD, SODFixtures.forgedSOD,
            Self.makeDG14(paceProtocol: .paceECDHGMAESCBCCMAC128),
            vectorTLV(0x75, vectorTLV(0x7F61, vectorTLV(0x02, Data([1])) + vectorTLV(0x7F60, vectorTLV(0x5F2E, Data([0xFF, 0xD8, 0x01]))))),
            vectorTLV(0x6B, vectorTLV(0x5C, Data([0x5F, 0x0E])) + vectorTLV(0x5F0E, Data("A".utf8))),
            vectorTLV(0x60, vectorTLV(0x5F01, Data("0107".utf8)) + vectorTLV(0x5F36, Data("040000".utf8)) + vectorTLV(0x5C, Data([0x61, 0x75]))),
        ]
        for iteration in 0 ..< 6000 {
            var input = seeds[iteration % seeds.count]
            let mutations = Int(rng.next() % 6) + 1
            for _ in 0 ..< mutations where !input.isEmpty {
                let position = Int(rng.next() % UInt64(input.count))
                switch rng.next() % 4 {
                case 0: input[input.startIndex + position] = UInt8(truncatingIfNeeded: rng.next())
                case 1: input.removeSubrange((input.startIndex + position)...)
                case 2: input.insert(UInt8(truncatingIfNeeded: rng.next()), at: input.startIndex + position)
                default: input[input.startIndex + position] ^= 0x80
                }
            }
            _ = try? DataGroupParser.parseDG1(input)
            _ = try? DataGroupParser.parseDG2(input)
            _ = try? DataGroupParser.parseDG7(input)
            _ = try? DataGroupParser.parseDG11(input)
            _ = try? DataGroupParser.parseDG12(input)
            _ = try? DataGroupParser.parseCOM(input)
            _ = try? DG14Parser.parse(input)
            _ = try? DG15Parser.parse(input)
            _ = DG15Parser.subjectPublicKeyInfo(input)
            _ = try? CardAccessParser.parse(input)
            if let sod = try? SODParser.parse(input) {
                _ = SODParser.verifyPassiveAuthentication(sodContent: sod, rawDataGroups: [.dg1: SODFixtures.dg1])
            }
        }
    }
}

/// Deterministic generator for the mutation test.
struct SplitMix64 {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// A clone without the AA private key: answers INTERNAL AUTHENTICATE with a plain status word.
final class PlainInternalAuthenticateRefusal: NFCTagTransport, @unchecked Sendable {
    let inner: SimulatedBACChip
    var identifier: Data { inner.identifier }
    init(inner: SimulatedBACChip) { self.inner = inner }
    func send(_: Data) async throws -> Data { throw NFCError.unsupportedOperation("raw") }
    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        if apdu.cla & 0x0C == 0x0C, apdu.ins == 0x88 {
            return ResponseAPDU(data: Data(), sw1: 0x6D, sw2: 0x00)
        }
        return try await inner.sendAPDU(apdu)
    }
}

#if canImport(OpenSSL)
    /// A PACE "chip" that never derives K_pi. It sends `encryptedNonce` as z; when the
    /// terminal's s is 0 mod n, G^ = H, which the chip knows without the password.
    final class PasswordlessPACEChip: NFCTagTransport, @unchecked Sendable {
        let identifier = Data([0x04, 0x01, 0x02, 0x03])
        private let curve: OpenSSLPACECurve
        private let oid: Data
        private let encryptedNonce: Data
        private(set) var generalAuthenticateCount = 0
        private var mappedGenerator = Data()
        private var terminalEphemeral = Data()
        private var ksMac = Data()

        init(oid: Data, encryptedNonce: Data) throws {
            self.oid = oid
            self.encryptedNonce = encryptedNonce
            curve = try OpenSSLPACECurve(parameterID: .secp256r1)
        }

        func send(_: Data) async throws -> Data { throw NFCError.unsupportedOperation("raw") }

        func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
            guard apdu.ins == 0x86 else { return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00) }
            generalAuthenticateCount += 1
            let wrapper = try #require(try ASN1Parser.parseTLV(apdu.data ?? Data()).first)
            let value = try wrapper.children().first?.value ?? Data()
            switch generalAuthenticateCount {
            case 1:
                return Self.dynamicAuthenticationData(0x80, encryptedNonce)
            case 2:
                let key = try curve.generatePrivateScalar()
                let publicKey = try curve.publicPoint(privateScalar: key, generator: nil)
                let shared = try curve.sharedPoint(privateScalar: key, peerPublic: value)
                mappedGenerator = try curve.mappedGenerator(nonce: Data(), sharedPoint: shared)
                return Self.dynamicAuthenticationData(0x82, publicKey)
            case 3:
                terminalEphemeral = value
                let key = try curve.generatePrivateScalar()
                let publicKey = try curve.publicPoint(privateScalar: key, generator: mappedGenerator)
                let secret = try curve.sharedSecretXCoordinate(privateScalar: key, peerPublic: value)
                ksMac = PACEHandler.derivePACESessionKeys(sharedSecret: secret, mode: .aes128).ksMac
                return Self.dynamicAuthenticationData(0x84, publicKey)
            default:
                let token = try PACEHandler.computeAuthToken(
                    ksMac: ksMac, publicKeyOther: terminalEphemeral, oid: oid, mode: .aes128
                )
                return Self.dynamicAuthenticationData(0x86, token)
            }
        }

        static func dynamicAuthenticationData(_ tag: UInt, _ value: Data) -> ResponseAPDU {
            ResponseAPDU(data: vectorTLV(0x7C, vectorTLV(tag, value)), sw1: 0x90, sw2: 0x00)
        }
    }
#endif
