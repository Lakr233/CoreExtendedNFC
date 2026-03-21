// Passport reader tests: PACE info parsing, BAC key derivation, MRZ vectors.
//
// ## References
// - BSI TR-03110 Part 3, Section A.6.1: PACEInfo structure in EF.CardAccess
//   https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html
// - ICAO Doc 9303 Part 11, Section 9.7: BAC protocol
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - ICAO Doc 9303 Part 11, Appendix D.1: MRZ key derivation test vector
@testable import CoreExtendedNFC
import Foundation
import Testing

struct PassportReaderTests {
    @Test("CardAccess parser extracts advertised PACE info")
    func parseCardAccessPACEInfo() throws {
        let cardAccessData = makeCardAccessData()

        let result = try CardAccessParser.parse(cardAccessData)

        #expect(result.supportsPACE)
        #expect(result.paceInfos.count == 1)
        #expect(result.paceInfos[0].protocolOID == SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue)
        #expect(result.paceInfos[0].parameterID == 12)
    }

    @Test("Passport reader falls back to BAC when advertised PACE cannot complete")
    func readPassportFallsBackToBACAfterPACEAttempt() async throws {
        let mrzKey = "L898902C<369080619406236"
        let cardAccessData = makeCardAccessData()
        let transport = PassportNegotiationTransport(
            mrzKey: mrzKey,
            cardAccessData: cardAccessData
        )

        let model = try await PassportReader(transport: transport).readPassport(
            mrzKey: mrzKey,
            dataGroups: [],
            performActiveAuth: false
        )

        #expect(model.cardAccess?.supportsPACE == true)
        #expect(model.securityReport.cardAccess.status == .succeeded)
        #expect(model.securityReport.pace.status == .fallback)
        #expect(model.securityReport.bac.status == .succeeded)
        #expect(model.securityReport.activeAuthentication.status == .skipped)
        #expect(transport.sentAPDUs.map(\.ins).contains(0x86))
        #expect(transport.sentAPDUs.map(\.ins).contains(0x84))
        #expect(transport.sentAPDUs.map(\.ins).contains(0x82))
    }

    #if canImport(OpenSSL)
        @Test("Passport reader completes PACE on supported NIST curves and skips BAC")
        func readPassportUsesPACEAndSkipsBAC() async throws {
            let mrzKey = "L898902C<369080619406236"
            let cardAccessData = makeCardAccessData()
            let transport = try PassportPACESuccessTransport(
                mrzKey: mrzKey,
                cardAccessData: cardAccessData
            )

            let model = try await PassportReader(transport: transport).readPassport(
                mrzKey: mrzKey,
                dataGroups: [],
                performActiveAuth: false
            )
            let instructions = transport.sentAPDUs.map(\.ins)
            let generalAuthenticateCount = instructions.filter { $0 == 0x86 }.count

            #expect(model.cardAccess?.supportsPACE == true)
            #expect(model.securityReport.cardAccess.status == .succeeded)
            #expect(model.securityReport.pace.status == .succeeded)
            #expect(model.securityReport.bac.status == .skipped)
            #expect(model.securityReport.activeAuthentication.status == .skipped)
            #expect(transport.didCompletePACE)
            #expect(generalAuthenticateCount == 4)
            #expect(!instructions.contains(0x84))
            #expect(!instructions.contains(0x82))
        }
    #endif

    private func makeCardAccessData() -> Data {
        let oid = ChipAuthenticationHandler.encodeOID(SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue)
        let oidNode = ASN1Parser.encodeTLV(tag: 0x06, value: oid)
        let versionNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x02]))
        let paramIDNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x0C]))
        let sequence = ASN1Parser.encodeTLV(tag: 0x30, value: oidNode + versionNode + paramIDNode)
        return ASN1Parser.encodeTLV(tag: 0x31, value: sequence)
    }
}

#if canImport(OpenSSL)
    private final class PassportPACESuccessTransport: NFCTagTransport, @unchecked Sendable {
        let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])

        private let cardAccessData: Data
        private let oidData = ChipAuthenticationHandler.encodeOID(SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue)
        private let passwordKey: Data
        private let encryptedNonce: Data
        private let nonce = Data([
            0x27, 0xA1, 0x4B, 0x99, 0xC0, 0xD4, 0x12, 0xFE,
            0x73, 0x4C, 0x31, 0x8A, 0x55, 0x61, 0x90, 0xAB,
        ])
        private let curve: OpenSSLPACECurve
        private let mseSetAT: CommandAPDU
        private let selectMF = CommandAPDU.selectMasterFile()
        private let selectCardAccess = CommandAPDU.selectEF(id: CardAccessParser.fileID)
        private let selectPassportApplication = CommandAPDU.selectPassportApplication()

        private var selectedFile: Data?
        private var chipMappingPrivateKey: Data?
        private var chipMappingPublicKey: Data?
        private var mappedGenerator: Data?
        private var chipEphemeralPublicKey: Data?
        private var terminalEphemeralPublicKey: Data?
        private var sessionKeys: (ksEnc: Data, ksMac: Data)?

        var sentAPDUs: [CommandAPDU] = []
        var didCompletePACE = false

        init(mrzKey: String, cardAccessData: Data) throws {
            self.cardAccessData = cardAccessData
            passwordKey = PACEHandler.derivePasswordKey(
                password: mrzKey,
                keyReference: .mrz,
                mode: .aes128
            )
            encryptedNonce = try CryptoUtils.aesEncrypt(
                key: passwordKey,
                message: nonce,
                iv: Data(count: 16)
            )
            curve = try OpenSSLPACECurve(parameterID: .secp256r1)
            mseSetAT = CommandAPDU.mseSetAT(oid: oidData, keyRef: PACEHandler.KeyReference.mrz.rawValue)
        }

        func send(_: Data) async throws -> Data {
            throw NFCError.unsupportedOperation("Raw transport is not used in passport APDU tests")
        }

        func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
            sentAPDUs.append(apdu)

            if apdu == selectMF {
                selectedFile = nil
                return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
            }

            if apdu == selectCardAccess {
                selectedFile = CardAccessParser.fileID
                return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
            }

            if apdu == selectPassportApplication {
                selectedFile = nil
                return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
            }

            if apdu == mseSetAT {
                return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
            }

            switch apdu.ins {
            case 0xB0:
                guard selectedFile == CardAccessParser.fileID else {
                    throw NFCError.invalidResponse(apdu.bytes)
                }
                return readBinaryResponse(for: apdu, file: cardAccessData)
            case 0x86:
                return try handlePACE(apdu)
            case 0x84, 0x82:
                throw NFCError.bacFailed("PACE success path should not fall back to BAC")
            default:
                throw NFCError.invalidResponse(apdu.bytes)
            }
        }

        private func readBinaryResponse(for apdu: CommandAPDU, file: Data) -> ResponseAPDU {
            let offset = (Int(apdu.p1 & 0x7F) << 8) | Int(apdu.p2)
            let requestedLength = Int(apdu.le ?? 0x00)
            guard offset <= file.count else {
                return ResponseAPDU(data: Data(), sw1: 0x6B, sw2: 0x00)
            }

            let end = min(offset + requestedLength, file.count)
            return ResponseAPDU(data: Data(file[offset ..< end]), sw1: 0x90, sw2: 0x00)
        }

        private func handlePACE(_ apdu: CommandAPDU) throws -> ResponseAPDU {
            guard let data = apdu.data else {
                throw NFCError.invalidResponse(apdu.bytes)
            }

            if data == ASN1Parser.encodeTLV(tag: 0x7C, value: Data()) {
                return dynamicAuthResponse(tag: 0x80, value: encryptedNonce)
            }

            if let terminalMappingPublicKey = try dynamicAuthValue(tag: 0x81, from: data) {
                let chipPrivateKey = try curve.generatePrivateScalar()
                let chipPublicKey = try curve.publicPoint(privateScalar: chipPrivateKey, generator: nil)
                let sharedPoint = try curve.sharedPoint(
                    privateScalar: chipPrivateKey,
                    peerPublic: terminalMappingPublicKey
                )

                chipMappingPrivateKey = chipPrivateKey
                chipMappingPublicKey = chipPublicKey
                mappedGenerator = try curve.mappedGenerator(nonce: nonce, sharedPoint: sharedPoint)
                return dynamicAuthResponse(tag: 0x82, value: chipPublicKey)
            }

            if let terminalPublicKey = try dynamicAuthValue(tag: 0x83, from: data) {
                guard let mappedGenerator else {
                    throw NFCError.secureMessagingError("PACE mapping step was not completed")
                }

                let chipPrivateKey = try curve.generatePrivateScalar()
                let chipPublicKey = try curve.publicPoint(
                    privateScalar: chipPrivateKey,
                    generator: mappedGenerator
                )
                let sharedSecret = try curve.sharedSecretXCoordinate(
                    privateScalar: chipPrivateKey,
                    peerPublic: terminalPublicKey
                )

                terminalEphemeralPublicKey = terminalPublicKey
                chipEphemeralPublicKey = chipPublicKey
                sessionKeys = PACEHandler.derivePACESessionKeys(
                    sharedSecret: sharedSecret,
                    mode: .aes128
                )
                return dynamicAuthResponse(tag: 0x84, value: chipPublicKey)
            }

            if let terminalToken = try dynamicAuthValue(tag: 0x85, from: data) {
                guard let sessionKeys,
                      let chipEphemeralPublicKey,
                      let terminalEphemeralPublicKey
                else {
                    throw NFCError.secureMessagingError("PACE key agreement state is incomplete")
                }

                let expectedTerminalToken = try PACEHandler.computeAuthToken(
                    ksMac: sessionKeys.ksMac,
                    publicKeyOther: chipEphemeralPublicKey,
                    oid: oidData,
                    mode: .aes128
                )
                guard terminalToken == expectedTerminalToken else {
                    throw NFCError.secureMessagingError("PACE terminal token did not verify")
                }

                let chipToken = try PACEHandler.computeAuthToken(
                    ksMac: sessionKeys.ksMac,
                    publicKeyOther: terminalEphemeralPublicKey,
                    oid: oidData,
                    mode: .aes128
                )
                didCompletePACE = true
                return dynamicAuthResponse(tag: 0x86, value: chipToken)
            }

            throw NFCError.invalidResponse(apdu.bytes)
        }

        private func dynamicAuthResponse(tag: UInt8, value: Data) -> ResponseAPDU {
            ResponseAPDU(
                data: ASN1Parser.encodeTLV(
                    tag: 0x7C,
                    value: ASN1Parser.encodeTLV(tag: UInt(tag), value: value)
                ),
                sw1: 0x90,
                sw2: 0x00
            )
        }

        private func dynamicAuthValue(tag: UInt, from data: Data) throws -> Data? {
            let nodes = try ASN1Parser.parseTLV(data)
            guard let wrapper = nodes.first(where: { $0.tag == 0x7C }) else {
                throw NFCError.secureMessagingError("PACE: Missing 0x7C wrapper in request")
            }
            let children = try ASN1Parser.parseTLV(wrapper.value)
            return children.first(where: { $0.tag == tag })?.value
        }
    }
#endif

private final class PassportNegotiationTransport: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])

    private let mrzKey: String
    private let rndICC = Data([0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12])
    private let kICC = Data([
        0x0B, 0x4F, 0x80, 0x32, 0x3E, 0xB3, 0x19, 0x1C,
        0xB0, 0x49, 0x70, 0xCB, 0x40, 0x52, 0x79, 0x0B,
    ])

    private var scriptedResponses: [ResponseAPDU]
    var sentAPDUs: [CommandAPDU] = []

    init(mrzKey: String, cardAccessData: Data) {
        self.mrzKey = mrzKey

        let passwordKey = PACEHandler.derivePasswordKey(
            password: mrzKey,
            keyReference: .mrz,
            mode: .aes128
        )
        let encryptedNonce = try? CryptoUtils.aesEncrypt(
            key: passwordKey,
            message: Data(repeating: 0x11, count: 16),
            iv: Data(count: 16)
        )
        let paceResponse = ResponseAPDU(
            data: ASN1Parser.encodeTLV(
                tag: 0x7C,
                value: ASN1Parser.encodeTLV(tag: 0x80, value: encryptedNonce ?? Data(repeating: 0x00, count: 16))
            ),
            sw1: 0x90,
            sw2: 0x00
        )

        scriptedResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(cardAccessData.prefix(4)), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: cardAccessData, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            paceResponse,
        ]
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw transport is not used in passport APDU tests")
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        sentAPDUs.append(apdu)

        switch apdu.ins {
        case 0x84:
            return ResponseAPDU(data: rndICC, sw1: 0x90, sw2: 0x00)
        case 0x82:
            return try mutualAuthenticateResponse(for: apdu)
        default:
            guard !scriptedResponses.isEmpty else {
                throw NFCError.tagConnectionLost
            }
            return scriptedResponses.removeFirst()
        }
    }

    private func mutualAuthenticateResponse(for apdu: CommandAPDU) throws -> ResponseAPDU {
        guard let requestData = apdu.data, requestData.count == 40 else {
            throw NFCError.invalidResponse(apdu.bytes)
        }

        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let kenc = KeyDerivation.deriveKey(keySeed: kseed, mode: .enc)
        let kmac = KeyDerivation.deriveKey(keySeed: kseed, mode: .mac)

        let encryptedRequest = Data(requestData.prefix(32))
        let requestMAC = Data(requestData.suffix(8))
        let expectedMAC = try ISO9797MAC.mac(
            key: kmac,
            message: ISO9797Padding.pad(encryptedRequest, blockSize: 8)
        )
        guard requestMAC == expectedMAC else {
            throw NFCError.bacFailed("Mock chip rejected BAC request MAC")
        }

        let decryptedRequest = try CryptoUtils.tripleDESDecrypt(key: kenc, message: encryptedRequest)
        let rndIFD = Data(decryptedRequest[0 ..< 8])
        let rndICCPrime = Data(decryptedRequest[8 ..< 16])
        guard rndICCPrime == rndICC else {
            throw NFCError.bacFailed("Mock chip rejected rndICC")
        }

        var responsePayload = Data()
        responsePayload.append(rndICC)
        responsePayload.append(rndIFD)
        responsePayload.append(kICC)

        let encryptedResponse = try CryptoUtils.tripleDESEncrypt(key: kenc, message: responsePayload)
        let responseMAC = try ISO9797MAC.mac(
            key: kmac,
            message: ISO9797Padding.pad(encryptedResponse, blockSize: 8)
        )
        return ResponseAPDU(data: encryptedResponse + responseMAC, sw1: 0x90, sw2: 0x00)
    }
}
