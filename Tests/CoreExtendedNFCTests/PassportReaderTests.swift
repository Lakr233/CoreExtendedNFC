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
        @Test("Passport reader completes PACE, reads COM over secure messaging, and skips BAC on supported NIST curves")
        func readPassportUsesPACEAndSecureMessaging() async throws {
            let mrzKey = "L898902C<369080619406236"
            let comData = makeCOMData()

            for scenario in PACEReaderScenario.supportedNISTCurves {
                let cardAccessData = makeCardAccessData(
                    securityProtocol: scenario.securityProtocol,
                    parameterID: scenario.parameterID
                )
                let transport = try PassportPACESuccessTransport(
                    mrzKey: mrzKey,
                    scenario: scenario,
                    cardAccessData: cardAccessData,
                    files: [
                        DataGroupId.com.fileID: comData,
                    ]
                )

                let model = try await PassportReader(transport: transport).readPassport(
                    mrzKey: mrzKey,
                    dataGroups: [.com],
                    performActiveAuth: false
                )
                let instructions = transport.sentAPDUs.map(\.ins)
                let generalAuthenticateCount = instructions.filter { $0 == 0x86 }.count

                #expect(model.cardAccess?.supportsPACE == true, "\(scenario.name): CardAccess should advertise PACE")
                #expect(model.securityReport.cardAccess.status == .succeeded, "\(scenario.name): CardAccess should succeed")
                #expect(model.securityReport.pace.status == .succeeded, "\(scenario.name): PACE should succeed")
                #expect(model.securityReport.bac.status == .skipped, "\(scenario.name): BAC should be skipped")
                #expect(model.securityReport.activeAuthentication.status == .skipped, "\(scenario.name): AA should be skipped")
                #expect(model.ldsVersion == "0107", "\(scenario.name): COM should be parsed over secure messaging")
                #expect(model.unicodeVersion == "040000", "\(scenario.name): COM should expose Unicode version")
                #expect(model.availableDataGroups == [.dg1, .dg2], "\(scenario.name): COM DG list should round-trip")
                #expect(model.rawDataGroups[.com] == comData, "\(scenario.name): COM bytes should be read through the protected channel")
                #expect(transport.didCompletePACE, "\(scenario.name): mock chip should complete PACE")
                #expect(transport.didUseSecureMessaging, "\(scenario.name): reader should use derived secure messaging")
                #expect(transport.didReadProtectedFile, "\(scenario.name): protected READ BINARY should execute")
                #expect(transport.protectedAPDUs.count >= 3, "\(scenario.name): secure SELECT + READs should be sent")
                #expect(transport.protectedAPDUs.allSatisfy { $0.cla == 0x0C }, "\(scenario.name): secure APDUs should use masked CLA")
                #expect(generalAuthenticateCount == 4, "\(scenario.name): PACE should use the four General Authenticate exchanges")
                #expect(!instructions.contains(0x84), "\(scenario.name): BAC GET CHALLENGE should not be used")
                #expect(!instructions.contains(0x82), "\(scenario.name): BAC MUTUAL AUTHENTICATE should not be used")
            }
        }
    #endif

    private func makeCardAccessData(
        securityProtocol: SecurityProtocol = .paceECDHGMAESCBCCMAC128,
        parameterID: PACEHandler.DomainParameterID = .secp256r1
    ) -> Data {
        let oid = ChipAuthenticationHandler.encodeOID(securityProtocol.rawValue)
        let oidNode = ASN1Parser.encodeTLV(tag: 0x06, value: oid)
        let versionNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x02]))
        let paramIDNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([UInt8(parameterID.rawValue)]))
        let sequence = ASN1Parser.encodeTLV(tag: 0x30, value: oidNode + versionNode + paramIDNode)
        return ASN1Parser.encodeTLV(tag: 0x31, value: sequence)
    }

    private func makeCOMData() -> Data {
        let ldsVersion = Data("0107".utf8)
        var ldsNode = Data([0x5F, 0x01, UInt8(ldsVersion.count)])
        ldsNode.append(ldsVersion)

        let unicodeVersion = Data("040000".utf8)
        var unicodeNode = Data([0x5F, 0x36, UInt8(unicodeVersion.count)])
        unicodeNode.append(unicodeVersion)

        let dgList = Data([0x61, 0x75])
        var dgNode = Data([0x5C, UInt8(dgList.count)])
        dgNode.append(dgList)

        let content = ldsNode + unicodeNode + dgNode
        return ASN1Parser.encodeTLV(tag: 0x60, value: content)
    }
}

#if canImport(OpenSSL)
    private struct PACEReaderScenario: Sendable {
        let name: String
        let securityProtocol: SecurityProtocol
        let parameterID: PACEHandler.DomainParameterID

        var mode: SMEncryptionMode {
            switch securityProtocol.aesKeyLength {
            case 16: .aes128
            case 24: .aes192
            case 32: .aes256
            default: .tripleDES
            }
        }

        static let supportedNISTCurves: [PACEReaderScenario] = [
            .init(
                name: "PACE AES-128 / secp256r1",
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                parameterID: .secp256r1
            ),
            .init(
                name: "PACE AES-192 / secp384r1",
                securityProtocol: .paceECDHGMAESCBCCMAC192,
                parameterID: .secp384r1
            ),
            .init(
                name: "PACE AES-256 / secp521r1",
                securityProtocol: .paceECDHGMAESCBCCMAC256,
                parameterID: .secp521r1
            ),
        ]
    }

    private final class PassportPACESuccessTransport: NFCTagTransport, @unchecked Sendable {
        let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])

        private let cardAccessData: Data
        private let files: [Data: Data]
        private let oidData: Data
        private let passwordKey: Data
        private let encryptedNonce: Data
        private let nonce = Data([
            0x27, 0xA1, 0x4B, 0x99, 0xC0, 0xD4, 0x12, 0xFE,
            0x73, 0x4C, 0x31, 0x8A, 0x55, 0x61, 0x90, 0xAB,
        ])
        private let curve: OpenSSLPACECurve
        private let smMode: SMEncryptionMode
        private let mseSetAT: CommandAPDU
        private let selectMF = CommandAPDU.selectMasterFile()
        private let selectCardAccess = CommandAPDU.selectEF(id: CardAccessParser.fileID)
        private let selectPassportApplication = CommandAPDU.selectPassportApplication()

        private var selectedFile: Data?
        private var mappedGenerator: Data?
        private var chipEphemeralPublicKey: Data?
        private var terminalEphemeralPublicKey: Data?
        private var sessionKeys: (ksEnc: Data, ksMac: Data)?
        private var secureMessagingSSC = Data(count: 8)

        var sentAPDUs: [CommandAPDU] = []
        var protectedAPDUs: [CommandAPDU] = []
        var didCompletePACE = false
        var didUseSecureMessaging = false
        var didReadProtectedFile = false

        init(
            mrzKey: String,
            scenario: PACEReaderScenario,
            cardAccessData: Data,
            files: [Data: Data]
        ) throws {
            self.cardAccessData = cardAccessData
            self.files = files
            oidData = ChipAuthenticationHandler.encodeOID(scenario.securityProtocol.rawValue)
            smMode = scenario.mode
            passwordKey = PACEHandler.derivePasswordKey(
                password: mrzKey,
                keyReference: .mrz,
                mode: smMode
            )
            encryptedNonce = try CryptoUtils.aesEncrypt(
                key: passwordKey,
                message: nonce,
                iv: Data(count: 16)
            )
            curve = try OpenSSLPACECurve(parameterID: scenario.parameterID)
            mseSetAT = CommandAPDU.mseSetAT(oid: oidData, keyRef: PACEHandler.KeyReference.mrz.rawValue)
        }

        func send(_: Data) async throws -> Data {
            throw NFCError.unsupportedOperation("Raw transport is not used in passport APDU tests")
        }

        func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
            sentAPDUs.append(apdu)

            if apdu.cla & 0x0C == 0x0C {
                protectedAPDUs.append(apdu)
                return try handleSecureMessaging(apdu)
            }

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
                return readBinaryResponse(for: apdu)
            case 0x86:
                return try handlePACE(apdu)
            case 0x84, 0x82:
                throw NFCError.bacFailed("PACE success path should not fall back to BAC")
            default:
                throw NFCError.invalidResponse(apdu.bytes)
            }
        }

        private func readBinaryResponse(for apdu: CommandAPDU) -> ResponseAPDU {
            guard let selectedFile else {
                return ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
            }
            let file: Data
            if selectedFile == CardAccessParser.fileID {
                file = cardAccessData
            } else if let storedFile = files[selectedFile] {
                file = storedFile
            } else {
                return ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
            }

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
                    mode: smMode
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
                    mode: smMode
                )
                guard terminalToken == expectedTerminalToken else {
                    throw NFCError.secureMessagingError("PACE terminal token did not verify")
                }

                let chipToken = try PACEHandler.computeAuthToken(
                    ksMac: sessionKeys.ksMac,
                    publicKeyOther: terminalEphemeralPublicKey,
                    oid: oidData,
                    mode: smMode
                )
                didCompletePACE = true
                secureMessagingSSC = Data(count: 8)
                return dynamicAuthResponse(tag: 0x86, value: chipToken)
            }

            throw NFCError.invalidResponse(apdu.bytes)
        }

        private func handleSecureMessaging(_ apdu: CommandAPDU) throws -> ResponseAPDU {
            guard let sessionKeys else {
                throw NFCError.secureMessagingError("PACE must complete before secure messaging starts")
            }

            didUseSecureMessaging = true
            incrementSecureMessagingSSC()
            let plainAPDU = try unprotectSecureMessagingCommand(apdu, sessionKeys: sessionKeys)

            let plainResponse: ResponseAPDU
            switch plainAPDU.ins {
            case 0xA4:
                selectedFile = plainAPDU.data
                plainResponse = ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
            case 0xB0:
                didReadProtectedFile = true
                plainResponse = readBinaryResponse(for: plainAPDU)
            default:
                throw NFCError.invalidResponse(plainAPDU.bytes)
            }

            incrementSecureMessagingSSC()
            return try protectSecureMessagingResponse(plainResponse, sessionKeys: sessionKeys)
        }

        private func unprotectSecureMessagingCommand(
            _ apdu: CommandAPDU,
            sessionKeys: (ksEnc: Data, ksMac: Data)
        ) throws -> CommandAPDU {
            guard let protectedData = apdu.data else {
                throw NFCError.secureMessagingError("Protected APDU is missing data objects")
            }

            let nodes = try ASN1Parser.parseTLV(protectedData)
            let do87Value: Data = nodes.first(where: { $0.tag == 0x87 }).map(\.value) ?? Data()
            let do97Value: Data = nodes.first(where: { $0.tag == 0x97 }).map(\.value) ?? Data()
            guard let do8eValue: Data = nodes.first(where: { $0.tag == 0x8E }).map(\.value) else {
                throw NFCError.secureMessagingError("Protected APDU is missing DO'8E")
            }

            let commandHeader = ISO9797Padding.pad(
                Data([apdu.cla, apdu.ins, apdu.p1, apdu.p2]),
                blockSize: 16
            )
            var macInput = paddedSSC()
            macInput.append(commandHeader)
            if !do87Value.isEmpty {
                macInput.append(0x87)
                macInput.append(contentsOf: ASN1Parser.encodeLength(do87Value.count))
                macInput.append(do87Value)
            }
            if !do97Value.isEmpty {
                macInput.append(0x97)
                macInput.append(contentsOf: ASN1Parser.encodeLength(do97Value.count))
                macInput.append(do97Value)
            }

            let expectedMAC = try secureMessagingMAC(
                key: sessionKeys.ksMac,
                message: ISO9797Padding.pad(macInput, blockSize: 16)
            )
            guard expectedMAC == do8eValue else {
                throw NFCError.secureMessagingError("Protected APDU MAC verification failed")
            }

            var plaintext = Data()
            if !do87Value.isEmpty {
                guard do87Value.count > 1, do87Value[0] == 0x01 else {
                    throw NFCError.secureMessagingError("Protected APDU has invalid DO'87")
                }

                let encrypted = Data(do87Value.dropFirst())
                let iv = try secureMessagingIV(key: sessionKeys.ksEnc)
                let decrypted = try CryptoUtils.aesDecrypt(
                    key: sessionKeys.ksEnc,
                    message: encrypted,
                    iv: iv
                )
                plaintext = ISO9797Padding.unpad(decrypted)
            }

            let le = do97Value.isEmpty ? nil : do97Value[do97Value.startIndex]
            return CommandAPDU(
                cla: apdu.cla & 0xF3,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                data: plaintext.isEmpty ? nil : plaintext,
                le: le
            )
        }

        private func protectSecureMessagingResponse(
            _ response: ResponseAPDU,
            sessionKeys: (ksEnc: Data, ksMac: Data)
        ) throws -> ResponseAPDU {
            var do87 = Data()
            if !response.data.isEmpty {
                let iv = try secureMessagingIV(key: sessionKeys.ksEnc)
                let encrypted = try CryptoUtils.aesEncrypt(
                    key: sessionKeys.ksEnc,
                    message: ISO9797Padding.pad(response.data, blockSize: 16),
                    iv: iv
                )
                let do87Value = Data([0x01]) + encrypted
                do87.append(0x87)
                do87.append(contentsOf: ASN1Parser.encodeLength(do87Value.count))
                do87.append(do87Value)
            }

            let do99Value = Data([response.sw1, response.sw2])
            var macInput = paddedSSC()
            if !do87.isEmpty {
                macInput.append(do87)
            }
            macInput.append(0x99)
            macInput.append(0x02)
            macInput.append(do99Value)

            let mac = try secureMessagingMAC(
                key: sessionKeys.ksMac,
                message: ISO9797Padding.pad(macInput, blockSize: 16)
            )

            var protectedResponse = Data()
            if !do87.isEmpty {
                protectedResponse.append(do87)
            }
            protectedResponse.append(0x99)
            protectedResponse.append(0x02)
            protectedResponse.append(do99Value)
            protectedResponse.append(0x8E)
            protectedResponse.append(0x08)
            protectedResponse.append(mac)

            return ResponseAPDU(data: protectedResponse, sw1: 0x90, sw2: 0x00)
        }

        private func secureMessagingMAC(key: Data, message: Data) throws -> Data {
            switch smMode {
            case .aes128, .aes192, .aes256:
                let fullMAC = try AESCMAC.mac(key: key, message: message)
                return Data(fullMAC.prefix(8))
            case .tripleDES:
                return try ISO9797MAC.mac(key: key, message: message)
            }
        }

        private func secureMessagingIV(key: Data) throws -> Data {
            try CryptoUtils.aesECBEncrypt(key: key, message: paddedSSC())
        }

        private func paddedSSC() -> Data {
            Data(repeating: 0x00, count: 8) + secureMessagingSSC
        }

        private func incrementSecureMessagingSSC() {
            var carry: UInt16 = 1
            for index in stride(from: secureMessagingSSC.count - 1, through: 0, by: -1) {
                let sum = UInt16(secureMessagingSSC[index]) + carry
                secureMessagingSSC[index] = UInt8(sum & 0xFF)
                carry = sum >> 8
                if carry == 0 {
                    break
                }
            }
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
