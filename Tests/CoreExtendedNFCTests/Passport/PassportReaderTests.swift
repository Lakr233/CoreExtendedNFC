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
    @Test
    func `CardAccess parser extracts advertised PACE info`() throws {
        let cardAccessData = makeCardAccessData()

        let result = try CardAccessParser.parse(cardAccessData)

        #expect(result.supportsPACE)
        #expect(result.paceInfos.count == 1)
        #expect(result.paceInfos[0].protocolOID == SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue)
        #expect(result.paceInfos[0].parameterID == 12)
    }

    @Test
    func `Passport reader falls back to BAC when advertised PACE cannot complete`() async throws {
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

        // ICAO 9303-11 §4.2: PACE (step 3) runs before the eMRTD Application is selected,
        // and "The eMRTD Application MUST be selected before Basic Access Control is
        // performed" (step 4). After a failed PACE the application is selected in plain,
        // after the last PACE command and before GET CHALLENGE.
        let apdus = transport.sentAPDUs
        let selectApplication = try #require(apdus.lastIndex(of: .selectPassportApplication()))
        let firstPACE = try #require(apdus.firstIndex { $0.ins == 0x22 })
        let lastPACE = try #require(apdus.lastIndex { $0.ins == 0x86 })
        let getChallenge = try #require(apdus.firstIndex { $0.ins == 0x84 })
        #expect(!apdus[..<firstPACE].contains { $0.ins == 0xA4 && $0.p1 == 0x04 }, "no SELECT by DF name before PACE")
        #expect(lastPACE < selectApplication && selectApplication < getChallenge)
    }

    #if canImport(OpenSSL)
        @Test
        func `Passport reader runs PACE with the first supported PACEInfo when an earlier one is unsupported`() async throws {
            let mrzKey = "L898902C<369080619406236"
            let scenario = PACEReaderScenario.supportedNISTCurves[0]
            let cardAccessData = makeCardAccessData(
                securityProtocol: scenario.securityProtocol,
                parameterID: scenario.parameterID,
                precedingInfos: [(.paceECDHIMAESCBCCMAC128, .secp256r1), (.paceECDHGMAESCBCCMAC128, .secp192r1)]
            )
            let transport = try PassportPACESuccessTransport(
                mrzKey: mrzKey,
                scenario: scenario,
                cardAccessData: cardAccessData,
                files: [DataGroupId.com.fileID: makeCOMData()]
            )

            let model = try await PassportReader(transport: transport).readPassport(
                mrzKey: mrzKey,
                dataGroups: [.com],
                performActiveAuth: false
            )

            #expect(model.cardAccess?.paceInfos.count == 3)
            #expect(model.securityReport.pace.status == .succeeded)
            #expect(model.securityReport.bac.status == .skipped)
            #expect(transport.didCompletePACE)
            #expect(transport.sentAPDUs.filter { $0.ins == 0x22 }.count == 1)
        }

        @Test
        func `Passport reader completes PACE, reads COM over secure messaging, and skips BAC on supported NIST curves`() async throws {
            let mrzKey = "L898902C<369080619406236"
            let comData = makeCOMData()

            for scenario in PACEReaderScenario.supportedNISTCurves + PACEReaderScenario.supportedBrainpoolCurves {
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
                let generalAuthenticateCount = instructions.count(where: { $0 == 0x86 })

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

        /// ICAO Doc 9303-11 (8th ed.) §4.2 Chip Access Procedure: read EF.CardAccess
        /// (step 1), then PACE (step 3); BAC (step 4) is skipped after PACE, and only BAC
        /// requires the eMRTD Application to be selected first. "As a result of the Chip
        /// Access Procedure, the Current DF can be either the Master File (if PACE was
        /// used) or the eMRTD Application (if BAC was used)." Appendix K step 1: "Perform
        /// the Chip Access Procedure (see Section 4.2) and select the eMRTD Application".
        /// PACE "SHALL restrict access rights to require Secure Messaging" (§4.2 step 3),
        /// so the SELECT that follows PACE is protected (§9.8: CLA b3-b4 set, DO'87, DO'8E).
        @Test
        func `Passport reader runs PACE at the Master File, then selects the eMRTD application under secure messaging`() async throws {
            let mrzKey = "L898902C<369080619406236"
            let scenario = PACEReaderScenario.supportedNISTCurves[0]
            let transport = try PassportPACESuccessTransport(
                mrzKey: mrzKey,
                scenario: scenario,
                cardAccessData: makeCardAccessData(
                    securityProtocol: scenario.securityProtocol,
                    parameterID: scenario.parameterID
                ),
                files: [DataGroupId.com.fileID: makeCOMData()]
            )

            let model = try await PassportReader(transport: transport).readPassport(
                mrzKey: mrzKey,
                dataGroups: [.com],
                performActiveAuth: false
            )

            #expect(model.securityReport.pace.status == .succeeded)
            #expect(model.rawDataGroups[.com] == makeCOMData())

            let apdus = transport.sentAPDUs
            let firstPACE = try #require(apdus.firstIndex { $0.ins == 0x22 })
            let lastPACE = try #require(apdus.lastIndex { $0.ins == 0x86 })
            // Before PACE the only selections are the MF and EF.CardAccess.
            #expect(Array(apdus[..<firstPACE].filter { $0.ins == 0xA4 }) == [
                .selectMasterFile(), .selectEF(id: CardAccessParser.fileID),
            ])
            #expect(!apdus.contains(.selectPassportApplication()), "the application is never selected in plain")

            // The first command after PACE selects the eMRTD application under SM.
            let selectApplication = try #require(apdus.indices.first { $0 > lastPACE })
            let protectedSelect = apdus[selectApplication]
            #expect(protectedSelect.cla == 0x0C)
            #expect(protectedSelect.ins == 0xA4 && protectedSelect.p1 == 0x04 && protectedSelect.p2 == 0x0C)
            let objects = try ASN1Parser.parseTLV(try #require(protectedSelect.data))
            #expect(objects.map(\.tag) == [0x87, 0x8E], "P2=0C has no Le, so there is no DO'97")
            #expect(transport.unprotectedCommands.first == .selectPassportApplication())
            // The SELECT reply carried only DO'99 and DO'8E and was accepted.
            #expect(transport.unprotectedCommands.dropFirst().first == .selectEF(id: DataGroupId.com.fileID))
        }
    #endif

    private func makeCardAccessData(
        securityProtocol: SecurityProtocol = .paceECDHGMAESCBCCMAC128,
        parameterID: PACEHandler.DomainParameterID = .secp256r1,
        precedingInfos: [(SecurityProtocol, PACEHandler.DomainParameterID)] = []
    ) -> Data {
        func paceInfo(_ securityProtocol: SecurityProtocol, _ parameterID: PACEHandler.DomainParameterID) -> Data {
            let oid = ChipAuthenticationHandler.encodeOID(securityProtocol.rawValue)
            let oidNode = ASN1Parser.encodeTLV(tag: 0x06, value: oid)
            let versionNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([0x02]))
            let paramIDNode = ASN1Parser.encodeTLV(tag: 0x02, value: Data([UInt8(parameterID.rawValue)]))
            return ASN1Parser.encodeTLV(tag: 0x30, value: oidNode + versionNode + paramIDNode)
        }
        let preceding = precedingInfos.reduce(into: Data()) { $0 += paceInfo($1.0, $1.1) }
        return ASN1Parser.encodeTLV(tag: 0x31, value: preceding + paceInfo(securityProtocol, parameterID))
    }

    @Test
    func `Passport reader skips PACE without any PACE APDU when no advertised parameters are supported`() async throws {
        let mrzKey = "L898902C<369080619406236"
        // Integrated Mapping on P-256: advertised, but not implemented.
        let cardAccessData = makeCardAccessData(securityProtocol: .paceECDHIMAESCBCCMAC128)
        let transport = PassportNegotiationTransport(mrzKey: mrzKey, cardAccessData: cardAccessData)

        let model = try await PassportReader(transport: transport).readPassport(
            mrzKey: mrzKey,
            dataGroups: [],
            performActiveAuth: false
        )

        #expect(model.cardAccess?.supportsPACE == true)
        #expect(model.securityReport.pace.status == .fallback)
        #expect(model.securityReport.bac.status == .succeeded)
        let instructions = transport.sentAPDUs.map(\.ins)
        #expect(!instructions.contains(0x22), "MSE:Set AT must not be sent for unsupported PACE parameters")
        #expect(!instructions.contains(0x86), "General Authenticate must not be sent for unsupported PACE parameters")
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
    private struct PACEReaderScenario {
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

        static let supportedBrainpoolCurves: [PACEReaderScenario] = [
            .init(
                name: "PACE AES-128 / brainpoolP256r1",
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                parameterID: .brainpoolP256r1
            ),
            .init(
                name: "PACE AES-192 / brainpoolP320r1",
                securityProtocol: .paceECDHGMAESCBCCMAC192,
                parameterID: .brainpoolP320r1
            ),
            .init(
                name: "PACE AES-256 / brainpoolP512r1",
                securityProtocol: .paceECDHGMAESCBCCMAC256,
                parameterID: .brainpoolP512r1
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
        /// Protected commands as the chip decrypted them, in order.
        var unprotectedCommands: [CommandAPDU] = []
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
            // The simulated chip derives keys with the independent reference KDF, not the
            // production functions under test (ICAO 9303-11 §9.7.3: K_π from full SHA-1).
            passwordKey = ReferencePACECrypto.kdf(
                seed: ReferencePACECrypto.sha1(Data(mrzKey.utf8)),
                counter: 3,
                mode: smMode
            )
            encryptedNonce = try CryptoUtils.aesEncrypt(
                key: passwordKey,
                message: nonce,
                iv: Data(count: 16)
            )
            curve = try OpenSSLPACECurve(parameterID: scenario.parameterID)
            // Tag 84 names the standardized domain parameter ID (ICAO 9303-11 §4.4.4.1).
            mseSetAT = CommandAPDU.mseSetAT(
                oid: oidData,
                keyRef: PACEHandler.KeyReference.mrz.rawValue,
                privateKeyRef: UInt8(scenario.parameterID.rawValue)
            )
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
                sessionKeys = (
                    ReferencePACECrypto.kdf(seed: sharedSecret, counter: 1, mode: smMode),
                    ReferencePACECrypto.kdf(seed: sharedSecret, counter: 2, mode: smMode)
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

                let expectedTerminalToken = try ReferencePACECrypto.authToken(
                    ksMac: sessionKeys.ksMac,
                    publicKey: chipEphemeralPublicKey,
                    oid: oidData
                )
                guard terminalToken == expectedTerminalToken else {
                    throw NFCError.secureMessagingError("PACE terminal token did not verify")
                }

                let chipToken = try ReferencePACECrypto.authToken(
                    ksMac: sessionKeys.ksMac,
                    publicKey: terminalEphemeralPublicKey,
                    oid: oidData
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
            unprotectedCommands.append(plainAPDU)

            let plainResponse: ResponseAPDU
            switch plainAPDU.ins {
            case 0xA4 where plainAPDU.p1 == 0x04:
                selectedFile = nil
                plainResponse = ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
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

        let passwordKey = ReferencePACECrypto.kdf(
            seed: ReferencePACECrypto.sha1(Data(mrzKey.utf8)),
            counter: 3,
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

        // SELECT commands are answered in `sendAPDU`, so this script does not depend on
        // where the reader selects the eMRTD application.
        scriptedResponses = [
            ResponseAPDU(data: Data(cardAccessData.prefix(4)), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: cardAccessData, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // MSE:Set AT
            paceResponse,
        ]
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw transport is not used in passport APDU tests")
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        sentAPDUs.append(apdu)

        switch apdu.ins {
        case 0xA4:
            return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
        case 0x84:
            return ResponseAPDU(data: rndICC, sw1: 0x90, sw2: 0x00)
        case 0x82:
            return try mutualAuthenticateResponse(for: apdu)
        default:
            guard !scriptedResponses.isEmpty else {
                // The chip rejects the rest of PACE (6A80 wrong data). A lost tag would
                // end the whole read instead of falling back to BAC.
                return ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x80)
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
