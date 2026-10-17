// eMRTD conformance tests against official test vectors.
//
// ## References
// - ICAO Doc 9303 Part 11, Appendix D: BAC worked example (D.2–D.4 secure messaging)
// - ICAO Doc 9303 Part 11, Appendix G.1: PACE ECDH-GM AES-128 worked example
// - ICAO Doc 9303 Part 11, §6.2 / BSI TR-03110-3 B.11: Chip Authentication APDUs
// - ICAO Doc 9303 Part 11, §9.8: Secure messaging (DO'8E mandatory; DO'99 optional in §9.8.4,
//   required by this library so the status word is authenticated)
// - ISO/IEC 7816-4 §10.2 (SM data objects), §11.3.3 (READ BINARY odd INS)
// - X.690 §8.19 (OBJECT IDENTIFIER encoding)
// - BSI TR-03110-3 Appendix A (Terminal Authentication OIDs)
// AES secure messaging vectors were computed independently with the OpenSSL CLI
// (`openssl enc`, `openssl mac CMAC`) from the Appendix G.1 session keys.
@testable import CoreExtendedNFC
import Foundation
#if canImport(OpenSSL)
    import OpenSSL
#endif
import Testing

struct PassportConformanceTests {
    // MARK: - ICAO 9303-11 Appendix D (BAC)

    private static let appendixDMRZKey = "L898902C<369080619406236"
    private static let appendixDKSEnc = vectorHex("979EC13B1CBFE9DCD01AB0FED307EAE5")
    private static let appendixDKSMac = vectorHex("F1CB1F1FB5ADF208806B89DC579DC1F8")
    private static let appendixDSSC = vectorHex("887022120C06C226")

    @Test
    func `BAC sends E_IFD and M_IFD from ICAO 9303-11 Appendix D and derives D.3 session keys`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("4608F91988702212"), sw1: 0x90, sw2: 0x00),
            // Appendix D.3: E_ICC || M_ICC
            ResponseAPDU(
                data: vectorHex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449"),
                sw1: 0x90,
                sw2: 0x00
            ),
            // Appendix D.4: protected SELECT EF.COM response
            ResponseAPDU(data: vectorHex("990290008E08FA855A5D4C50A8ED"), sw1: 0x90, sw2: 0x00),
        ]

        let sm = try await BACHandler.performBAC(
            mrzKey: Self.appendixDMRZKey,
            transport: mock,
            rndIFD: vectorHex("781723860C06C226"),
            kIFD: vectorHex("0B795240CB7049B01C19B33E32804F0B")
        )

        #expect(mock.sentAPDUs[1].data == vectorHex(
            "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2" + "5F1448EEA8AD90A7"
        ))

        // KSenc/KSmac/SSC from D.3 are proven by the D.4 protected SELECT bytes.
        let response = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        #expect(response.isSuccess)
        #expect(mock.sentAPDUs[2].data == vectorHex("8709016375432908C044F68E08BF8B92D635FF24F8"))
    }

    @Test
    func `BAC rejects caller-supplied kIFD and rndIFD of the wrong length`() async {
        let mock = MockTransport()
        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(
                mrzKey: Self.appendixDMRZKey,
                transport: mock,
                rndIFD: vectorHex("781723860C06C226"),
                kIFD: Data(count: 15)
            )
        }
        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(
                mrzKey: Self.appendixDMRZKey,
                transport: mock,
                rndIFD: Data(count: 7)
            )
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `SM matches ICAO 9303-11 Appendix D.4 SELECT and READ BINARY`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("990290008E08FA855A5D4C50A8ED"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: vectorHex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED"), sw1: 0x90, sw2: 0x00),
        ]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        let select = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        #expect(select.isSuccess)
        #expect(mock.sentAPDUs[0].bytes == vectorHex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"))

        let read = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        #expect(mock.sentAPDUs[1].bytes == vectorHex("0CB000000D9701048E08ED6705417E96BA5500"))
        #expect(read.isSuccess)
        #expect(read.data == vectorHex("60145F01"))
    }

    @Test
    func `SM matches ICAO 9303-11 Appendix D.4 step 3 READ BINARY of the remaining 18 bytes`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("990290008E08FA855A5D4C50A8ED"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: vectorHex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED"), sw1: 0x90, sw2: 0x00),
            // Appendix D.4 step 3: RAPDU = DO'87 || DO'99 || DO'8E, SW 9000 (SSC ...C22C).
            ResponseAPDU(
                data: vectorHex(
                    "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A"
                        + "990290008E08C8B2787EAEA07D74"
                ),
                sw1: 0x90,
                sw2: 0x00
            ),
        ]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        _ = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        _ = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        // READ BINARY offset 4, Le 18 (SSC ...C22B).
        let read = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x04, le: 0x12))

        #expect(mock.sentAPDUs[2].bytes == vectorHex("0CB000040D9701128E082EA28A70F3C7B53500"))
        #expect(read.isSuccess)
        #expect(read.data == vectorHex("04303130365F36063034303030305C026175"))
    }

    @Test
    func `SM uses extended Le 0000 when the protected command needs extended length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        // 240 plain bytes protect to DO'87 (252) + DO'97 (3) + DO'8E (10) = 265 bytes,
        // so the protected APDU is extended although Ne is only 256.
        _ = try? await sm.sendAPDU(CommandAPDU(
            cla: 0x00, ins: 0xD6, p1: 0x00, p2: 0x00, data: Data(repeating: 0x5A, count: 240), le: 0x00
        ))

        let sent = try #require(mock.sentAPDUs.first)
        #expect(sent.data?.count == 265)
        #expect(sent.isExtendedLength)
        #expect(sent.expectedResponseLength == CommandAPDU.maxExpectedResponseLength)
        // ICAO 9303-11 §9.8 Figure 5: extended Le is 0000, not the plain Ne (0100).
        #expect(sent.bytes.suffix(2) == Data([0x00, 0x00]))
        #expect(sent.bytes.prefix(7) == vectorHex("0CD60000000109"))
    }

    @Test
    func `AES SM accepts a 16-byte block-sized SSC and matches the 8-byte form`() async throws {
        let response = ResponseAPDU(data: vectorHex("990290008E08BEA7B381C494A079"), sw1: 0x90, sw2: 0x00)
        var sentBySSCLength: [Int: Data] = [:]
        for ssc in [Data(count: 8), Data(count: 16)] {
            let mock = MockTransport()
            mock.apduResponses = [response]
            let sm = SecureMessagingTransport(
                transport: mock,
                ksEnc: vectorHex("F5F0E35C0D7161EE6724EE513A0D9A7F"),
                ksMac: vectorHex("FE251C7858B356B24514B3BD5F4297D1"),
                ssc: ssc,
                mode: .aes128
            )
            let select = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
            #expect(select.isSuccess)
            sentBySSCLength[ssc.count] = mock.sentAPDUs.first?.data
        }
        #expect(sentBySSCLength[16] == vectorHex("871101EE0E4724F4465C1BE9C2F73ABDD73A3D8E08835D1B54575C955F"))
        #expect(sentBySSCLength[8] == sentBySSCLength[16])
    }

    @Test
    func `SM refuses an SSC of the wrong length without sending anything`() async {
        let cases: [(SMEncryptionMode, Int)] = [(.tripleDES, 16), (.tripleDES, 4), (.aes128, 12), (.aes256, 0)]
        for (mode, length) in cases {
            let mock = MockTransport()
            let sm = SecureMessagingTransport(
                transport: mock,
                ksEnc: Data(count: mode == .tripleDES ? 16 : 32),
                ksMac: Data(count: mode == .tripleDES ? 16 : 32),
                ssc: Data(count: length),
                mode: mode
            )
            do {
                _ = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
                Issue.record("Expected invalidParameter for \(mode) with a \(length)-byte SSC")
            } catch NFCError.invalidParameter {
                // expected
            } catch {
                Issue.record("Unexpected error \(error)")
            }
            #expect(mock.sentAPDUs.isEmpty)
        }
    }

    @Test
    func `SM rejects a response without DO'8E`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: vectorHex("99029000"), sw1: 0x90, sw2: 0x00)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        await #expect(throws: NFCError.self) {
            _ = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        }
    }

    @Test
    func `SM rejects data appended after DO'8E`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: vectorHex("990290008E08FA855A5D4C50A8ED870101"), sw1: 0x90, sw2: 0x00)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        await #expect(throws: NFCError.self) {
            _ = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        }
    }

    @Test
    func `SM verifies the MAC over DO'87 as received with a non-minimal length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("878109019FF0EC34F9922651990290008E080F1391B519930FF6"), sw1: 0x90, sw2: 0x00),
        ]
        // SSC before the READ BINARY of Appendix D.4 (two exchanges after D.3).
        let sm = makeAppendixDTransport(mock, ssc: vectorHex("887022120C06C228"))

        let read = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        #expect(read.data == vectorHex("60145F01"))
    }

    @Test
    func `SM rejects authenticated plaintext without ISO 9797-1 padding`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("870901B0C26754EBC13E75990290008E082A8ECC20314373A8"), sw1: 0x90, sw2: 0x00),
        ]
        let sm = makeAppendixDTransport(mock, ssc: vectorHex("887022120C06C228"))

        await #expect(throws: NFCError.self) {
            _ = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        }
    }

    @Test
    func `SM surfaces a plain error status word from the chip`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        do {
            _ = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
            Issue.record("Expected a thrown error")
        } catch let NFCError.unexpectedStatusWord(sw1, sw2) {
            #expect(sw1 == 0x6A && sw2 == 0x82)
        } catch {
            Issue.record("Unexpected error \(error)")
        }
    }

    @Test
    func `SM accepts an SSC passed as a Data slice`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: vectorHex("990290008E08FA855A5D4C50A8ED"), sw1: 0x90, sw2: 0x00)]
        let buffer = vectorHex("FFFF") + Self.appendixDSSC + vectorHex("FFFF")
        let sm = makeAppendixDTransport(mock, ssc: buffer[2 ..< 10])

        let response = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        #expect(response.isSuccess)
    }

    @Test
    func `SM uses DO'85 without padding indicator for odd INS`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x88)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        _ = try? await sm.sendAPDU(CommandAPDU(
            cla: 0x00, ins: 0xB1, p1: 0x00, p2: 0x00, data: vectorHex("54028000"), le: 0xA3
        ))
        let sent = try #require(mock.sentAPDUs.first?.data)
        // 85 08 <8-byte cryptogram> 97 01 A3 8E 08 <MAC>
        #expect(sent.first == 0x85)
        #expect(sent[sent.startIndex + 1] == 0x08)
        let expectedCount = 23 // DO'85 (2 + 8) + DO'97 (3) + DO'8E (10)
        #expect(sent.count == expectedCount)
    }

    // MARK: - AES secure messaging (Appendix G.1 keys, OpenSSL-computed vectors)

    @Test
    func `AES-128 SM protects and unprotects SELECT and READ BINARY`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: vectorHex("990290008E08BEA7B381C494A079"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(
                data: vectorHex("871101645C0B1F998A088278D07942BBE94B60990290008E0894A33C6AA2D8CCC8"),
                sw1: 0x90,
                sw2: 0x00
            ),
        ]
        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: vectorHex("F5F0E35C0D7161EE6724EE513A0D9A7F"),
            ksMac: vectorHex("FE251C7858B356B24514B3BD5F4297D1"),
            ssc: Data(count: 8),
            mode: .aes128
        )

        let select = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        #expect(select.isSuccess)
        #expect(mock.sentAPDUs[0].data == vectorHex("871101EE0E4724F4465C1BE9C2F73ABDD73A3D8E08835D1B54575C955F"))

        let read = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        #expect(mock.sentAPDUs[1].data == vectorHex("9701048E08AA6BA54F44DF8364"))
        #expect(read.data == vectorHex("60145F01"))
    }

    // MARK: - ICAO 9303-11 Appendix G.1 (PACE ECDH-GM AES-128)

    @Test
    func `PACE K_pi matches ICAO 9303-11 Appendix G.1`() throws {
        let kpi = try PACEHandler.derivePasswordKey(
            password: "T22000129364081251010318",
            keyReference: .mrz,
            mode: .aes128
        )
        #expect(kpi == vectorHex("89DED1B26624EC1E634C1989302849DD"))

        let nonce = try CryptoUtils.aesDecrypt(
            key: kpi,
            message: vectorHex("95A3A016522EE98D01E76CB6B98B42C3"),
            iv: Data(count: 16)
        )
        #expect(nonce == vectorHex("3F00C4D39D153F2B2A214A078D899B22"))
    }

    @Test
    func `PACE session keys and AES token match ICAO 9303-11 Appendix G.1`() throws {
        let keys = PACEHandler.derivePACESessionKeys(
            sharedSecret: vectorHex("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
            mode: .aes128
        )
        #expect(keys.ksEnc == vectorHex("F5F0E35C0D7161EE6724EE513A0D9A7F"))
        #expect(keys.ksMac == vectorHex("FE251C7858B356B24514B3BD5F4297D1"))

        let pkIC = vectorHex(
            "049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB"
                + "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094"
        )
        let token = try PACEHandler.computeAuthToken(
            ksMac: keys.ksMac,
            publicKeyOther: pkIC,
            oid: vectorHex("04007F00070202040202"),
            mode: .aes128
        )
        #expect(token == vectorHex("C2B0BD78D94BA866"))
    }

    @Test
    func `PACE rejects a CAN that is not ISO-8859-1 without touching the chip`() async {
        let mock = MockTransport()
        let info = PACEInfo(
            protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
            securityProtocol: .paceECDHGMAESCBCCMAC128,
            version: 2,
            parameterID: 12
        )

        await #expect(throws: NFCError.self) {
            _ = try await PACEHandler.performPACE(paceInfo: info, can: "１２３４５６", transport: mock)
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    #if canImport(OpenSSL)
        @Test
        func `PACE runs ICAO 9303-11 Appendix G.1 end to end on brainpoolP256r1`() async throws {
            // The chip side is the published G.1 APDU trace; the terminal uses the G.1
            // private keys so every command it sends is fixed.
            let pkMapIC = vectorHex(
                "04824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57"
                    + "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"
            )
            let pkIC = vectorHex(
                "049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB"
                    + "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094"
            )
            let mock = MockTransport()
            mock.apduResponses = [
                ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: vectorHex("7C12801095A3A016522EE98D01E76CB6B98B42C3"), sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: vectorHex("7C438241") + pkMapIC, sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: vectorHex("7C438441") + pkIC, sw1: 0x90, sw2: 0x00),
                ResponseAPDU(data: vectorHex("7C0A86083ABB9674BCE93C08"), sw1: 0x90, sw2: 0x00),
                // AES-128 SELECT EF.COM response under the G.1 session keys (see the AES SM test).
                ResponseAPDU(data: vectorHex("990290008E08BEA7B381C494A079"), sw1: 0x90, sw2: 0x00),
            ]
            let info = PACEInfo(
                protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                version: 2,
                parameterID: PACEHandler.DomainParameterID.brainpoolP256r1.rawValue
            )

            let sm = try await PACEHandler.performPACE(
                paceInfo: info,
                password: "T22000129364081251010318",
                keyReference: .mrz,
                transport: mock,
                mappingPrivateKey: vectorHex("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99"),
                ephemeralPrivateKey: vectorHex("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595")
            )

            let sent = mock.sentAPDUs.map(\.bytes)
            // G.1 MSE:Set AT, plus tag 84 naming standardized domain parameter 13.
            #expect(sent[0] == vectorHex("0022C1A412800A04007F00070202040202830101" + "84010D"))
            #expect(sent[1] == vectorHex("10860000027C0000"))
            #expect(sent[2] == vectorHex(
                "10860000457C438141"
                    + "047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E"
                    + "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D00"
            ))
            #expect(sent[3] == vectorHex(
                "10860000457C438341"
                    + "042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C"
                    + "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB3646200"
            ))
            #expect(sent[4] == vectorHex("008600000C7C0A8508C2B0BD78D94BA86600"))

            // The returned transport runs AES-128 SM with KSenc/KSmac from G.1 and SSC 0.
            #expect(sm.mode == .aes128)
            let select = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
            #expect(select.isSuccess)
            #expect(mock.sentAPDUs[5].data == vectorHex("871101EE0E4724F4465C1BE9C2F73ABDD73A3D8E08835D1B54575C955F"))
        }

        @Test
        func `PACE refuses a supplied private key outside the curve order before any APDU`() async {
            let mock = MockTransport()
            let info = PACEInfo(
                protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                version: 2,
                parameterID: 12
            )
            await #expect(throws: NFCError.self) {
                _ = try await PACEHandler.performPACE(
                    paceInfo: info,
                    password: "T22000129364081251010318",
                    keyReference: .mrz,
                    transport: mock,
                    mappingPrivateKey: Data(count: 32)
                )
            }
            #expect(mock.sentAPDUs.isEmpty)
        }
    #endif

    @Test
    func `PACE rejects unsupported parameters before sending any APDU`() async {
        let unsupported: [PACEInfo] = [
            // Integrated Mapping
            PACEInfo(
                protocolOID: SecurityProtocol.paceECDHIMAESCBCCMAC128.rawValue,
                securityProtocol: .paceECDHIMAESCBCCMAC128,
                version: 2,
                parameterID: 12
            ),
            // DH Generic Mapping
            PACEInfo(
                protocolOID: SecurityProtocol.paceDHGMAESCBCCMAC128.rawValue,
                securityProtocol: .paceDHGMAESCBCCMAC128,
                version: 2,
                parameterID: 0
            ),
            // secp192r1
            PACEInfo(
                protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                version: 2,
                parameterID: 8
            ),
            // Proprietary domain parameters
            PACEInfo(
                protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC128.rawValue,
                securityProtocol: .paceECDHGMAESCBCCMAC128,
                version: 2,
                parameterID: 32
            ),
            // Unknown OID
            PACEInfo(protocolOID: "0.4.0.127.0.7.2.2.4.6.2", securityProtocol: nil, version: 2, parameterID: 13),
        ]
        for info in unsupported {
            let mock = MockTransport()
            #expect(!PACEHandler.isSupported(info))
            do {
                _ = try await PACEHandler.performPACE(paceInfo: info, mrzKey: "T22000129364081251010318", transport: mock)
                Issue.record("Expected unsupportedOperation for \(info)")
            } catch NFCError.unsupportedOperation {
                // expected
            } catch {
                Issue.record("Unexpected error \(error)")
            }
            #expect(mock.sentAPDUs.isEmpty, "\(info.protocolOID) / \(String(describing: info.parameterID))")
        }
    }

    @Test
    func `PACE selects the first supported PACEInfo from EF.CardAccess`() {
        let integrated = PACEInfo(
            protocolOID: SecurityProtocol.paceECDHIMAESCBCCMAC128.rawValue,
            securityProtocol: .paceECDHIMAESCBCCMAC128,
            version: 2,
            parameterID: 12
        )
        let generic = PACEInfo(
            protocolOID: SecurityProtocol.paceECDHGMAESCBCCMAC256.rawValue,
            securityProtocol: .paceECDHGMAESCBCCMAC256,
            version: 2,
            parameterID: 16
        )
        let infos = SecurityInfos(
            paceInfos: [integrated, generic],
            chipAuthInfos: [],
            chipAuthPublicKeyInfos: [],
            activeAuthInfos: []
        )
        #expect(PACEHandler.selectPACEInfo(from: infos) == generic)

        let none = SecurityInfos(paceInfos: [integrated], chipAuthInfos: [], chipAuthPublicKeyInfos: [], activeAuthInfos: [])
        #expect(PACEHandler.selectPACEInfo(from: none) == nil)
    }

    // MARK: - Chip Authentication

    @Test
    func `CA KDF equals the ICAO 9303-11 KDF for AES-128 (Appendix G.1 K)`() {
        let keys = ChipAuthenticationHandler.deriveCASessionKeys(
            sharedSecret: vectorHex("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
            mode: .aes128
        )
        #expect(keys.ksEnc == vectorHex("F5F0E35C0D7161EE6724EE513A0D9A7F"))
        #expect(keys.ksMac == vectorHex("FE251C7858B356B24514B3BD5F4297D1"))
    }

    @Test
    func `CA KDF for 3DES uses SHA-1 with DES parity (Appendix D.3 keys)`() {
        // Appendix D.3: K_seed = K.IFD xor K.ICC; KSenc/KSmac use the same 3DES KDF.
        let keys = ChipAuthenticationHandler.deriveCASessionKeys(
            sharedSecret: vectorHex("0036D272F5C350ACAC50C3F572D23600"),
            mode: .tripleDES
        )
        #expect(keys.ksEnc == vectorHex("979EC13B1CBFE9DCD01AB0FED307EAE5"))
        #expect(keys.ksMac == vectorHex("F1CB1F1FB5ADF208806B89DC579DC1F8"))
    }

    @Test
    func `CA MSE Set AT uses P1 0x41 and does not send an empty General Authenticate`() async {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x88)]
        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: Data(count: 16),
            ksMac: Data(count: 16),
            ssc: Data(count: 8)
        )
        let infos = SecurityInfos(
            paceInfos: [],
            chipAuthInfos: [ChipAuthenticationInfo(
                protocolOID: SecurityProtocol.caECDHAESCBCCMAC128.rawValue,
                securityProtocol: .caECDHAESCBCCMAC128,
                version: 1,
                keyID: nil
            )],
            chipAuthPublicKeyInfos: [ChipAuthenticationPublicKeyInfo(
                protocolOID: SecurityProtocol.pkECDH.rawValue,
                subjectPublicKey: Data([0x30, 0x00]),
                keyID: nil
            )],
            activeAuthInfos: []
        )

        _ = try? await ChipAuthenticationHandler.performCA(securityInfos: infos, transport: sm)

        #expect(mock.sentAPDUs.count == 1)
        #expect(mock.sentAPDUs.first?.p1 == 0x41)
        #expect(mock.sentAPDUs.first?.p2 == 0xA4)
    }

    @Test
    func `CA APDU builders follow ICAO 9303-11 section 6_2`() {
        let oid = vectorHex("04007F00070202030202")
        let mse = ChipAuthenticationHandler.mseSetATForCA(oid: oid, keyID: 0x0102)
        #expect(mse.bytes == vectorHex("002241A410" + "800A04007F00070202030202" + "84020102"))

        let kat = ChipAuthenticationHandler.mseSetKATForCA(ephemeralPublicKey: vectorHex("04AABB"), keyID: 1)
        #expect(kat.bytes == vectorHex("002241A608" + "910304AABB" + "840101"))

        let ga = ChipAuthenticationHandler.generalAuthenticateForCA(ephemeralPublicKey: vectorHex("04AABB"))
        #expect(ga.bytes == vectorHex("0086000007" + "7C05800304AABB" + "00"))
    }

    // MARK: - OIDs

    @Test
    func `OID decoding follows X.690 first-arc rules`() {
        #expect(DG14Parser.decodeOID(Data([0x78])) == "2.40")
        #expect(DG14Parser.decodeOID(Data([0x88, 0x37, 0x03])) == "2.999.3")
        #expect(DG14Parser.decodeOID(Data([0x2A, 0x86])) == "")
    }

    @Test
    func `OID encoding handles large first arcs without trapping`() {
        #expect(ChipAuthenticationHandler.encodeOID("2.999.3") == Data([0x88, 0x37, 0x03]))
        #expect(ChipAuthenticationHandler.encodeOID("2.40") == Data([0x78]))
        #expect(ChipAuthenticationHandler.encodeOID("3.1").isEmpty)
        #expect(ChipAuthenticationHandler.encodeOID("1.40").isEmpty)
    }

    @Test
    func `Terminal Authentication ECDSA OIDs match BSI TR-03110-3`() {
        #expect(SecurityProtocol(rawValue: "0.4.0.127.0.7.2.2.2.2.2") == .taECDSASHA224)
        #expect(SecurityProtocol(rawValue: "0.4.0.127.0.7.2.2.2.2.3") == .taECDSASHA256)
    }

    // MARK: - Passive Authentication

    @Test
    func `Empty hash results are not valid`() {
        let result = PassiveAuthenticationResult(
            dataGroupHashResults: [:],
            hasCertificate: false,
            status: .unsupportedHashAlgorithm
        )
        #expect(!result.allHashesValid)
    }

    @Test
    func `A data group read but absent from the SOD fails passive authentication`() {
        let dg1 = Data([0x61, 0x00])
        // SHA-256("\x61\x00")
        let sod = SODContent(
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            hashAlgorithm: "SHA-256",
            dataGroupHashes: [.dg1: vectorHex("FFE9AAEAA2A2D5048174DF0B80599EF0197EC024C4B051BC9860CFF58EF7F9F3")],
            ldsVersion: nil,
            unicodeVersion: nil,
            documentSignerCertificate: nil,
            signedAttributes: nil,
            signature: nil,
            signatureAlgorithmOID: nil,
            encapsulatedContent: nil
        )
        let result = SODParser.verifyHashes(
            sodContent: sod,
            rawDataGroups: [.dg1: dg1, .dg11: Data([0x6B, 0x00]), .com: Data([0x60, 0x00])]
        )
        #expect(result.dataGroupHashResults[.dg11] == false)
        #expect(result.dataGroupHashResults[.com] == nil)
        #expect(!result.allHashesValid)
    }

    @Test
    func `LDS security object hash algorithm without NULL parameters wins over digestAlgorithms`() throws {
        let sha1AlgId = vectorTLV(0x30, vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("1.3.14.3.2.26")) + vectorHex("0500"))
        let sha256AlgIdNoParams = vectorTLV(0x30, vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("2.16.840.1.101.3.4.2.1")))
        let dgHash = vectorTLV(0x30, vectorTLV(0x02, Data([0x01])) + vectorTLV(0x04, Data(repeating: 0xAB, count: 32)))
        let ldsSecurityObject = vectorTLV(0x30, vectorTLV(0x02, Data([0x00])) + sha256AlgIdNoParams + vectorTLV(0x30, dgHash))
        let encapContentInfo = vectorTLV(
            0x30,
            vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("2.23.136.1.1.1")) + vectorTLV(0xA0, vectorTLV(0x04, ldsSecurityObject))
        )
        let signedData = vectorTLV(0x30, vectorTLV(0x02, Data([0x03])) + vectorTLV(0x31, sha1AlgId) + encapContentInfo)
        let contentInfo = vectorTLV(
            0x30,
            vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("1.2.840.113549.1.7.2")) + vectorTLV(0xA0, signedData)
        )

        let sod = try SODParser.parse(vectorTLV(0x77, contentInfo))
        #expect(sod.hashAlgorithm == "SHA-256")
        #expect(sod.hashAlgorithmOID == "2.16.840.1.101.3.4.2.1")
    }

    // MARK: - Data group parsing robustness

    @Test
    func `DG2 with an empty biometric data object throws instead of trapping`() {
        #expect(throws: NFCError.self) {
            _ = try DataGroupParser.parseDG2(Data([0x75, 0x03, 0x5F, 0x2E, 0x00]))
        }
    }

    @Test
    func `DG2 with a one-byte biometric data object does not trap`() throws {
        let image = try DataGroupParser.parseDG2(Data([0x75, 0x04, 0x5F, 0x2E, 0x01, 0xFF]))
        #expect(image == Data([0xFF]))
    }

    @Test
    func `ISO 9797-1 unpad handles sliced Data`() throws {
        let buffer = Data([0xEE, 0x01, 0x02, 0x80, 0x00, 0xEE])
        #expect(ISO9797Padding.unpad(buffer[1 ..< 5]) == Data([0x01, 0x02]))
        #expect(try ISO9797Padding.strictUnpad(Data([0x01, 0x02, 0x80, 0x00]), blockSize: 4) == Data([0x01, 0x02]))
        #expect(throws: NFCError.self) {
            _ = try ISO9797Padding.strictUnpad(Data([0x01, 0x02, 0x03, 0x04]), blockSize: 4)
        }
    }

    // MARK: - MRZ

    @Test
    func `MRZ key keeps long TD1 document numbers and uppercases input`() {
        let key = MRZKeyGenerator.computeMRZKey(
            documentNumber: "D23145890734",
            dateOfBirth: "740812",
            dateOfExpiry: "120415"
        )
        // ICAO 9303-3 check digit of "D23145890734" (weights 7,3,1): 9.
        #expect(key == "D231458907349" + "7408122" + "1204159")
        #expect(MRZKeyGenerator.computeMRZKey(documentNumber: "l898902c", dateOfBirth: "690806", dateOfExpiry: "940623")
            == Self.appendixDMRZKey)
    }

    @Test
    func `MRZ check digit only accepts ASCII digits as digits`() {
        // Full-width "１" is not a valid MRZ character and is valued like a filler.
        #expect(MRZKeyGenerator.checkDigit("１") == "0")
        #expect(MRZKeyGenerator.checkDigit("a") == MRZKeyGenerator.checkDigit("A"))
    }

    // MARK: - Extended length under secure messaging

    @Test
    func `SM encodes extended Ne as a two-byte DO'97 and extended outer Le`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x88)]
        let sm = makeAppendixDTransport(mock, ssc: Self.appendixDSSC)

        _ = try? await sm.sendAPDU(CommandAPDU(
            cla: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: vectorHex("0123456789ABCDEF"),
            expectedResponseLength: 512
        ))
        let sent = try #require(mock.sentAPDUs.first)
        let objects = try ASN1Parser.parseTLV(try #require(sent.data))
        #expect(objects.first { $0.tag == 0x97 }?.value == vectorHex("0200"))
        #expect(sent.expectedResponseLength == 65536)
    }

    // MARK: - Active Authentication expected length

    /// The protected INTERNAL AUTHENTICATE that Active Authentication sends for
    /// `publicKey` over a secure messaging session in `mode`.
    private func sentInternalAuthenticate(
        publicKey: ActiveAuthenticationPublicKey,
        mode: SMEncryptionMode
    ) async throws -> CommandAPDU {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x80)]
        let sm = mode == .tripleDES
            ? makeAppendixDTransport(mock, ssc: Self.appendixDSSC)
            : SecureMessagingTransport(
                transport: mock,
                ksEnc: Data(repeating: 0x11, count: 16),
                ksMac: Data(repeating: 0x22, count: 16),
                ssc: Data(count: 16),
                mode: mode
            )
        _ = try? await PassportReader(transport: mock).performActiveAuthentication(
            publicKey: publicKey,
            subjectPublicKeyInfo: nil,
            securityInfos: nil,
            transport: sm
        )
        return try #require(mock.sentAPDUs.first)
    }

    private static func rsaKey(bits: Int) -> ActiveAuthenticationPublicKey {
        .rsa(modulus: Data([0xC1]) + Data(repeating: 0x5A, count: bits / 8 - 1), exponent: vectorHex("010001"))
    }

    /// ISO/IEC 7816-4 §5.1: a short Le field encodes Ne of at most 256 bytes. ICAO
    /// 9303-11 §6.1.4 Note: "when using key lengths exceeding 1 848 bits (if Secure
    /// Messaging with 3DES is used) / 1 792 bits (if Secure Messaging with AES is used)
    /// in Active Authentication with Secure Messaging, Extended Length APDUs MUST be
    /// supported by the eMRTD chip and the Inspection System." The protected reply of a
    /// k-byte signature is DO'87 (01 || padded cryptogram) + DO'99 (4) + DO'8E (10) bytes,
    /// which exceeds 256 above those key lengths. Extended length under SM is DO'97 '00 00'
    /// and outer Le '00 00' (ICAO 9303-11 §9.8, Figure 5).
    ///
    /// RSA-1792 with AES is listed on purpose: its 224-byte signature pads to 240 bytes,
    /// a 258-byte protected reply, so it cannot use a short Le even though the Note only
    /// names keys exceeding 1 792 bits.
    @Test(arguments: [
        (3072, SMEncryptionMode.tripleDES), (3072, .aes128),
        (2048, .tripleDES), (2048, .aes128), (2048, .aes256),
        (1856, .tripleDES), (1856, .aes128), (1792, .aes128),
    ])
    func `AA asks for an extended response when the DG15 RSA signature does not fit a short protected reply`(
        bits: Int,
        mode: SMEncryptionMode
    ) async throws {
        let sent = try await sentInternalAuthenticate(publicKey: Self.rsaKey(bits: bits), mode: mode)
        #expect(sent.ins == 0x88)
        let objects = try ASN1Parser.parseTLV(try #require(sent.data))
        #expect(objects.first { $0.tag == 0x97 }?.value == vectorHex("0000"), "RSA-\(bits) \(mode): DO'97 must be extended")
        #expect(sent.expectedResponseLength == 65536, "RSA-\(bits) \(mode): outer Le must be extended '00 00'")
        #expect(sent.isExtendedLength)
    }

    /// Keys whose protected reply fits 256 bytes keep the short Le '00' (ICAO 9303-11
    /// §6.1.4 Note: up to 1 848 bits with 3DES; ECDSA signatures are 2 x field size).
    @Test(arguments: [
        (1024, SMEncryptionMode.tripleDES), (1024, .aes128), (1536, .aes128),
        (1848, .tripleDES), (1784, .aes128),
    ])
    func `AA keeps the short Le when the DG15 RSA signature fits a short protected reply`(
        bits: Int,
        mode: SMEncryptionMode
    ) async throws {
        let sent = try await sentInternalAuthenticate(publicKey: Self.rsaKey(bits: bits), mode: mode)
        let objects = try ASN1Parser.parseTLV(try #require(sent.data))
        #expect(objects.first { $0.tag == 0x97 }?.value == vectorHex("00"), "RSA-\(bits) \(mode)")
        #expect(sent.expectedResponseLength == 256, "RSA-\(bits) \(mode)")
    }

    @Test
    func `AA keeps the short Le for ECDSA DG15 keys`() async throws {
        // P-521: uncompressed point 04 || X || Y of 133 bytes, plain signature r || s of 132 bytes.
        let p521 = ActiveAuthenticationPublicKey.ecdsa(
            curveOID: "1.3.132.0.35",
            publicPoint: Data([0x04]) + Data(repeating: 0x01, count: 132)
        )
        let sent = try await sentInternalAuthenticate(publicKey: p521, mode: .aes256)
        let objects = try ASN1Parser.parseTLV(try #require(sent.data))
        #expect(objects.first { $0.tag == 0x97 }?.value == vectorHex("00"))
        #expect(sent.expectedResponseLength == 256)
    }

    @Test
    func `INTERNAL AUTHENTICATE encodes an extended Le as 00 Lc1 Lc2 data Le1 Le2`() {
        // ISO/IEC 7816-4 §5.1: extended Lc '00 00 08', extended Le '00 00' = 65 536.
        let challenge = vectorHex("0123456789ABCDEF")
        #expect(CommandAPDU.internalAuthenticate(data: challenge, expectedResponseLength: 65536).bytes
            == vectorHex("00880000000008") + challenge + vectorHex("0000"))
        #expect(CommandAPDU.internalAuthenticate(data: challenge).bytes == vectorHex("0088000008") + challenge + vectorHex("00"))
    }

    // MARK: - Active Authentication with explicit EC parameters

    #if canImport(OpenSSL)
        @Test
        func `ECDSA AA verifies a DG15 key with explicit P-256 domain parameters`() throws {
            let (privateKey, publicPoint) = try makeP256Key()
            defer { EVP_PKEY_free(privateKey) }

            let challenge = vectorHex("0123456789ABCDEF")
            let signature = try signPlainSHA256(challenge, privateKey: privateKey)

            // SPKI with explicit ECParameters (RFC 3279 §2.3.5), P-256 constants from SEC 2.
            let fieldID = vectorTLV(0x30, vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("1.2.840.10045.1.1"))
                + vectorTLV(0x02, vectorHex("00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")))
            let curve = vectorTLV(0x30, vectorTLV(0x04, vectorHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"))
                + vectorTLV(0x04, vectorHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")))
            let generator = vectorTLV(0x04, vectorHex(
                "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                    + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            ))
            let order = vectorTLV(0x02, vectorHex("00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"))
            let ecParameters = vectorTLV(0x30, vectorTLV(0x02, Data([0x01])) + fieldID + curve + generator + order + vectorTLV(0x02, Data([0x01])))
            let algorithm = vectorTLV(0x30, vectorTLV(0x06, ChipAuthenticationHandler.encodeOID("1.2.840.10045.2.1")) + ecParameters)
            let spki = vectorTLV(0x30, algorithm + vectorTLV(0x03, Data([0x00]) + publicPoint))
            let dg15 = vectorTLV(0x6F, spki)

            let parsedKey = try DG15Parser.parse(dg15)
            let securityInfos = SecurityInfos(
                paceInfos: [],
                chipAuthInfos: [],
                chipAuthPublicKeyInfos: [],
                activeAuthInfos: [ActiveAuthenticationInfo(
                    protocolOID: SecurityProtocol.aaRSA.rawValue,
                    securityProtocol: .aaRSA,
                    version: 1,
                    signatureAlgorithmOID: "0.4.0.127.0.7.1.1.4.1.3"
                )]
            )

            #expect(DG15Parser.subjectPublicKeyInfo(dg15) == spki)
            let result = ActiveAuthenticationVerifier.verify(
                challenge: challenge,
                signature: signature,
                publicKey: parsedKey,
                subjectPublicKeyInfo: DG15Parser.subjectPublicKeyInfo(dg15),
                securityInfos: securityInfos
            )
            #expect(result.status == .verified)

            // Without the SPKI the key cannot be rebuilt: report unsupported, not a forgery.
            let withoutSPKI = ActiveAuthenticationVerifier.verify(
                challenge: challenge,
                signature: signature,
                publicKey: parsedKey,
                securityInfos: securityInfos
            )
            #expect(withoutSPKI.status == .unsupportedKeyType)
        }

        private func makeP256Key() throws -> (OpaquePointer, Data) {
            guard let context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil) else {
                throw NFCError.cryptoError("EVP_PKEY_CTX_new_id failed")
            }
            defer { EVP_PKEY_CTX_free(context) }
            var generated: OpaquePointer?
            guard EVP_PKEY_keygen_init(context) == 1,
                  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1,
                  EVP_PKEY_keygen(context, &generated) == 1,
                  let key = generated
            else {
                throw NFCError.cryptoError("P-256 key generation failed")
            }
            var length = 0
            guard EVP_PKEY_get_octet_string_param(key, "pub", nil, 0, &length) == 1 else {
                EVP_PKEY_free(key)
                throw NFCError.cryptoError("public key length query failed")
            }
            var point = Data(count: length)
            let status = point.withUnsafeMutableBytes { buffer in
                EVP_PKEY_get_octet_string_param(
                    key, "pub", buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), length, &length
                )
            }
            guard status == 1 else {
                EVP_PKEY_free(key)
                throw NFCError.cryptoError("public key export failed")
            }
            return (key, point.prefix(length))
        }

        private func signPlainSHA256(_ message: Data, privateKey: OpaquePointer) throws -> Data {
            guard let context = EVP_MD_CTX_new() else { throw NFCError.cryptoError("EVP_MD_CTX_new failed") }
            defer { EVP_MD_CTX_free(context) }
            guard EVP_DigestSignInit(context, nil, EVP_sha256(), nil, privateKey) == 1 else {
                throw NFCError.cryptoError("EVP_DigestSignInit failed")
            }
            var length = 0
            let input = [UInt8](message)
            guard EVP_DigestSign(context, nil, &length, input, input.count) == 1 else {
                throw NFCError.cryptoError("signature length query failed")
            }
            var der = [UInt8](repeating: 0, count: length)
            guard EVP_DigestSign(context, &der, &length, input, input.count) == 1 else {
                throw NFCError.cryptoError("EVP_DigestSign failed")
            }
            let sequence = try #require(ASN1Parser.parseTLV(Data(der.prefix(length))).first)
            let parts = try sequence.children()
            return fixedWidth(parts[0].value, 32) + fixedWidth(parts[1].value, 32)
        }

        private func fixedWidth(_ value: Data, _ width: Int) -> Data {
            let trimmed = Data(value.drop(while: { $0 == 0x00 }))
            return Data(repeating: 0x00, count: max(0, width - trimmed.count)) + trimmed
        }
    #endif

    // MARK: - Helpers

    private func makeAppendixDTransport(_ mock: MockTransport, ssc: Data) -> SecureMessagingTransport {
        SecureMessagingTransport(
            transport: mock,
            ksEnc: Self.appendixDKSEnc,
            ksMac: Self.appendixDKSMac,
            ssc: ssc
        )
    }
}

func vectorTLV(_ tag: UInt, _ value: Data) -> Data {
    ASN1Parser.encodeTLV(tag: tag, value: value)
}

func vectorHex(_ string: String) -> Data {
    let digits = string.filter { !$0.isWhitespace }
    var data = Data()
    var index = digits.startIndex
    while index < digits.endIndex {
        let next = digits.index(index, offsetBy: 2)
        data.append(UInt8(digits[index ..< next], radix: 16)!)
        index = next
    }
    return data
}
