// MIFARE DESFire authentication regression tests.
//
// Provenance:
// - proxmark3 `client/src/mifare/desfiresecurechan.c`,
//   `DesfireSecureChannelDecodeEV1`: "if comm mode = plain --> response with
//   MAC" — after AuthenticateISO the PICC appends an 8-byte CMAC to plain
//   responses, on the last frame of an AF-chained answer.
// - proxmark3 `client/src/mifare/desfirecrypto.c` `DesfireGenSessionKeyEV1`
//   and `desfirecore.c` `DesfireAuthenticate`: 2K3DES session key
//   `RndA[0..3] ‖ RndB[0..3] ‖ RndA[4..7] ‖ RndB[4..7]`; when the two key
//   halves are equal (single DES) the second half repeats the first.
//   proxmark3 `desfiretest.c` has no EV1 session-key vector, so the expected
//   keys below follow that rule byte for byte.
// - NXP AN12343 §10.1 / AN12196: AuthenticateEV2First Part 1 is
//   `KeyNo ‖ LenCap ‖ PCDcap2`; the Part 2 answer is
//   E(Kx, TI ‖ RndA' ‖ PDcap2 ‖ PCDcap2) = 32 bytes.
// - proxmark3 `client/src/cmdhfmfdes.c` `getCardType`: HW major 0x43 on
//   hardware type 0x81 is EV3; DESFire Light (0x08 / 0x30) and DUOX (0xA0)
//   are separate products.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DESFireAuthenticationTests {
    // MARK: - EV1 response MAC after AuthenticateISO

    @Test
    func `AuthenticateISO read strips the CMAC from the last chained frame`() async throws {
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let mac = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        let mock = try Self.isoMock(key: key)
        mock.apduResponses += [
            ResponseAPDU(data: Data([0x01, 0x02, 0x03]), sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: Data([0x04, 0x05]) + mac, sw1: 0x91, sw2: 0x00),
        ]

        let result = try await DESFireCommands(transport: mock).readDataAuthenticatedISO(
            fileID: 0x01,
            keyNo: 0x00,
            key: key,
            offset: 0,
            length: 0,
            rndA: Self.rndA
        )

        #expect(result.data == Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        #expect(mock.sentAPDUs.map(\.ins) == [0x1A, 0xAF, 0xBD, 0xAF])
    }

    @Test
    func `AuthenticateISO MAC-only answer yields empty data`() async throws {
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let mock = try Self.isoMock(key: key)
        mock.apduResponses.append(
            ResponseAPDU(data: Data(repeating: 0xEE, count: 8), sw1: 0x91, sw2: 0x00)
        )

        let result = try await DESFireCommands(transport: mock).readRecordsAuthenticatedISO(
            fileID: 0x02,
            keyNo: 0x00,
            key: key,
            offset: 0,
            count: 0,
            rndA: Self.rndA
        )
        #expect(result.data.isEmpty)
    }

    @Test
    func `AuthenticateISO read rejects a response shorter than the CMAC`() async throws {
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let mock = try Self.isoMock(key: key)
        mock.apduResponses.append(
            ResponseAPDU(data: Data([0xCA, 0xFE, 0xF0, 0x0D]), sw1: 0x91, sw2: 0x00)
        )

        await #expect(throws: NFCError.invalidResponse(Data([0xCA, 0xFE, 0xF0, 0x0D]))) {
            _ = try await DESFireCommands(transport: mock).readDataAuthenticatedISO(
                fileID: 0x01,
                keyNo: 0x00,
                key: key,
                offset: 0,
                length: 4,
                rndA: Self.rndA
            )
        }
    }

    @Test
    func `AuthenticateISO GET_VALUE decodes a MAC-suffixed 12-byte answer`() async throws {
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let mock = try Self.isoMock(key: key)
        mock.apduResponses.append(
            ResponseAPDU(
                data: Data([0xFE, 0xFF, 0xFF, 0xFF]) + Data(repeating: 0x5A, count: 8),
                sw1: 0x91,
                sw2: 0x00
            )
        )

        let result = try await DESFireCommands(transport: mock).getValueAuthenticatedISO(
            fileID: 0x03,
            keyNo: 0x00,
            key: key,
            rndA: Self.rndA
        )
        #expect(result.value == -2)
    }

    // MARK: - Single-DES session key

    @Test
    func `AuthenticateISO with the all-zero factory key yields a single-DES session key`() async throws {
        let key = Data(count: 16)
        let mock = try Self.isoMock(key: key)

        let session = try await DESFireCommands(transport: mock).authenticateISO(
            keyNo: 0x00,
            key: key,
            rndA: Self.rndA
        )

        // RndA[0..3] ‖ RndB[0..3], repeated in both halves.
        let expected = try #require(Data(hexString: "01020304112233440102030411223344"))
        #expect(session.sessionENCKey == expected)
        #expect(session.sessionMACKey == expected)
    }

    @Test
    func `ISO session key repeats the first half only when the key halves match`() throws {
        let rndB = Self.rndB
        let singleDES = try #require(Data(hexString: "0123456789ABCDEF0123456789ABCDEF"))
        #expect(
            try DESFireCommands.deriveISOSessionKey(key: singleDES, rndA: Self.rndA, rndB: rndB)
                == Data(hexString: "01020304112233440102030411223344")
        )
        let twoKey = try #require(Data(hexString: "0123456789ABCDEFFEDCBA9876543210"))
        #expect(
            try DESFireCommands.deriveISOSessionKey(key: twoKey, rndA: Self.rndA, rndB: rndB)
                == Data(hexString: "01020304112233440506070855667788")
        )
        // Slices with a non-zero start index derive the same key.
        let padded = Data([0xFF]) + singleDES
        #expect(
            try DESFireCommands.deriveISOSessionKey(key: padded.dropFirst(), rndA: Self.rndA, rndB: rndB)
                == Data(hexString: "01020304112233440102030411223344")
        )
    }

    @Test
    func `ISO session key derivation rejects short challenges and wrong key sizes`() {
        let key = Data(count: 16)
        let rnd8 = Data(repeating: 0x11, count: 8)
        let cases: [(Data, Data, Data)] = [
            (key, Data([0x01]), rnd8),
            (key, rnd8, Data([0x02])),
            (key, Data(), Data()),
            (Data(count: 8), rnd8, rnd8),
            (Data(count: 24), rnd8, rnd8),
            (Data(), rnd8, rnd8),
        ]
        for (key, rndA, rndB) in cases {
            do {
                _ = try DESFireCommands.deriveISOSessionKey(key: key, rndA: rndA, rndB: rndB)
                Issue.record("expected invalidParameter for key \(key.count), rndA \(rndA.count), rndB \(rndB.count)")
            } catch NFCError.invalidParameter {
            } catch {
                Issue.record("unexpected error \(error)")
            }
        }
    }

    // MARK: - AuthenticateEV2First framing

    @Test
    func `AuthenticateEV2First Part 1 sends LenCap and PCDcap2`() async throws {
        let mock = MockTransport()
        mock.apduResponses = Self.an12196EV2FirstResponses
        // PCDCap2.1 bit 1 (LRP) clear: this is the AES EV2 transcript.
        let pcdCap2 = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        let session = try await DESFireCommands(transport: mock).authenticateEV2First(
            keyNo: 0x03,
            key: Data(count: 16),
            pcdCapabilities: pcdCap2,
            rndA: Self.an12196RndA
        )

        #expect(mock.sentAPDUs[0].ins == 0x71)
        #expect(mock.sentAPDUs[0].data == Data([0x03, 0x06]) + pcdCap2)
        // The capabilities in the session are the ones the PICC echoed back.
        #expect(session.pcdCapabilities == Data(count: 6))
    }

    @Test
    func `AuthenticateEV2First default sends LenCap zero`() async throws {
        let mock = MockTransport()
        mock.apduResponses = Self.an12196EV2FirstResponses

        _ = try await DESFireCommands(transport: mock).authenticateEV2First(
            keyNo: 0x00,
            key: Data(count: 16),
            pcdCapabilities: Data(),
            rndA: Self.an12196RndA
        )
        #expect(mock.sentAPDUs[0].data == Data([0x00, 0x00]))
    }

    @Test
    func `AuthenticateEV2First rejects more than six PCD capability bytes`() async {
        let mock = MockTransport()
        await #expect(throws: NFCError.self) {
            _ = try await DESFireCommands(transport: mock).authenticateEV2First(
                keyNo: 0x00,
                key: Data(count: 16),
                pcdCapabilities: Data(count: 7),
                rndA: Self.an12196RndA
            )
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `AuthenticateEV2First rejects the LRP capability bit before sending`() async {
        // NT4H2421Gx §9.1: "If present, PCDcap2:1:Bit1 must not be set, otherwise LRP
        // authentication is targeted"; the LRP answer adds an AuthMode byte (§9.2).
        let mock = MockTransport()
        do {
            _ = try await DESFireCommands(transport: mock).authenticateEV2First(
                keyNo: 0x00,
                key: Data(count: 16),
                pcdCapabilities: Data([0x02]),
                rndA: Self.an12196RndA
            )
            Issue.record("Expected invalidParameter")
        } catch let NFCError.invalidParameter(message) {
            #expect(message.contains("LRP"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `Authentication delay status is decoded`() async {
        // NT4H2421Gx Table 23: 91 AD AUTHENTICATION_DELAY.
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0xAD)]
        await #expect(throws: NFCError.desfireError(.authenticationDelay)) {
            _ = try await DESFireCommands(transport: mock).authenticateEV2First(
                keyNo: 0x00,
                key: Data(count: 16),
                pcdCapabilities: Data(),
                rndA: Self.an12196RndA
            )
        }
    }

    @Test(arguments: [31, 48])
    func `AuthenticateEV2First rejects a Part 2 answer that is not 32 bytes`(length: Int) async throws {
        let full = Self.an12196EV2FirstResponses[1].data
        let answer = length < full.count
            ? Data(full.prefix(length))
            : full + Data(repeating: 0x00, count: length - full.count)
        let mock = MockTransport()
        mock.apduResponses = [
            Self.an12196EV2FirstResponses[0],
            ResponseAPDU(data: answer, sw1: 0x91, sw2: 0x00),
        ]

        await #expect(throws: NFCError.invalidResponse(answer)) {
            _ = try await DESFireCommands(transport: mock).authenticateEV2First(
                keyNo: 0x00,
                key: Data(count: 16),
                pcdCapabilities: Data(),
                rndA: Self.an12196RndA
            )
        }
    }

    // MARK: - GetVersion mapping

    @Test
    func `GetVersion maps HW major 0x43 to EV3 and keeps Light and DUOX generic`() throws {
        var data = Data(repeating: 0x00, count: 28)
        data[0] = 0x04

        data[1] = 0x81
        data[3] = 0x43
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfireEV3)

        data[1] = 0x81
        data[3] = 0x42
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfireEV2)

        data[1] = 0x08
        data[3] = 0x30
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfire)

        data[1] = 0x01
        data[3] = 0xA0
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfire)
    }

    // MARK: - Fixtures

    private static let rndA = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    private static let rndB = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

    /// Mock PICC answering an AuthenticateISO handshake for `key`.
    private static func isoMock(key: Data) throws -> MockTransport {
        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: rndA + rotateLeft(rndB),
            iv: encryptedRndB
        )
        let finalCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: finalCiphertext, sw1: 0x91, sw2: 0x00),
        ]
        return mock
    }

    private static func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return Data(data.dropFirst()) + Data([first])
    }

    /// AN12196 AuthenticateEV2First example RndA.
    private static let an12196RndA = Data([
        0x13, 0xC5, 0xDB, 0x8A, 0x59, 0x30, 0x43, 0x9F,
        0xC3, 0xDE, 0xF9, 0xA4, 0xC6, 0x75, 0x36, 0x0F,
    ])

    /// AN12196 AuthenticateEV2First PICC answers, Kx = 00..00.
    private static let an12196EV2FirstResponses: [ResponseAPDU] = [
        ResponseAPDU(
            data: Data(hexString: "A04C124213C186F22399D33AC2A30215")!,
            sw1: 0x91,
            sw2: 0xAF
        ),
        ResponseAPDU(
            data: Data(hexString: "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663")!,
            sw1: 0x91,
            sw2: 0x00
        ),
    ]
}
