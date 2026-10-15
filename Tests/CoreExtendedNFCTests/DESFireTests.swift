// MIFARE DESFire command test suite.
//
// Public provenance for byte-level assertions in this file:
// - NXP AN11004, "MIFARE DESFire as Type 4 Tag", section 5.1, shows the
//   wrapped native-command APDU layout `90 xx 00 00 Lc Data 00` and the
//   `0xAF` additional-frame exchange in ISO 7816-4 mode.
//   https://www.nxp.com/docs/en/application-note/AN11004.pdf
// - NXP AN12343, "MIFARE DESFire Light Features and Hints", section 10.1,
//   documents the AuthenticateEV2First transcript shape, the returned
//   `TI || RndA' || PDcap2 || PCDcap2` plaintext, and SV1/SV2 session-key
//   derivation for `SesAuthENCKey` / `SesAuthMACKey`.
//   https://www.nxp.com/docs/en/application-note/AN12343.pdf
// - NXP AN12196, "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints",
//   AuthenticateEV2First example: Kx = 0, RndA = 13C5DB8A..., RndB = B9E2FC78...,
//   SesAuthENCKey = 1309C877..., SesAuthMACKey = 4C6626F5... (hard-coded below).
//
// Public NXP material does not publish the full legacy EV1 AuthenticateISO
// 2K3DES byte transcript with session-key concatenation. Those tests therefore
// lock the interoperable wrapped-mode behavior we implement, while the EV2
// session-key path is anchored to public NXP documentation above.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DESFireTests {
    // MARK: - Command Wrapping

    @Test
    func `DESFire command wrapping format`() {
        let apdu = CommandAPDU.desfireWrap(command: 0x6A)
        #expect(apdu.cla == 0x90)
        #expect(apdu.ins == 0x6A)
        #expect(apdu.p1 == 0x00)
        #expect(apdu.p2 == 0x00)
        #expect(apdu.le == 0x00)
    }

    @Test
    func `DESFire command wrapping with data`() {
        let apdu = CommandAPDU.desfireWrap(command: 0x5A, data: Data([0x01, 0x00, 0x00]))
        let bytes = apdu.bytes
        #expect(bytes == Data([0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00]))
    }

    @Test
    func `Additional Frame wrapping`() {
        let apdu = CommandAPDU.desfireWrap(command: DESFireCommands.ADDITIONAL_FRAME)
        #expect(apdu.ins == 0xAF)
        #expect(apdu.bytes == Data([0x90, 0xAF, 0x00, 0x00, 0x00]))
    }

    // MARK: - Chaining

    @Test
    func `Single-frame response`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x01, 0x02, 0x03]), sw1: 0x91, sw2: 0x00),
        ]
        let commands = DESFireCommands(transport: mock)
        let result = try await commands.sendCommand(0x6A)
        #expect(result == Data([0x01, 0x02, 0x03]))
    }

    @Test
    func `Multi-frame AF chaining collects all data`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x01, 0x02]), sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: Data([0x03, 0x04]), sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: Data([0x05]), sw1: 0x91, sw2: 0x00),
        ]
        let commands = DESFireCommands(transport: mock)
        let result = try await commands.sendCommand(0x60)
        #expect(result == Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        // Should have sent initial + 2 AF frames
        #expect(mock.sentAPDUs.count == 3)
        #expect(mock.sentAPDUs[1].ins == 0xAF)
        #expect(mock.sentAPDUs[2].ins == 0xAF)
    }

    @Test
    func `Error status throws desfireError`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x9D), // Permission denied
        ]
        let commands = DESFireCommands(transport: mock)

        do {
            _ = try await commands.sendCommand(0x6A)
            #expect(Bool(false), "Should have thrown")
        } catch let error as NFCError {
            if case let .desfireError(status) = error {
                #expect(status == .permissionDenied)
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }

    // MARK: - Status Codes

    @Test
    func `DESFire status descriptions`() {
        #expect(DESFireStatus.operationOK.description == "Operation OK")
        #expect(DESFireStatus.permissionDenied.description == "Permission denied")
        #expect(DESFireStatus.authenticationError.description == "Authentication error")
        #expect(DESFireStatus.fileNotFound.description == "File not found")
    }

    @Test
    func `DESFire status raw values`() {
        #expect(DESFireStatus.operationOK.rawValue == 0x00)
        #expect(DESFireStatus.additionalFrame.rawValue == 0xAF)
        #expect(DESFireStatus.permissionDenied.rawValue == 0x9D)
    }

    // MARK: - Version Info

    @Test
    func `Parse DESFire version info`() throws {
        var data = Data(repeating: 0x00, count: 28)
        data[0] = 0x04 // HW vendor NXP
        data[3] = 0x01 // HW major version 1 = EV1
        let info = try DESFireVersionInfo(data: data)
        #expect(info.hardwareVendorID == 0x04)
        #expect(info.cardType == .mifareDesfireEV1)
    }

    @Test
    func `DESFire EV2 and EV3 detection uses datasheet HW major versions`() throws {
        // NXP MF3D(H)x2 GetVersion: HWMajorVersion 0x12 (EV2); MF3D(H)x3: 0x33 (EV3).
        var data = Data(repeating: 0x00, count: 28)
        data[0] = 0x04
        data[3] = 0x12
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfireEV2)
        data[3] = 0x22 // EV2 XL
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfireEV2)
        data[3] = 0x33
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfireEV3)
        data[3] = 0x00
        #expect(try DESFireVersionInfo(data: data).cardType == .mifareDesfire)
    }

    @Test
    func `EV2 session keys match AN12196 vector`() throws {
        // NXP AN12196 AuthenticateEV2First example, Kx = 00..00.
        let keys = try DESFireCommands.deriveEV2SessionKeys(
            staticKey: Data(count: 16),
            rndA: #require(Data(hexString: "13C5DB8A5930439FC3DEF9A4C675360F")),
            rndB: #require(Data(hexString: "B9E2FC789B64BF237CCCAA20EC7E6E48"))
        )
        #expect(keys.sessionENCKey == Data(hexString: "1309C877509E5A215007FF0ED19CA564"))
        #expect(keys.sessionMACKey == Data(hexString: "4C6626F5E72EA694202139295C7A7FC7"))
    }

    // MARK: - Status Mapping and Chaining Bounds

    @Test
    func `Non-0x91 status is not mapped to a DESFire status`() async {
        for (sw1, sw2): (UInt8, UInt8) in [(0x6E, 0x00), (0x6D, 0x00), (0x69, 0x9D)] {
            let mock = MockTransport()
            mock.apduResponses = [ResponseAPDU(data: Data(), sw1: sw1, sw2: sw2)]
            do {
                _ = try await DESFireCommands(transport: mock).getFileIDs()
                Issue.record("expected throw")
            } catch let NFCError.unexpectedStatusWord(gotSW1, gotSW2) {
                #expect(gotSW1 == sw1)
                #expect(gotSW2 == sw2)
            } catch {
                Issue.record("got \(error)")
            }
        }
    }

    @Test
    func `Endless AF chaining is bounded`() async {
        let mock = MockTransport()
        mock.apduResponses = Array(
            repeating: ResponseAPDU(data: Data([0x00]), sw1: 0x91, sw2: 0xAF),
            count: DESFireCommands.maxAdditionalFrames + 10
        )
        do {
            _ = try await DESFireCommands(transport: mock).sendCommand(0xBD, data: Data([0x01, 0, 0, 0, 0, 0, 0]))
            Issue.record("expected throw")
        } catch let NFCError.unexpectedStatusWord(sw1, sw2) {
            #expect(sw1 == 0x91)
            #expect(sw2 == 0xAF)
        } catch {
            Issue.record("got \(error)")
        }
        #expect(mock.sentAPDUs.count == DESFireCommands.maxAdditionalFrames + 1)
    }

    // MARK: - File Settings (Transaction MAC)

    @Test
    func `Parse Transaction MAC file settings`() throws {
        // MF3D(H)x2/x3 file type 0x05: FileType, FileOption, AccessRights, TMKeyOption, ...
        for data in [Data([0x05, 0x00, 0xF0, 0xFF, 0x02, 0x00]), Data([0x05, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0x00])] {
            let settings = try DESFireFileSettings(data: data)
            #expect(settings.fileType == .transactionMAC)
            #expect(settings.accessRights == 0xFFF0)
        }
    }

    // MARK: - File Settings

    @Test
    func `Parse standard data file settings`() throws {
        // File type=0x00, comm=0x00, access=0x0000, size=0x000020 (32 bytes)
        let data = Data([0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00])
        let settings = try DESFireFileSettings(data: data)
        #expect(settings.fileType == .standardData)
        #expect(settings.fileSize == 32)
    }

    // MARK: - Application Operations

    @Test
    func `SELECT_APPLICATION sends 3-byte AID`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00),
        ]
        let commands = DESFireCommands(transport: mock)
        try await commands.selectApplication(Data([0x01, 0x00, 0x00]))
        #expect(mock.sentAPDUs[0].ins == 0x5A)
    }

    @Test
    func `GET_APPLICATION_IDS parses 3-byte AIDs`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x01, 0x00, 0x00, 0x02, 0x00, 0x00]), sw1: 0x91, sw2: 0x00),
        ]
        let commands = DESFireCommands(transport: mock)
        let aids = try await commands.getApplicationIDs()
        #expect(aids.count == 2)
        #expect(aids[0] == Data([0x01, 0x00, 0x00]))
        #expect(aids[1] == Data([0x02, 0x00, 0x00]))
    }

    // MARK: - Authentication

    @Test
    func `AuthenticateISO establishes a 2K3DES session`() async throws {
        // Wrapped native mode and AF chaining are public in AN11004 section 5.1.
        // The legacy 2K3DES session-key splice used here is regression-locked for
        // interoperability because NXP's public DESFire notes do not expose the
        // full EV1 AuthenticateISO transcript byte-for-byte.
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndA = try #require(Data(hexString: "0102030405060708"))
        let rndB = try #require(Data(hexString: "1122334455667788"))

        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let finalCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: finalCiphertext, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let session = try await commands.authenticateISO(keyNo: 0x02, key: key, rndA: rndA)

        #expect(session.scheme == .authenticateISO)
        #expect(session.keyNumber == 0x02)
        #expect(
            session.sessionENCKey
                == Data([0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44, 0x05, 0x06, 0x07, 0x08, 0x55, 0x66, 0x77, 0x88])
        )
        #expect(session.sessionENCKey == session.sessionMACKey)
        #expect(mock.sentAPDUs.map(\.ins) == [0x1A, 0xAF])
        #expect(mock.sentAPDUs[0].data == Data([0x02]))
        #expect(mock.sentAPDUs[1].data == challengeCiphertext)
    }

    @Test
    func `AuthenticateEV2First derives AES session keys and TI`() async throws {
        // AN12343 section 10.1 / AN12196 describe the public EV2 flow:
        // 1. `0x71` starts authentication and the PICC returns `E(Kx, RndB)` (16 bytes).
        // 2. The PCD answers with `E(Kx, RndA || RndB')`.
        // 3. The final plaintext is `TI || RndA' || PDcap2 || PCDcap2`.
        // 4. `SesAuthENCKey` and `SesAuthMACKey` are derived from SV1 / SV2.
        // Key, RndA and RndB are the AN12196 example values, so the session keys
        // must equal the AN12196 published SesAuthENCKey / SesAuthMACKey.
        let key = Data(count: 16)
        let rndA = try #require(Data(hexString: "13C5DB8A5930439FC3DEF9A4C675360F"))
        let rndB = try #require(Data(hexString: "B9E2FC789B64BF237CCCAA20EC7E6E48"))
        let ti = try #require(Data(hexString: "A1B2C3D4"))
        let pcdCapabilities = try #require(Data(hexString: "010203040506"))
        let piccCapabilities = try #require(Data(hexString: "0A0B0C0D0E0F"))

        let encryptedRndB = try CryptoUtils.aesEncrypt(
            key: key,
            message: rndB,
            iv: Data(count: 16)
        )
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let responsePlaintext = Self.concat(ti, Self.rotateLeft(rndA), piccCapabilities, pcdCapabilities)
        let responseCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: responsePlaintext,
            iv: Data(challengeCiphertext.suffix(16))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: responseCiphertext, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let session = try await commands.authenticateEV2First(
            keyNo: 0x00,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )

        #expect(session.scheme == .authenticateEV2First)
        #expect(session.keyNumber == 0x00)
        #expect(session.transactionIdentifier == ti)
        #expect(session.pcdCapabilities == pcdCapabilities)
        #expect(session.piccCapabilities == piccCapabilities)
        #expect(session.sessionENCKey == Data(hexString: "1309C877509E5A215007FF0ED19CA564"))
        #expect(session.sessionMACKey == Data(hexString: "4C6626F5E72EA694202139295C7A7FC7"))
        #expect(mock.sentAPDUs.map(\.ins) == [0x71, 0xAF])
        #expect(mock.sentAPDUs[0].data == Data([0x00, 0x00]))
        #expect(mock.sentAPDUs[1].data == challengeCiphertext)
    }

    @Test
    func `Authenticated EV2 read performs auth before READ_DATA`() async throws {
        // The ordering assertion here is intentional: authenticate first, then
        // issue the plain-communication file command. That keeps UIKit truthful
        // about current support: authenticated bootstrap, plain read only.
        let key = try #require(Data(hexString: "000102030405060708090A0B0C0D0E0F"))
        let rndA = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndB = try #require(Data(hexString: "102132435465768798A9BACBDCEDFE0F"))
        let ti = try #require(Data(hexString: "A1B2C3D4"))
        let pcdCapabilities = try #require(Data(hexString: "010203040506"))
        let piccCapabilities = try #require(Data(hexString: "0A0B0C0D0E0F"))
        let filePayload = try #require(Data(hexString: "DEADBEEF"))

        let encryptedRndB = try CryptoUtils.aesEncrypt(
            key: key,
            message: rndB,
            iv: Data(count: 16)
        )
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let responseCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(ti, Self.rotateLeft(rndA), piccCapabilities, pcdCapabilities),
            iv: Data(challengeCiphertext.suffix(16))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: responseCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: filePayload, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.readDataAuthenticatedEV2(
            fileID: 0x03,
            keyNo: 0x00,
            key: key,
            offset: 0x000102,
            length: 0x000004,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )

        #expect(result.session.transactionIdentifier == ti)
        #expect(result.data == filePayload)
        #expect(mock.sentAPDUs.map(\.ins) == [0x71, 0xAF, 0xBD])
        #expect(
            mock.sentAPDUs[2].data
                == Data([0x03, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00])
        )
    }

    @Test
    func `Authenticated EV2 record read performs auth before READ_RECORDS`() async throws {
        // This mirrors the EV2-first transcript from AN12343 section 10.1, then
        // locks the wrapped `READ_RECORDS (0xBB)` request layout we expose as a
        // safe read-only follow-up after authentication.
        let key = try #require(Data(hexString: "000102030405060708090A0B0C0D0E0F"))
        let rndA = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndB = try #require(Data(hexString: "102132435465768798A9BACBDCEDFE0F"))
        let ti = try #require(Data(hexString: "A1B2C3D4"))
        let pcdCapabilities = try #require(Data(hexString: "010203040506"))
        let piccCapabilities = try #require(Data(hexString: "0A0B0C0D0E0F"))
        let recordPayload = try #require(Data(hexString: "10203040"))

        let encryptedRndB = try CryptoUtils.aesEncrypt(
            key: key,
            message: rndB,
            iv: Data(count: 16)
        )
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let responseCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(ti, Self.rotateLeft(rndA), piccCapabilities, pcdCapabilities),
            iv: Data(challengeCiphertext.suffix(16))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: responseCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: recordPayload, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.readRecordsAuthenticatedEV2(
            fileID: 0x07,
            keyNo: 0x00,
            key: key,
            offset: 0x000002,
            count: 0x000001,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )

        #expect(result.session.transactionIdentifier == ti)
        #expect(result.data == recordPayload)
        #expect(mock.sentAPDUs.map(\.ins) == [0x71, 0xAF, 0xBB])
        #expect(mock.sentAPDUs[2].data == Data([0x07, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00]))
    }

    @Test
    func `Authenticated ISO read performs auth before READ_DATA`() async throws {
        // `0xBD` is the wrapped READ_DATA instruction used after the legacy ISO
        // mutual-auth handshake has completed. This test keeps the call order and
        // 3-byte offset / length encoding fixed so a single-byte regression fails fast.
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndA = try #require(Data(hexString: "0102030405060708"))
        let rndB = try #require(Data(hexString: "1122334455667788"))
        let filePayload = try #require(Data(hexString: "CAFEF00D"))

        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let finalCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: finalCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: filePayload, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.readDataAuthenticatedISO(
            fileID: 0x04,
            keyNo: 0x02,
            key: key,
            offset: 0x000000,
            length: 0x000004,
            rndA: rndA
        )

        #expect(result.session.scheme == .authenticateISO)
        #expect(result.data == filePayload)
        #expect(mock.sentAPDUs.map(\.ins) == [0x1A, 0xAF, 0xBD])
        #expect(mock.sentAPDUs[2].data == Data([0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]))
    }

    @Test
    func `Authenticated ISO record read performs auth before READ_RECORDS`() async throws {
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndA = try #require(Data(hexString: "0102030405060708"))
        let rndB = try #require(Data(hexString: "1122334455667788"))
        let recordPayload = try #require(Data(hexString: "010203040506"))

        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let finalCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: finalCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: recordPayload, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.readRecordsAuthenticatedISO(
            fileID: 0x06,
            keyNo: 0x02,
            key: key,
            offset: 0x000001,
            count: 0x000002,
            rndA: rndA
        )

        #expect(result.session.scheme == .authenticateISO)
        #expect(result.data == recordPayload)
        #expect(mock.sentAPDUs.map(\.ins) == [0x1A, 0xAF, 0xBB])
        #expect(mock.sentAPDUs[2].data == Data([0x06, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00]))
    }

    @Test
    func `Authenticated ISO value read performs auth before GET_VALUE`() async throws {
        // `0x6C` is the wrapped GET_VALUE instruction. This remains read-only on
        // purpose; we are not exposing authenticated write/admin flows yet.
        let key = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndA = try #require(Data(hexString: "0102030405060708"))
        let rndB = try #require(Data(hexString: "1122334455667788"))
        let valueBytes = Data([0x78, 0x56, 0x34, 0x12])

        let encryptedRndB = try CryptoUtils.tripleDESEncrypt(key: key, message: rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let finalCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: Self.rotateLeft(rndA),
            iv: Data(challengeCiphertext.suffix(8))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: finalCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: valueBytes, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.getValueAuthenticatedISO(
            fileID: 0x05,
            keyNo: 0x02,
            key: key,
            rndA: rndA
        )

        #expect(result.session.scheme == .authenticateISO)
        #expect(result.value == 0x1234_5678)
        #expect(mock.sentAPDUs.map(\.ins) == [0x1A, 0xAF, 0x6C])
        #expect(mock.sentAPDUs[2].data == Data([0x05]))
    }

    @Test
    func `Authenticated EV2 value read performs auth before GET_VALUE`() async throws {
        // Like the other EV2 tests, this anchors the auth transcript to AN12343
        // and regression-locks the follow-up wrapped `GET_VALUE (0x6C)` request.
        let key = try #require(Data(hexString: "000102030405060708090A0B0C0D0E0F"))
        let rndA = try #require(Data(hexString: "00112233445566778899AABBCCDDEEFF"))
        let rndB = try #require(Data(hexString: "102132435465768798A9BACBDCEDFE0F"))
        let ti = try #require(Data(hexString: "A1B2C3D4"))
        let pcdCapabilities = try #require(Data(hexString: "010203040506"))
        let piccCapabilities = try #require(Data(hexString: "0A0B0C0D0E0F"))
        let valueBytes = Data([0xEF, 0xCD, 0xAB, 0x89])

        let encryptedRndB = try CryptoUtils.aesEncrypt(
            key: key,
            message: rndB,
            iv: Data(count: 16)
        )
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(rndA, Self.rotateLeft(rndB)),
            iv: encryptedRndB
        )
        let responseCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: Self.concat(ti, Self.rotateLeft(rndA), piccCapabilities, pcdCapabilities),
            iv: Data(challengeCiphertext.suffix(16))
        )

        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: encryptedRndB, sw1: 0x91, sw2: 0xAF),
            ResponseAPDU(data: responseCiphertext, sw1: 0x91, sw2: 0x00),
            ResponseAPDU(data: valueBytes, sw1: 0x91, sw2: 0x00),
        ]

        let commands = DESFireCommands(transport: mock)
        let result = try await commands.getValueAuthenticatedEV2(
            fileID: 0x08,
            keyNo: 0x00,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )

        #expect(result.session.transactionIdentifier == ti)
        #expect(result.value == -1_985_229_329)
        #expect(mock.sentAPDUs.map(\.ins) == [0x71, 0xAF, 0x6C])
        #expect(mock.sentAPDUs[2].data == Data([0x08]))
    }

    private static func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return concat(Data(data.dropFirst()), Data([first]))
    }

    private static func concat(_ parts: Data...) -> Data {
        parts.reduce(into: Data()) { result, part in
            result.append(part)
        }
    }
}
