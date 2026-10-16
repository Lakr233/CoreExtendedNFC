import Foundation

public extension DESFireCommands {
    /// AuthenticateISO (0x1A) — 2K3DES mutual authentication.
    ///
    /// This establishes card-side authentication state for subsequent plain reads.
    /// A 16-byte key whose halves are equal (including the all-zero factory
    /// key) is single DES; the session key then repeats `RndA[0..3] ‖ RndB[0..3]`
    /// in both halves, as proxmark3 `DesfireAuthenticate` does.
    ///
    /// Not implemented: AuthenticateAES (0xAA), 3K3DES keys, and the EV1 CMAC
    /// secure-messaging layer for later commands (IV chaining, command MACs,
    /// response MAC verification, enciphered communication).
    func authenticateISO(keyNo: UInt8, key: Data) async throws -> DESFireAuthenticationSession {
        try await authenticateISO(keyNo: keyNo, key: key, rndA: nil)
    }

    /// AuthenticateEV2First (0x71) — AES-128 mutual authentication.
    ///
    /// Reference: NXP AN12343 section 10.1, including the `SV1` / `SV2`
    /// session-vector derivation for `SesAuthENCKey` and `SesAuthMACKey`.
    /// Part 1 is sent as `KeyNo ‖ LenCap ‖ PCDcap2`, where `LenCap` is
    /// `pcdCapabilities.count` (0–6 bytes; the default sends `LenCap = 0`).
    ///
    /// Not implemented: AuthenticateEV2NonFirst, EV2 secure messaging for
    /// later commands (command counter, CMACt, enciphered communication) and
    /// Transaction MAC (TMAC) computation. Follow-up reads therefore only
    /// work on files whose communication mode is plain.
    func authenticateEV2First(
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data = Data()
    ) async throws -> DESFireAuthenticationSession {
        try await authenticateEV2First(
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication data file.
    ///
    /// After AuthenticateISO the PICC appends an 8-byte EV1 CMAC to plain
    /// responses; it is stripped from the returned data but not verified.
    func readDataAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        length: UInt32 = 0
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await readDataAuthenticatedISO(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            offset: offset,
            length: length,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication data file.
    func readDataAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        length: UInt32 = 0,
        pcdCapabilities: Data = Data()
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await readDataAuthenticatedEV2(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            offset: offset,
            length: length,
            pcdCapabilities: pcdCapabilities,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication record file.
    ///
    /// After AuthenticateISO the PICC appends an 8-byte EV1 CMAC to plain
    /// responses; it is stripped from the returned data but not verified.
    func readRecordsAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        count: UInt32 = 0
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await readRecordsAuthenticatedISO(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            offset: offset,
            count: count,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication record file.
    func readRecordsAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32 = 0,
        count: UInt32 = 0,
        pcdCapabilities: Data = Data()
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        try await readRecordsAuthenticatedEV2(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            offset: offset,
            count: count,
            pcdCapabilities: pcdCapabilities,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication value file.
    ///
    /// After AuthenticateISO the PICC appends an 8-byte EV1 CMAC to plain
    /// responses; it is stripped before decoding but not verified.
    func getValueAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        try await getValueAuthenticatedISO(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication value file.
    func getValueAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data = Data()
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        try await getValueAuthenticatedEV2(
            fileID: fileID,
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: nil
        )
    }
}

public extension DESFireCommands {
    func getValueAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        let session = try await authenticateEV2First(
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )
        let value = try await getValue(fileID: fileID)
        return (session, value)
    }

    func readDataAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32,
        length: UInt32,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        let session = try await authenticateISO(
            keyNo: keyNo,
            key: key,
            rndA: rndA
        )
        let data = try await readData(fileID: fileID, offset: offset, length: length)
        return try (session, Self.stripEV1ResponseMAC(data))
    }

    func readDataAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32,
        length: UInt32,
        pcdCapabilities: Data,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        let session = try await authenticateEV2First(
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )
        let data = try await readData(fileID: fileID, offset: offset, length: length)
        return (session, data)
    }

    func readRecordsAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32,
        count: UInt32,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        let session = try await authenticateISO(keyNo: keyNo, key: key, rndA: rndA)
        let data = try await readRecords(fileID: fileID, offset: offset, count: count)
        return try (session, Self.stripEV1ResponseMAC(data))
    }

    func readRecordsAuthenticatedEV2(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        offset: UInt32,
        count: UInt32,
        pcdCapabilities: Data,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, data: Data) {
        let session = try await authenticateEV2First(
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: rndA
        )
        let data = try await readRecords(fileID: fileID, offset: offset, count: count)
        return (session, data)
    }

    func getValueAuthenticatedISO(
        fileID: UInt8,
        keyNo: UInt8,
        key: Data,
        rndA: Data?
    ) async throws -> (session: DESFireAuthenticationSession, value: Int32) {
        let session = try await authenticateISO(keyNo: keyNo, key: key, rndA: rndA)
        let response = try await sendCommand(Self.GET_VALUE, data: Data([fileID]))
        let value = try Self.decodeDESFireValue(Self.stripEV1ResponseMAC(response))
        return (session, value)
    }

    func authenticateISO(
        keyNo: UInt8,
        key: Data,
        rndA: Data?
    ) async throws -> DESFireAuthenticationSession {
        guard key.count == 16 else {
            throw NFCError.invalidParameter(
                "AuthenticateISO currently supports 16-byte 2K3DES keys"
            )
        }

        let startResponse = try await sendAuthenticationStart(
            command: Self.AUTHENTICATE_ISO,
            data: Data([keyNo])
        )
        let encryptedRndB = startResponse.data

        guard encryptedRndB.count == 8 else {
            throw NFCError.invalidResponse(startResponse.data)
        }

        let rndB = try CryptoUtils.tripleDESDecrypt(key: key, message: encryptedRndB)
        let rndAValue = try validateOrGenerateRandom(rndA, count: 8)
        let challenge = rndAValue + rotateLeft(rndB)

        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: challenge,
            iv: encryptedRndB
        )
        let finalResponse = try await sendAuthenticationContinuation(challengeCiphertext)

        guard finalResponse.data.count == 8 else {
            throw NFCError.invalidResponse(finalResponse.data)
        }

        let rotatedRndA = try CryptoUtils.tripleDESDecrypt(
            key: key,
            message: finalResponse.data,
            iv: Data(challengeCiphertext.suffix(8))
        )
        guard CryptoUtils.constantTimeEquals(rotatedRndA, rotateLeft(rndAValue)) else {
            throw NFCError.authenticationFailed
        }

        let sessionKey = Self.deriveISOSessionKey(key: key, rndA: rndAValue, rndB: rndB)

        return DESFireAuthenticationSession(
            scheme: .authenticateISO,
            keyNumber: keyNo,
            sessionENCKey: sessionKey,
            sessionMACKey: sessionKey
        )
    }

    func authenticateEV2First(
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data,
        rndA: Data?
    ) async throws -> DESFireAuthenticationSession {
        guard key.count == 16 else {
            throw NFCError.invalidParameter(
                "AuthenticateEV2First currently supports 16-byte AES keys"
            )
        }
        guard pcdCapabilities.count <= 6 else {
            throw NFCError.invalidParameter("PCD capabilities must be at most 6 bytes")
        }

        // AN12343 §10.1: Part 1 = KeyNo ‖ LenCap ‖ PCDcap2 (LenCap bytes).
        let startResponse = try await sendAuthenticationStart(
            command: Self.AUTHENTICATE_EV2_FIRST,
            data: Data([keyNo, UInt8(pcdCapabilities.count)]) + Data(pcdCapabilities)
        )
        guard startResponse.data.count >= 16 else {
            throw NFCError.invalidResponse(startResponse.data)
        }

        // Part 1 returns only E(Kx, RndB); PDcap2 arrives in the Part 2 answer.
        let encryptedRndB = Data(startResponse.data.prefix(16))
        let rndB = try CryptoUtils.aesDecrypt(
            key: key,
            message: encryptedRndB,
            iv: Data(count: 16)
        )

        let rndAValue = try validateOrGenerateRandom(rndA, count: 16)
        let challenge = rndAValue + rotateLeft(rndB)
        // AN12196 §6.6 / AN12343: unlike legacy AuthenticateAES (0xAA), the
        // EV2First Part 2 command and response are each encrypted with a
        // zero IV — the IV is NOT chained from E(Kx, RndB).
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: challenge,
            iv: Data(count: 16)
        )
        let finalResponse = try await sendAuthenticationContinuation(challengeCiphertext)

        // E(Kx, TI ‖ RndA' ‖ PDcap2 ‖ PCDcap2) is always exactly 32 bytes.
        guard finalResponse.data.count == 32 else {
            throw NFCError.invalidResponse(finalResponse.data)
        }

        let decryptedResponse = try CryptoUtils.aesDecrypt(
            key: key,
            message: finalResponse.data,
            iv: Data(count: 16)
        )
        guard decryptedResponse.count == 32 else {
            throw NFCError.invalidResponse(finalResponse.data)
        }

        // Decrypted Part 2 answer (AN12343 §10.1, AN12196):
        // TI (4) ‖ RndA' (16) ‖ PDcap2 (6) ‖ PCDcap2 (6).
        let plain = [UInt8](decryptedResponse)
        let transactionIdentifier = Data(plain[0 ..< 4])
        let rotatedRndA = Data(plain[4 ..< 20])
        guard CryptoUtils.constantTimeEquals(rotatedRndA, rotateLeft(rndAValue)) else {
            throw NFCError.authenticationFailed
        }
        let piccCapabilities = Data(plain[20 ..< 26])
        let echoedPCDCapabilities = Data(plain[26 ..< 32])

        let (sessionENCKey, sessionMACKey) = try Self.deriveEV2SessionKeys(
            staticKey: key,
            rndA: rndAValue,
            rndB: rndB
        )

        return DESFireAuthenticationSession(
            scheme: .authenticateEV2First,
            keyNumber: keyNo,
            sessionENCKey: sessionENCKey,
            sessionMACKey: sessionMACKey,
            transactionIdentifier: transactionIdentifier,
            piccCapabilities: piccCapabilities,
            pcdCapabilities: echoedPCDCapabilities
        )
    }

    /// EV1 AuthenticateISO session key for a 16-byte DES/2K3DES key
    /// (proxmark3 `DesfireGenSessionKeyEV1`, `desfirecore.c`):
    /// `RndA[0..3] ‖ RndB[0..3] ‖ RndA[4..7] ‖ RndB[4..7]`, or, when both key
    /// halves are equal (single DES), `RndA[0..3] ‖ RndB[0..3]` twice.
    static func deriveISOSessionKey(key: Data, rndA: Data, rndB: Data) -> Data {
        let a = [UInt8](rndA)
        let b = [UInt8](rndB)
        let k = [UInt8](key)
        let first = Data(a[0 ..< 4]) + Data(b[0 ..< 4])
        if k.count == 16, k[0 ..< 8] == k[8 ..< 16] {
            return first + first
        }
        return first + Data(a[4 ..< 8]) + Data(b[4 ..< 8])
    }

    /// Strip the 8-byte CMAC that the PICC appends to plain-mode responses
    /// once an EV1 (AuthenticateISO) session is active (proxmark3
    /// `DesfireSecureChannelDecodeEV1`: "if comm mode = plain --> response
    /// with MAC"). The MAC is not verified: that needs the EV1 CMAC IV chained
    /// over every command since authentication, which this library does not
    /// track.
    static func stripEV1ResponseMAC(_ data: Data) throws -> Data {
        guard data.count >= 8 else {
            throw NFCError.invalidResponse(data)
        }
        return Data(data.dropLast(8))
    }

    static func deriveEV2SessionKeys(
        staticKey: Data,
        rndA: Data,
        rndB: Data
    ) throws -> (sessionENCKey: Data, sessionMACKey: Data) {
        guard staticKey.count == 16, rndA.count == 16, rndB.count == 16 else {
            throw NFCError.cryptoError("EV2 session derivation requires 16-byte AES inputs")
        }

        // AN12196 / AN12343: SV1 = A5 5A 00 01 00 80 ‖ RndA[15..14] ‖
        // (RndA[13..8] ⊕ RndB[15..10]) ‖ RndB[9..0] ‖ RndA[7..0].
        // NXP numbers bytes MSB-first, so byte 15 is array index 0.
        let a = [UInt8](rndA)
        let b = [UInt8](rndB)
        let sharedTail = Data(a[0 ..< 2])
            + Data(zip(a[2 ..< 8], b[0 ..< 6]).map { $0 ^ $1 })
            + Data(b[6 ..< 16])
            + Data(a[8 ..< 16])

        let sv1 = Data([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + sharedTail
        let sv2 = Data([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + sharedTail

        return try (
            AESCMAC.mac(key: staticKey, message: sv1),
            AESCMAC.mac(key: staticKey, message: sv2)
        )
    }

    func sendAuthenticationStart(command: UInt8, data: Data) async throws -> ResponseAPDU {
        let response = try await transport.sendAPDU(CommandAPDU.desfireWrap(command: command, data: data))
        try validateDESFireStatus(response, expected: .additionalFrame)
        return response
    }

    func sendAuthenticationContinuation(_ data: Data) async throws -> ResponseAPDU {
        let response = try await transport.sendAPDU(
            CommandAPDU.desfireWrap(command: Self.ADDITIONAL_FRAME, data: data)
        )
        try validateDESFireStatus(response, expected: .operationOK)
        return response
    }

    func validateDESFireStatus(_ response: ResponseAPDU, expected: DESFireStatus) throws {
        guard response.sw1 == 0x91 else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
        guard response.sw2 == expected.rawValue else {
            if let status = DESFireStatus(rawValue: response.sw2) {
                throw NFCError.desfireError(status)
            }
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
    }

    func validateOrGenerateRandom(_ candidate: Data?, count: Int) throws -> Data {
        if let candidate {
            guard candidate.count == count else {
                throw NFCError.cryptoError("Random input must be \(count) bytes")
            }
            return candidate
        }
        return try CryptoUtils.secureRandomBytes(count: count)
    }

    func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return Data(data.dropFirst()) + Data([first])
    }
}
