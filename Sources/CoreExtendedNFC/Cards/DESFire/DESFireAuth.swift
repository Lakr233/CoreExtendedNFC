import Foundation

public extension DESFireCommands {
    /// AuthenticateISO (0x1A) — 2K3DES mutual authentication.
    ///
    /// This establishes card-side authentication state for subsequent plain reads.
    /// Session key diversification beyond the 2K3DES flow remains out of scope.
    func authenticateISO(keyNo: UInt8, key: Data) async throws -> DESFireAuthenticationSession {
        try await authenticateISO(keyNo: keyNo, key: key, rndA: nil)
    }

    /// AuthenticateEV2First (0x71) — AES-128 mutual authentication.
    ///
    /// Reference: NXP AN12343 section 10.1, including the `SV1` / `SV2`
    /// session-vector derivation for `SesAuthENCKey` and `SesAuthMACKey`.
    func authenticateEV2First(
        keyNo: UInt8,
        key: Data,
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6)
    ) async throws -> DESFireAuthenticationSession {
        try await authenticateEV2First(
            keyNo: keyNo,
            key: key,
            pcdCapabilities: pcdCapabilities,
            rndA: nil
        )
    }

    /// Authenticate, then immediately read a plain-communication data file.
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
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6)
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
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6)
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
        pcdCapabilities: Data = Data(repeating: 0x00, count: 6)
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

extension DESFireCommands {
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
        return (session, data)
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
        return (session, data)
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
        let value = try await getValue(fileID: fileID)
        return (session, value)
    }

    func authenticateISO(
        keyNo: UInt8,
        key: Data,
        rndA: Data?
    ) async throws -> DESFireAuthenticationSession {
        guard key.count == 16 else {
            throw NFCError.unsupportedOperation(
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
        guard rotatedRndA == rotateLeft(rndAValue) else {
            throw NFCError.authenticationFailed
        }

        let sessionKey = Data(rndAValue.prefix(4))
            + Data(rndB.prefix(4))
            + Data(rndAValue.suffix(4))
            + Data(rndB.suffix(4))

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
            throw NFCError.unsupportedOperation(
                "AuthenticateEV2First currently supports 16-byte AES keys"
            )
        }
        guard pcdCapabilities.count == 6 else {
            throw NFCError.unsupportedOperation("PCD capabilities must be 6 bytes")
        }

        let startResponse = try await sendAuthenticationStart(
            command: Self.AUTHENTICATE_EV2_FIRST,
            data: Data([keyNo, 0x00])
        )
        guard startResponse.data.count >= 16 else {
            throw NFCError.invalidResponse(startResponse.data)
        }

        let encryptedRndB = Data(startResponse.data.prefix(16))
        let piccCapabilities = Data(startResponse.data.dropFirst(16))
        let rndB = try CryptoUtils.aesDecrypt(
            key: key,
            message: encryptedRndB,
            iv: Data(count: 16)
        )

        let rndAValue = try validateOrGenerateRandom(rndA, count: 16)
        let challenge = rndAValue + rotateLeft(rndB)
        let challengeCiphertext = try CryptoUtils.aesEncrypt(
            key: key,
            message: challenge,
            iv: encryptedRndB
        )
        let finalResponse = try await sendAuthenticationContinuation(challengeCiphertext)

        guard finalResponse.data.count >= 20 else {
            throw NFCError.invalidResponse(finalResponse.data)
        }

        let decryptedResponse = try CryptoUtils.aesDecrypt(
            key: key,
            message: finalResponse.data,
            iv: Data(challengeCiphertext.suffix(16))
        )
        guard decryptedResponse.count >= 20 else {
            throw NFCError.invalidResponse(finalResponse.data)
        }

        let transactionIdentifier = Data(decryptedResponse.prefix(4))
        let rotatedRndA = Data(decryptedResponse[4 ..< 20])
        guard rotatedRndA == rotateLeft(rndAValue) else {
            throw NFCError.authenticationFailed
        }

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
            pcdCapabilities: pcdCapabilities
        )
    }

    static func deriveEV2SessionKeys(
        staticKey: Data,
        rndA: Data,
        rndB: Data
    ) throws -> (sessionENCKey: Data, sessionMACKey: Data) {
        guard staticKey.count == 16, rndA.count == 16, rndB.count == 16 else {
            throw NFCError.cryptoError("EV2 session derivation requires 16-byte AES inputs")
        }

        let sharedTail = descendingSlice(rndA, from: 15, to: 14)
            + xor(
                descendingSlice(rndA, from: 13, to: 8),
                descendingSlice(rndB, from: 15, to: 10)
            )
            + descendingSlice(rndB, from: 9, to: 0)
            + descendingSlice(rndA, from: 7, to: 0)

        let sv1 = Data([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + sharedTail
        let sv2 = Data([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + sharedTail

        return try (
            AESCMAC.mac(key: staticKey, message: sv1),
            AESCMAC.mac(key: staticKey, message: sv2)
        )
    }

    private func sendAuthenticationStart(command: UInt8, data: Data) async throws -> ResponseAPDU {
        let response = try await transport.sendAPDU(CommandAPDU.desfireWrap(command: command, data: data))
        try validateDESFireStatus(response, expected: .additionalFrame)
        return response
    }

    private func sendAuthenticationContinuation(_ data: Data) async throws -> ResponseAPDU {
        let response = try await transport.sendAPDU(
            CommandAPDU.desfireWrap(command: Self.ADDITIONAL_FRAME, data: data)
        )
        try validateDESFireStatus(response, expected: .operationOK)
        return response
    }

    private func validateDESFireStatus(_ response: ResponseAPDU, expected: DESFireStatus) throws {
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

    private func validateOrGenerateRandom(_ candidate: Data?, count: Int) throws -> Data {
        if let candidate {
            guard candidate.count == count else {
                throw NFCError.cryptoError("Random input must be \(count) bytes")
            }
            return candidate
        }
        return CryptoUtils.randomBytes(count: count)
    }

    private func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return Data(data.dropFirst()) + Data([first])
    }

    private static func descendingSlice(_ data: Data, from upper: Int, to lower: Int) -> Data {
        precondition(upper >= lower)
        var result = Data()
        for index in stride(from: upper, through: lower, by: -1) {
            result.append(data[index])
        }
        return result
    }

    private static func xor(_ lhs: Data, _ rhs: Data) -> Data {
        precondition(lhs.count == rhs.count)
        var result = Data(count: lhs.count)
        for index in 0 ..< lhs.count {
            result[index] = lhs[index] ^ rhs[index]
        }
        return result
    }
}

private extension Data {
    static func + (lhs: Data, rhs: Data) -> Data {
        var result = Data(lhs)
        result.append(rhs)
        return result
    }
}
