import Foundation

public extension UltralightCommands {
    /// AUTHENTICATE (0x1A): MIFARE Ultralight C 2K3DES mutual authentication.
    func authenticateUltralightC(key: Data) async throws -> UltralightCAuthenticationSession {
        try await authenticateUltralightC(key: key, randomA: nil)
    }

    /// PWD_AUTH (0x1B): Authenticate with 4-byte password.
    /// Returns 2-byte PACK (Password Acknowledgment).
    /// Supported on Ultralight EV1 and NTAG.
    func passwordAuth(password: Data) async throws -> Data {
        guard password.count == 4 else {
            throw NFCError.unsupportedOperation("Password must be exactly 4 bytes")
        }
        var command = Data([0x1B])
        command.append(password)
        let response = try await transport.send(command)
        guard response.count >= 2 else {
            throw NFCError.authenticationFailed
        }
        return Data(response.prefix(2))
    }

    /// Read AUTH0 and ACCESS config pages to determine password protection range.
    /// Returns the first page protected by password and the access config byte.
    func readAuthConfig(configStartPage: UInt8) async throws -> (auth0Page: UInt8, accessBits: UInt8) {
        // Config pages layout (EV1/NTAG):
        // configStart + 0: MOD, RFUI, RFUI, AUTH0
        // configStart + 1: ACCESS, RFUI, RFUI, RFUI
        let data = try await readPages(startPage: configStartPage)
        let auth0 = data[data.startIndex + 3] // 4th byte of first config page
        let access = data[data.startIndex + 4] // 1st byte of second config page
        return (auth0, access)
    }

    /// Read AUTH0 / AUTH1 from Ultralight C configuration pages 42 and 43.
    func readUltralightCAccessConfiguration() async throws -> UltralightCAccessConfiguration {
        let data = try await readPages(startPage: 0x28)
        guard data.count >= 16 else {
            throw NFCError.invalidResponse(data)
        }

        let auth0 = data[data.startIndex + 8]
        let auth1 = data[data.startIndex + 12]
        let firstProtectedPage: UInt8? = auth0 == 0x30 ? nil : auth0
        return UltralightCAccessConfiguration(firstProtectedPage: firstProtectedPage, auth1: auth1)
    }
}

extension UltralightCommands {
    func authenticateUltralightC(
        key: Data,
        randomA: Data?
    ) async throws -> UltralightCAuthenticationSession {
        guard key.count == 16 else {
            throw NFCError.unsupportedOperation("Ultralight C authentication requires a 16-byte key")
        }

        let startResponse = try await transport.send(Data([0x1A, 0x00]))
        let startBytes = [UInt8](startResponse)
        guard startBytes.count >= 9, startBytes[0] == 0xAF else {
            throw NFCError.invalidResponse(startResponse)
        }

        let encryptedRndB = Data(startBytes[1 ..< 9])
        let rndB = try CryptoUtils.tripleDESDecrypt(key: key, message: encryptedRndB)
        let randomAValue = try validateOrGenerateRandom(randomA)
        let challenge = randomAValue + rotateLeft(rndB)
        let challengeCiphertext = try CryptoUtils.tripleDESEncrypt(
            key: key,
            message: challenge,
            iv: encryptedRndB
        )

        let finalResponse = try await transport.send(Data([0xAF]) + challengeCiphertext)
        let finalBytes = [UInt8](finalResponse)
        guard finalBytes.count >= 9, finalBytes[0] == 0x00 else {
            throw NFCError.invalidResponse(finalResponse)
        }

        let rotatedRndA = try CryptoUtils.tripleDESDecrypt(
            key: key,
            message: Data(finalBytes[1 ..< 9]),
            iv: Data(challengeCiphertext.suffix(8))
        )
        guard rotatedRndA == rotateLeft(randomAValue) else {
            throw NFCError.authenticationFailed
        }

        return UltralightCAuthenticationSession(randomA: randomAValue, randomB: rndB)
    }

    private func validateOrGenerateRandom(_ candidate: Data?) throws -> Data {
        if let candidate {
            guard candidate.count == 8 else {
                throw NFCError.cryptoError("Ultralight C random input must be 8 bytes")
            }
            return candidate
        }

        return CryptoUtils.randomBytes(count: 8)
    }

    private func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first else { return Data() }
        return Data(data.dropFirst()) + Data([first])
    }
}
