import Foundation

/// BAC (Basic Access Control) handler per ICAO Doc 9303 Part 11.
///
/// Performs mutual authentication using MRZ-derived keys and establishes
/// a Secure Messaging channel for subsequent data group reads.
///
/// Protocol flow:
/// 1. Derive Kenc and Kmac from MRZ key
/// 2. GET CHALLENGE → receive rnd.icc (8 bytes)
/// 3. Build MUTUAL AUTHENTICATE payload (eifd || mifd)
/// 4. Decrypt response → extract session key material
/// 5. Derive KSenc, KSmac, SSC
/// 6. Return SecureMessagingTransport
public enum BACHandler {
    /// Perform BAC and return a Secure Messaging transport.
    ///
    /// - Parameters:
    ///   - mrzKey: The MRZ key string (docNumber + checkDigit + DOB + checkDigit + DOE + checkDigit).
    ///   - transport: The underlying NFC tag transport (ISO 7816).
    ///   - rndIFD: Optional 8-byte random for testing (nil = generate random).
    ///   - kIFD: Optional 16-byte keying material for testing (nil = generate random).
    /// - Returns: A `SecureMessagingTransport` wrapping the underlying transport.
    public static func performBAC(
        mrzKey: String,
        transport: any NFCTagTransport,
        rndIFD: Data? = nil,
        kIFD: Data? = nil
    ) async throws -> SecureMessagingTransport {
        NFCLog.info("Starting BAC authentication", source: "Passport")

        // Validate caller-supplied randomness before any RF traffic (ICAO 9303-11 §9.7.2).
        if let rndIFD, rndIFD.count != 8 {
            throw NFCError.bacFailed("rndIFD must be 8 bytes, got \(rndIFD.count)")
        }
        if let kIFD, kIFD.count != 16 {
            throw NFCError.bacFailed("kIFD must be 16 bytes, got \(kIFD.count)")
        }

        // Step 1: Derive basic access keys from MRZ
        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let kenc = KeyDerivation.deriveKey(keySeed: kseed, mode: .enc)
        let kmac = KeyDerivation.deriveKey(keySeed: kseed, mode: .mac)

        // Step 2: GET CHALLENGE — receive 8-byte random from chip
        NFCLog.debug("GET CHALLENGE", source: "Passport")
        let challengeAPDU = CommandAPDU.getChallenge()
        let challengeResponse = try await transport.sendAPDU(challengeAPDU)

        guard challengeResponse.isSuccess else {
            throw NFCError.bacFailed("GET CHALLENGE failed: SW=\(String(format: "%04X", challengeResponse.statusWord))")
        }
        guard challengeResponse.data.count == 8 else {
            throw NFCError.bacFailed("GET CHALLENGE returned \(challengeResponse.data.count) bytes, expected 8")
        }
        let rndICC = Data(challengeResponse.data)

        // Step 3: Generate our random values
        let rndIFDValue = try rndIFD.map { Data($0) } ?? CryptoUtils.secureRandomBytes(count: 8)
        let kIFDValue = try kIFD.map { Data($0) } ?? CryptoUtils.secureRandomBytes(count: 16)

        // Step 4: Build concatenation S = rndIFD || rndICC || kIFD
        var s = Data()
        s.append(rndIFDValue)
        s.append(rndICC)
        s.append(kIFDValue)

        // Step 5: Encrypt S with Kenc using 3DES-CBC (IV=0)
        let eifd = try CryptoUtils.tripleDESEncrypt(key: kenc, message: s)

        // Step 6: Compute MAC over padded eifd
        let paddedEifd = ISO9797Padding.pad(eifd, blockSize: 8)
        let mifd = try ISO9797MAC.mac(key: kmac, message: paddedEifd)

        // Step 7: MUTUAL AUTHENTICATE with eifd || mifd (40 bytes)
        var authData = eifd
        authData.append(mifd)

        NFCLog.debug("MUTUAL AUTHENTICATE", source: "Passport")
        let authAPDU = CommandAPDU.mutualAuthenticate(data: authData)
        let authResponse = try await transport.sendAPDU(authAPDU)

        guard authResponse.isSuccess else {
            throw NFCError.bacFailed("MUTUAL AUTHENTICATE failed: SW=\(String(format: "%04X", authResponse.statusWord))")
        }
        guard authResponse.data.count == 40 else {
            throw NFCError.bacFailed("MUTUAL AUTHENTICATE returned \(authResponse.data.count) bytes, expected 40")
        }

        // Step 8: Parse response — encrypted (32 bytes) || MAC (8 bytes)
        let authResponseData = Data(authResponse.data)
        let responseEncrypted = Data(authResponseData.prefix(32))
        let responseMac = Data(authResponseData.suffix(8))

        // Verify response MAC
        let paddedResponseEncrypted = ISO9797Padding.pad(responseEncrypted, blockSize: 8)
        let computedMac = try ISO9797MAC.mac(key: kmac, message: paddedResponseEncrypted)
        guard computedMac == responseMac else {
            throw NFCError.bacFailed("Response MAC verification failed")
        }

        // Decrypt response
        let responseDecrypted = try Data(CryptoUtils.tripleDESDecrypt(key: kenc, message: responseEncrypted))
        guard responseDecrypted.count == 32 else {
            throw NFCError.bacFailed("MUTUAL AUTHENTICATE plaintext has \(responseDecrypted.count) bytes, expected 32")
        }

        // Parse decrypted response: rndICC' (8) || rndIFD' (8) || kICC (16)
        let rndICCPrime = Data(responseDecrypted[0 ..< 8])
        let rndIFDPrime = Data(responseDecrypted[8 ..< 16])
        let kICC = Data(responseDecrypted[16 ..< 32])

        // Verify rndICC matches
        guard rndICCPrime == rndICC else {
            throw NFCError.bacFailed("rndICC mismatch in response")
        }
        // Verify rndIFD matches
        guard rndIFDPrime == rndIFDValue else {
            throw NFCError.bacFailed("rndIFD mismatch in response")
        }

        // Step 9: Compute new session keys
        // Kseed_new = kIFD XOR kICC
        var kseedNew = Data(count: 16)
        for i in 0 ..< 16 {
            kseedNew[i] = kIFDValue[i] ^ kICC[i]
        }

        let ksEnc = KeyDerivation.deriveKey(keySeed: kseedNew, mode: .enc)
        let ksMac = KeyDerivation.deriveKey(keySeed: kseedNew, mode: .mac)

        // Step 10: Compute initial SSC = rndICC[4..<8] || rndIFD[4..<8]
        var ssc = Data()
        ssc.append(Data(rndICC[4 ..< 8]))
        ssc.append(Data(rndIFDValue[4 ..< 8]))

        NFCLog.info("BAC succeeded, secure messaging established", source: "Passport")

        return SecureMessagingTransport(
            transport: transport,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc
        )
    }
}
