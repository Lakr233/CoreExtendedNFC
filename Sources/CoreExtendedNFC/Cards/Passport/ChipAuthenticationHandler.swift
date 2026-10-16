import Foundation

/// Chip Authentication (CA) handler.
///
/// CA authenticates the chip by key agreement with the public key advertised in DG14.
/// A completed exchange replaces the BAC session keys with stronger session keys.
///
/// Command sequence (ICAO 9303-11 §6.2.4, BSI TR-03110-3 B.11):
/// - 3DES (`id-CA-*-3DES-CBC-CBC`): MSE:Set KAT `00 22 41 A6` with `91 <PK_PCD> [84 <keyID>]`.
/// - AES (`id-CA-*-AES-CBC-CMAC-*`): MSE:Set AT `00 22 41 A4` with `80 <OID> [84 <keyID>]`,
///   then GENERAL AUTHENTICATE `00 86 00 00` with `7C { 80 <PK_PCD> }`.
/// - Afterwards both sides restart secure messaging with `KDF(K, 1)`, `KDF(K, 2)` and SSC = 0.
///
/// References: ICAO 9303 Part 11 §6.2, BSI TR-03110, JMRTD `ChipAuthenticationHandler`.
public enum ChipAuthenticationHandler {
    /// Perform Chip Authentication and return a new Secure Messaging transport.
    ///
    /// Ephemeral ECDH key agreement is not implemented yet. A GENERAL AUTHENTICATE or
    /// MSE:Set KAT carrying a public key would make the chip switch to session keys this
    /// library cannot derive, which would break the current secure messaging session.
    /// This method therefore only selects the CA protocol (AES variants) and returns `nil`,
    /// keeping the current BAC/PACE session intact.
    ///
    /// - Parameters:
    ///   - securityInfos: Parsed DG14 SecurityInfos.
    ///   - transport: Current Secure Messaging transport.
    /// - Returns: A new `SecureMessagingTransport` with stronger session keys,
    ///   or nil if CA is not supported or not completed.
    public static func performCA(
        securityInfos: SecurityInfos,
        transport: SecureMessagingTransport
    ) async throws -> SecureMessagingTransport? {
        // Find CA info and matching public key
        guard let caInfo = securityInfos.chipAuthInfos.first,
              findMatchingPublicKey(
                  caInfo: caInfo,
                  publicKeys: securityInfos.chipAuthPublicKeyInfos
              ) != nil
        else {
            return nil
        }

        guard let caProtocol = caInfo.securityProtocol else {
            throw NFCError.secureMessagingError("Unknown CA protocol OID: \(caInfo.protocolOID)")
        }

        // Only ECDH-based CA with AES uses MSE:Set AT; 3DES CA carries the ephemeral key in
        // MSE:Set KAT, which requires the (not yet implemented) key agreement.
        guard caProtocol.isECDH, caProtocol.isAES else {
            return nil
        }

        let mseAPDU = mseSetATForCA(oid: encodeOID(caInfo.protocolOID), keyID: caInfo.keyID)
        let mseResponse = try await transport.sendAPDU(mseAPDU)

        // 6A88 = referenced data not found — the chip does not support the selected key.
        if !mseResponse.isSuccess, mseResponse.statusWord != 0x6A88 {
            throw NFCError.secureMessagingError(
                "MSE:Set AT for CA failed: SW=\(String(format: "%04X", mseResponse.statusWord))"
            )
        }

        // ECDH key agreement is still stubbed, so CA keeps the existing session.
        return nil
    }

    // MARK: - APDU Builders

    /// MSE:Set AT for Chip Authentication (AES): `00 22 41 A4`, data `80 <OID> [84 <keyID>]`.
    ///
    /// P1 = 0x41 (set for internal authentication / computation), not 0xC1 which selects PACE.
    public static func mseSetATForCA(oid: Data, keyID: Int?) -> CommandAPDU {
        var data = ASN1Parser.encodeTLV(tag: 0x80, value: oid)
        if let keyID {
            data.append(ASN1Parser.encodeTLV(tag: 0x84, value: encodeKeyReference(keyID)))
        }
        return CommandAPDU(cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA4, data: data)
    }

    /// MSE:Set KAT for Chip Authentication (3DES): `00 22 41 A6`, data `91 <PK_PCD> [84 <keyID>]`.
    public static func mseSetKATForCA(ephemeralPublicKey: Data, keyID: Int?) -> CommandAPDU {
        var data = ASN1Parser.encodeTLV(tag: 0x91, value: ephemeralPublicKey)
        if let keyID {
            data.append(ASN1Parser.encodeTLV(tag: 0x84, value: encodeKeyReference(keyID)))
        }
        return CommandAPDU(cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA6, data: data)
    }

    /// GENERAL AUTHENTICATE for Chip Authentication (AES): data `7C { 80 <PK_PCD> }`.
    public static func generalAuthenticateForCA(ephemeralPublicKey: Data) -> CommandAPDU {
        let dynamicAuthData = ASN1Parser.encodeTLV(
            tag: 0x7C,
            value: ASN1Parser.encodeTLV(tag: 0x80, value: ephemeralPublicKey)
        )
        return CommandAPDU.generalAuthenticate(data: dynamicAuthData, isLast: true)
    }

    // MARK: - Helpers

    /// Find the ChipAuthenticationPublicKeyInfo that matches the CA info.
    public static func findMatchingPublicKey(
        caInfo: ChipAuthenticationInfo,
        publicKeys: [ChipAuthenticationPublicKeyInfo]
    ) -> ChipAuthenticationPublicKeyInfo? {
        if let keyID = caInfo.keyID {
            return publicKeys.first { $0.keyID == keyID }
        }
        return publicKeys.first
    }

    /// Encode a key identifier as the minimal big-endian unsigned byte string.
    public static func encodeKeyReference(_ keyID: Int) -> Data {
        var value = UInt64(truncatingIfNeeded: keyID)
        var bytes: [UInt8] = []
        repeat {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        } while value > 0
        return Data(bytes)
    }

    /// Encode an OID string (dotted decimal) to DER content octets (X.690 §8.19).
    ///
    /// Returns empty data when the string is not a valid OID.
    public static func encodeOID(_ oidString: String) -> Data {
        let parts = oidString.split(separator: ".", omittingEmptySubsequences: false)
        let components = parts.compactMap { UInt64($0) }
        guard components.count >= 2, components.count == parts.count else { return Data() }

        let first = components[0]
        let second = components[1]
        // X.690 §8.19.4: the first arc is 0, 1 or 2; arcs 0 and 1 allow second < 40.
        guard first <= 2, first == 2 || second < 40 else { return Data() }
        let (combined, overflow) = (first * 40).addingReportingOverflow(second)
        guard !overflow else { return Data() }

        var encoded = Data(base128(combined))
        for component in components.dropFirst(2) {
            encoded.append(contentsOf: base128(component))
        }
        return encoded
    }

    /// Base-128 encoding of one OID subidentifier with continuation bits.
    public static func base128(_ value: UInt64) -> [UInt8] {
        var remaining = value >> 7
        var bytes: [UInt8] = [UInt8(value & 0x7F)]
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
            remaining >>= 7
        }
        return bytes
    }

    /// Derive session keys from the CA shared secret.
    ///
    /// Uses the ICAO 9303-11 §9.7.1 KDF: SHA-1 for 3DES (parity adjusted) and AES-128,
    /// SHA-256 for AES-192/256. KSenc = KDF(K, 1), KSmac = KDF(K, 2).
    public static func deriveCASessionKeys(
        sharedSecret: Data,
        mode: SMEncryptionMode
    ) -> (ksEnc: Data, ksMac: Data) {
        (
            ksEnc: KeyDerivation.deriveKey(keySeed: sharedSecret, counter: 1, mode: mode),
            ksMac: KeyDerivation.deriveKey(keySeed: sharedSecret, counter: 2, mode: mode)
        )
    }
}
