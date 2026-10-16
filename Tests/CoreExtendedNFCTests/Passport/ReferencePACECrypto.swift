@testable import CoreExtendedNFC
import CryptoKit
import Foundation

/// Reference PACE computations for simulated chips, written directly from
/// ICAO 9303-11 §9.7.1 / §9.7.3 / §4.4.3.4 with CryptoKit hashing so a simulated chip
/// does not share code with `PACEHandler` (the functions under test). AES-CMAC itself is
/// the RFC 4493-validated primitive (see CryptoTests).
enum ReferencePACECrypto {
    static func sha1(_ data: Data) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    /// KDF(K, c) for AES modes: SHA-1 → 16 bytes (AES-128), SHA-256 → 24/32 bytes.
    static func kdf(seed: Data, counter: UInt8, mode: SMEncryptionMode) -> Data {
        let input = seed + Data([0x00, 0x00, 0x00, counter])
        switch mode {
        case .aes128:
            return Data(Data(Insecure.SHA1.hash(data: input)).prefix(16))
        case .aes192:
            return Data(Data(SHA256.hash(data: input)).prefix(24))
        case .aes256:
            return Data(Data(SHA256.hash(data: input)).prefix(32))
        case .tripleDES:
            preconditionFailure("The simulated PACE chip only implements AES modes")
        }
    }

    /// T = CMAC(KSmac, 7F49 { 06 OID, 86 PK }) truncated to 8 bytes — no extra padding.
    static func authToken(ksMac: Data, publicKey: Data, oid: Data) throws -> Data {
        var body = Data([0x06, UInt8(oid.count)]) + oid
        body += Data([0x86]) + derLength(publicKey.count) + publicKey
        let input = Data([0x7F, 0x49]) + derLength(body.count) + body
        return try Data(AESCMAC.mac(key: ksMac, message: input).prefix(8))
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        if length <= 0xFF { return Data([0x81, UInt8(length)]) }
        return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
    }
}
