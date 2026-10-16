import Foundation

/// ISO/IEC 9797-1 MAC Algorithm 3 (Retail MAC) used by ICAO 9303 BAC and
/// 3DES-based secure messaging.
///
/// Reference: ISO/IEC 9797-1:2011, Algorithm 3
/// Cross-ref: JMRTD Util.mac() in Util.java
/// https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/Util.java
public enum ISO9797MAC {
    /// Compute an 8-byte MAC over a message already padded with ISO 9797-1 Method 2.
    /// Key must be 16 bytes.
    public static func mac(key: Data, message: Data) throws -> Data {
        guard key.count == 16 else {
            throw NFCError.cryptoError("ISO 9797 MAC requires 16-byte key, got \(key.count)")
        }
        guard !message.isEmpty, message.count % 8 == 0 else {
            throw NFCError.cryptoError("ISO 9797 MAC message must be padded to 8-byte blocks")
        }

        let ka = key.prefix(8)
        let kb = key.suffix(8)

        let cbcResult = try CryptoUtils.desEncrypt(key: ka, message: message)

        let lastBlock = cbcResult.suffix(8)

        let decrypted = try CryptoUtils.desECBDecrypt(key: Data(kb), message: lastBlock)

        return try CryptoUtils.desECBEncrypt(key: Data(ka), message: decrypted)
    }
}
