import CommonCrypto
import Foundation

/// Hashing utilities using CommonCrypto (available on all Apple platforms without availability restrictions).
public enum HashUtils {
    /// SHA-1 hash (20 bytes). Used by BAC key derivation (ICAO 9303).
    public static func sha1(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            digest.withUnsafeMutableBytes { digestPtr in
                _ = CC_SHA1(dataPtr.baseAddress, CC_LONG(data.count), digestPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return digest
    }

    /// SHA-256 hash (32 bytes).
    public static func sha256(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            digest.withUnsafeMutableBytes { digestPtr in
                _ = CC_SHA256(dataPtr.baseAddress, CC_LONG(data.count), digestPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return digest
    }

    /// SHA-224 hash (28 bytes).
    public static func sha224(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            digest.withUnsafeMutableBytes { digestPtr in
                _ = CC_SHA224(dataPtr.baseAddress, CC_LONG(data.count), digestPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return digest
    }

    /// SHA-384 hash (48 bytes).
    public static func sha384(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA384_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            digest.withUnsafeMutableBytes { digestPtr in
                _ = CC_SHA384(dataPtr.baseAddress, CC_LONG(data.count), digestPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return digest
    }

    /// SHA-512 hash (64 bytes).
    public static func sha512(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            digest.withUnsafeMutableBytes { digestPtr in
                _ = CC_SHA512(dataPtr.baseAddress, CC_LONG(data.count), digestPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return digest
    }
}
