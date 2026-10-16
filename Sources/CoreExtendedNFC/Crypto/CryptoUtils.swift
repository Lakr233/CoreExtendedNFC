import CommonCrypto
import Foundation

/// Low-level symmetric cipher wrappers around CommonCrypto.
/// All functions are static, stateless, and safe for concurrent use.
public enum CryptoUtils {
    // MARK: - Triple DES

    /// 3DES-CBC encrypt. Key must be 16 bytes (2-key) or 24 bytes (3-key).
    /// 16-byte keys are automatically expanded to 24 bytes (K1||K2||K1).
    /// No padding is applied — input length must be a multiple of 8.
    static func tripleDESEncrypt(key: Data, message: Data, iv: Data = Data(count: 8)) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithm3DES),
            key: expandDESKey(key),
            iv: iv,
            data: message
        )
    }

    /// 3DES-CBC decrypt.
    static func tripleDESDecrypt(key: Data, message: Data, iv: Data = Data(count: 8)) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCDecrypt),
            algorithm: CCAlgorithm(kCCAlgorithm3DES),
            key: expandDESKey(key),
            iv: iv,
            data: message
        )
    }

    // MARK: - DES

    /// DES-CBC encrypt. Key must be 8 bytes.
    static func desEncrypt(key: Data, message: Data, iv: Data = Data(count: 8)) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithmDES),
            key: key,
            iv: iv,
            data: message
        )
    }

    /// DES-CBC decrypt. Key must be 8 bytes.
    static func desDecrypt(key: Data, message: Data, iv: Data = Data(count: 8)) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCDecrypt),
            algorithm: CCAlgorithm(kCCAlgorithmDES),
            key: key,
            iv: iv,
            data: message
        )
    }

    /// DES-ECB encrypt. Processes each 8-byte block independently.
    static func desECBEncrypt(key: Data, message: Data) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithmDES),
            key: key,
            iv: Data(),
            data: message,
            options: CCOptions(kCCOptionECBMode)
        )
    }

    /// DES-ECB decrypt. Processes each 8-byte block independently.
    static func desECBDecrypt(key: Data, message: Data) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCDecrypt),
            algorithm: CCAlgorithm(kCCAlgorithmDES),
            key: key,
            iv: Data(),
            data: message,
            options: CCOptions(kCCOptionECBMode)
        )
    }

    // MARK: - AES

    /// AES-CBC encrypt. Key can be 16, 24, or 32 bytes. No padding applied.
    static func aesEncrypt(key: Data, message: Data, iv: Data) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithmAES),
            key: key,
            iv: iv,
            data: message
        )
    }

    /// AES-CBC decrypt. Key can be 16, 24, or 32 bytes. No padding applied.
    static func aesDecrypt(key: Data, message: Data, iv: Data) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCDecrypt),
            algorithm: CCAlgorithm(kCCAlgorithmAES),
            key: key,
            iv: iv,
            data: message
        )
    }

    /// AES-ECB encrypt. Processes each 16-byte block independently.
    static func aesECBEncrypt(key: Data, message: Data) throws -> Data {
        try ccCrypt(
            operation: CCOperation(kCCEncrypt),
            algorithm: CCAlgorithm(kCCAlgorithmAES),
            key: key,
            iv: Data(),
            data: message,
            options: CCOptions(kCCOptionECBMode)
        )
    }

    // MARK: - Comparison

    /// Compare two byte strings in time that depends only on their lengths.
    ///
    /// Use it for MACs, authentication tokens, recovered digests and challenge echoes,
    /// so the position of the first differing byte cannot be learnt from timing.
    /// Inputs may be sliced `Data`; only their bytes are compared.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }

    // MARK: - Internal

    /// Generate cryptographically random bytes, throwing if the system generator fails.
    ///
    /// Protocol nonces (BAC RND.IFD/K.IFD, AA challenges) must never fall back to
    /// all-zero bytes, so callers in those paths use this variant.
    static func secureRandomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { ptr -> Int32 in
            guard let baseAddress = ptr.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        guard status == errSecSuccess else {
            throw NFCError.cryptoError("SecRandomCopyBytes failed with status \(status)")
        }
        return bytes
    }

    /// Expand a 16-byte 2-key 3DES key to 24-byte 3-key format: K1||K2||K1.
    private static func expandDESKey(_ key: Data) -> Data {
        if key.count == 16 {
            return key + key.prefix(8)
        }
        return key
    }

    /// Perform a CCCrypt operation.
    private static func ccCrypt(
        operation: CCOperation,
        algorithm: CCAlgorithm,
        key: Data,
        iv: Data,
        data: Data,
        options: CCOptions = 0
    ) throws -> Data {
        let outputSize = data.count + kCCBlockSize3DES
        var outputBuffer = Data(count: outputSize)
        var numBytesEncrypted: size_t = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    outputBuffer.withUnsafeMutableBytes { outputBytes in
                        CCCrypt(
                            operation,
                            algorithm,
                            options,
                            keyBytes.baseAddress,
                            key.count,
                            iv.isEmpty ? nil : ivBytes.baseAddress,
                            dataBytes.baseAddress,
                            data.count,
                            outputBytes.baseAddress,
                            outputSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw NFCError.cryptoError("CCCrypt failed with status \(status)")
        }

        return outputBuffer.prefix(numBytesEncrypted)
    }
}
