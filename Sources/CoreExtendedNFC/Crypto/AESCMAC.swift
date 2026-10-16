import Foundation

/// AES-CMAC per RFC 4493 for ICAO 9303 AES-based secure messaging.
/// Uses AES-ECB from `CryptoUtils`.
/// References: NIST SP 800-38B, RFC 4493.
/// https://www.rfc-editor.org/rfc/rfc4493
/// https://csrc.nist.gov/pubs/sp/800/38/b/final
public enum AESCMAC {
    /// Compute a 16-byte AES-CMAC. Key must be 16, 24, or 32 bytes.
    public static func mac(key: Data, message: Data) throws -> Data {
        let (k1, k2) = try generateSubkeys(key: key)

        let blockSize = 16
        let n = message.isEmpty ? 1 : (message.count + blockSize - 1) / blockSize
        let isComplete = !message.isEmpty && (message.count % blockSize == 0)

        var lastBlock: Data
        if isComplete {
            let start = message.count - blockSize
            lastBlock = Data(message[start...])
            lastBlock = xor(lastBlock, k1)
        } else {
            let start = (n - 1) * blockSize
            var partial = Data(message[start...])
            partial.append(0x80)
            while partial.count < blockSize {
                partial.append(0x00)
            }
            lastBlock = xor(partial, k2)
        }

        var x = Data(count: blockSize)
        for i in 0 ..< n - 1 {
            let blockStart = i * blockSize
            let block = Data(message[blockStart ..< blockStart + blockSize])
            x = try CryptoUtils.aesECBEncrypt(key: key, message: xor(x, block))
        }
        x = try CryptoUtils.aesECBEncrypt(key: key, message: xor(x, lastBlock))

        return x
    }

    // MARK: - Private

    /// Generate CMAC subkeys K1 and K2 per RFC 4493 section 2.3.
    public static func generateSubkeys(key: Data) throws -> (Data, Data) {
        let zeroBlock = Data(count: 16)
        let l = try CryptoUtils.aesECBEncrypt(key: key, message: zeroBlock)

        let k1 = shiftLeft(l)
        let k1Final: Data = if l[0] & 0x80 != 0 {
            xor(k1, rb)
        } else {
            k1
        }

        let k2 = shiftLeft(k1Final)
        let k2Final: Data = if k1Final[0] & 0x80 != 0 {
            xor(k2, rb)
        } else {
            k2
        }

        return (k1Final, k2Final)
    }

    /// Rb constant for 128-bit CMAC.
    public static let rb = Data([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
    ])

    /// Left-shift a 16-byte block by 1 bit.
    public static func shiftLeft(_ data: Data) -> Data {
        var output = Data(count: data.count)
        for i in 0 ..< data.count {
            output[i] = data[i] << 1
            if i + 1 < data.count {
                output[i] |= (data[i + 1] >> 7)
            }
        }
        return output
    }

    /// XOR two equal-length Data values.
    public static func xor(_ a: Data, _ b: Data) -> Data {
        var result = Data(count: a.count)
        for i in 0 ..< a.count {
            result[i] = a[i] ^ b[i]
        }
        return result
    }
}
