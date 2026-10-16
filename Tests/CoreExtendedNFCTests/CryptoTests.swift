// Crypto test suite for CoreExtendedNFC.
//
// ## References
// - ICAO Doc 9303 Part 11, Appendix D.1: BAC key derivation test vectors
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - NIST FIPS 197 (AES): https://csrc.nist.gov/pubs/fips/197/final
// - NIST FIPS 180-4 (SHA-1, SHA-256): https://csrc.nist.gov/pubs/fips/180-4/upd1/final
// - NIST SP 800-38B / RFC 4493 (AES-CMAC): https://www.rfc-editor.org/rfc/rfc4493
// - ISO/IEC 9797-1:2011 MAC Algorithm 3 (Retail MAC)
// - ISO/IEC 9797-1:2011 Padding Method 2
// - JMRTD (Java eMRTD) reference implementation:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/Util.java
@testable import CoreExtendedNFC
import Foundation
import Testing

struct CryptoTests {
    // MARK: - 3DES

    @Test
    func `3DES-CBC encrypt and decrypt round-trip`() throws {
        let key = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ])
        let plaintext = Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])

        let encrypted = try CryptoUtils.tripleDESEncrypt(key: key, message: plaintext)
        #expect(encrypted.count == 8)
        #expect(encrypted != plaintext)

        let decrypted = try CryptoUtils.tripleDESDecrypt(key: key, message: encrypted)
        #expect(decrypted == plaintext)
    }

    @Test
    func `3DES 16-byte key auto-expanded to 24 bytes`() throws {
        // 16-byte key should produce same result as 24-byte K1||K2||K1
        let key16 = Data([
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF,
            0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2,
        ])
        let key24 = key16 + Data(key16.prefix(8))

        let message = Data(repeating: 0xAA, count: 16)
        let enc16 = try CryptoUtils.tripleDESEncrypt(key: key16, message: message)
        let enc24 = try CryptoUtils.tripleDESEncrypt(key: key24, message: message)
        #expect(enc16 == enc24)
    }

    // MARK: - DES

    @Test
    func `DES-CBC encrypt and decrypt round-trip`() throws {
        let key = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let plaintext = Data([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48])

        let encrypted = try CryptoUtils.desEncrypt(key: key, message: plaintext)
        let decrypted = try CryptoUtils.desDecrypt(key: key, message: encrypted)
        #expect(decrypted == plaintext)
    }

    @Test
    func `DES-ECB encrypt and decrypt round-trip`() throws {
        let key = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let plaintext = Data([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48])

        let encrypted = try CryptoUtils.desECBEncrypt(key: key, message: plaintext)
        let decrypted = try CryptoUtils.desECBDecrypt(key: key, message: encrypted)
        #expect(decrypted == plaintext)
    }

    // MARK: - AES

    @Test
    func `AES-CBC encrypt and decrypt round-trip (128-bit key)`() throws {
        let key = Data(repeating: 0x00, count: 16)
        let iv = Data(repeating: 0x00, count: 16)
        let plaintext = Data(repeating: 0x42, count: 32) // 2 blocks

        let encrypted = try CryptoUtils.aesEncrypt(key: key, message: plaintext, iv: iv)
        let decrypted = try CryptoUtils.aesDecrypt(key: key, message: encrypted, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test
    func `AES-ECB encrypt known vector — all-zero key and block`() throws {
        // AES-128 ECB, key = all zeros, plaintext = all zeros (well-known value 66E94BD4…;
        // not from FIPS 197 — the FIPS 197 Appendix B/C vectors are in Vectors/CryptoVectorTests.swift)
        // Reference: https://csrc.nist.gov/pubs/fips/197/final
        let key = Data(repeating: 0x00, count: 16)
        let plaintext = Data(repeating: 0x00, count: 16)

        let encrypted = try CryptoUtils.aesECBEncrypt(key: key, message: plaintext)
        #expect(encrypted.count == 16)
        // AES-128(0...0, 0...0) = 66E94BD4EF8A2C3B884CFA59CA342B2E
        let expected = Data([
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B,
            0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E,
        ])
        #expect(encrypted == expected)
    }

    // MARK: - ISO 9797 Padding

    // Reference: ISO/IEC 9797-1:2011 Padding Method 2

    @Test
    func `ISO 9797 pad appends 0x80 and fills to block size`() {
        let data = Data([0x01, 0x02, 0x03])
        let padded = ISO9797Padding.pad(data, blockSize: 8)
        #expect(padded.count == 8)
        #expect(padded == Data([0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00]))
    }

    @Test
    func `ISO 9797 pad full block adds extra block`() {
        let data = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let padded = ISO9797Padding.pad(data, blockSize: 8)
        #expect(padded.count == 16)
        #expect(padded[8] == 0x80)
        #expect(padded[9 ..< 16] == Data(repeating: 0x00, count: 7))
    }

    @Test
    func `ISO 9797 unpad removes padding correctly`() {
        let padded = Data([0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00])
        let unpadded = ISO9797Padding.unpad(padded)
        #expect(unpadded == Data([0x01, 0x02, 0x03]))
    }

    @Test
    func `ISO 9797 unpad with no padding returns data as-is`() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let result = ISO9797Padding.unpad(data)
        #expect(result == data)
    }

    // MARK: - ISO 9797 MAC

    // Reference: ISO/IEC 9797-1:2011, Algorithm 3 (Retail MAC)
    // Split 16-byte key into Ka||Kb, DES-CBC with Ka, decrypt last block with Kb, encrypt with Ka

    @Test
    func `ISO 9797-1 MAC Algorithm 3 requires 16-byte key`() throws {
        let badKey = Data(repeating: 0x01, count: 8)
        let message = ISO9797Padding.pad(Data(repeating: 0xAA, count: 8), blockSize: 8)

        #expect(throws: NFCError.self) {
            _ = try ISO9797MAC.mac(key: badKey, message: message)
        }
    }

    @Test
    func `ISO 9797-1 MAC returns 8 bytes`() throws {
        let key = Data(repeating: 0x01, count: 16)
        let message = ISO9797Padding.pad(Data(repeating: 0xAA, count: 8), blockSize: 8)
        let mac = try ISO9797MAC.mac(key: key, message: message)
        #expect(mac.count == 8)
    }

    @Test
    func `ISO 9797-1 MAC deterministic`() throws {
        let key = Data(repeating: 0x42, count: 16)
        let message = ISO9797Padding.pad(Data([0x01, 0x02, 0x03, 0x04]), blockSize: 8)
        let mac1 = try ISO9797MAC.mac(key: key, message: message)
        let mac2 = try ISO9797MAC.mac(key: key, message: message)
        #expect(mac1 == mac2)
    }

    // MARK: - AES-CMAC

    // All 4 AES-CMAC vectors from RFC 4493 Section 4:
    // https://www.rfc-editor.org/rfc/rfc4493#section-4

    @Test
    func `AES-CMAC RFC 4493 test vector 1: empty message`() throws {
        // RFC 4493 Section 4, Example 1: key = 2b7e1516...
        let key = Data([
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ])
        let mac = try AESCMAC.mac(key: key, message: Data())
        let expected = Data([
            0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28,
            0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67, 0x46,
        ])
        #expect(mac == expected)
    }

    @Test
    func `AES-CMAC RFC 4493 test vector 2: 16-byte message`() throws {
        let key = Data([
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ])
        let message = Data([
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        ])
        let mac = try AESCMAC.mac(key: key, message: message)
        let expected = Data([
            0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44,
            0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C,
        ])
        #expect(mac == expected)
    }

    @Test
    func `AES-CMAC RFC 4493 test vector 3: 40-byte message`() throws {
        let key = Data([
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ])
        let message = Data([
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
            0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
        ])
        let mac = try AESCMAC.mac(key: key, message: message)
        let expected = Data([
            0xDF, 0xA6, 0x67, 0x47, 0xDE, 0x9A, 0xE6, 0x30,
            0x30, 0xCA, 0x32, 0x61, 0x14, 0x97, 0xC8, 0x27,
        ])
        #expect(mac == expected)
    }

    @Test
    func `AES-CMAC RFC 4493 test vector 4: 64-byte message`() throws {
        let key = Data([
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        ])
        let message = Data([
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
            0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
            0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
            0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
            0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
            0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
        ])
        let mac = try AESCMAC.mac(key: key, message: message)
        let expected = Data([
            0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92,
            0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE,
        ])
        #expect(mac == expected)
    }

    // MARK: - Hashing

    @Test
    func `SHA-1 produces 20-byte digest`() {
        let hash = HashUtils.sha1(Data("test".utf8))
        #expect(hash.count == 20)
    }

    @Test
    func `SHA-1 known value — NIST FIPS 180-4 example`() {
        // SHA-1("abc") from the NIST CSRC examples for FIPS 180-4
        // Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
        let hash = HashUtils.sha1(Data("abc".utf8))
        let expected = Data([
            0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
            0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
            0x9C, 0xD0, 0xD8, 0x9D,
        ])
        #expect(hash == expected)
    }

    @Test
    func `SHA-256 known value — NIST FIPS 180-4 example`() {
        // SHA-256("abc") from the NIST CSRC examples for FIPS 180-4
        // Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        let hash = HashUtils.sha256(Data("abc".utf8))
        let expected = Data([
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
            0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
        ])
        #expect(hash == expected)
    }

    @Test
    func `SHA-384 produces 48-byte digest`() {
        let hash = HashUtils.sha384(Data("test".utf8))
        #expect(hash.count == 48)
    }

    @Test
    func `SHA-512 produces 64-byte digest`() {
        let hash = HashUtils.sha512(Data("test".utf8))
        #expect(hash.count == 64)
    }

    // MARK: - Key Derivation (ICAO 9303 Part 11 Appendix D test vectors)

    // Reference: ICAO Doc 9303 Part 11, Appendix D.1 — Worked Example
    // https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
    // Cross-ref: JMRTD Util.computeKeySeedForBAC()
    // https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/Util.java

    @Test
    func `ICAO 9303 Kseed derivation from MRZ key`() {
        // From ICAO 9303 Part 11, Appendix D.1
        // Document number: L898902C<, DOB: 690806, DOE: 940623
        // MRZ Key: L898902C<369080619406236
        let mrzKey = "L898902C<369080619406236"
        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)

        // Expected Kseed from ICAO 9303 Part 11, Appendix D.1:
        // SHA-1(MRZKey) = 239AB9CB282DAF66231DC5A4DF6BFBAEDF477565
        // Kseed = first 16 bytes = 239AB9CB282DAF66231DC5A4DF6BFBAE
        let expected = Data([
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66,
            0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE,
        ])
        #expect(kseed == expected)
    }

    @Test
    func `ICAO 9303 derive encryption key — Appendix D.1 Kenc`() {
        // ICAO 9303 Part 11, Appendix D.1: Kseed → Kenc
        // Kseed = 239AB9CB282DAF66231DC5A4DF6BFBAE
        // Expected Kenc = AB94FDECF2674FDFB9B391F85D7F76F2
        let keySeed = Data([
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66,
            0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE,
        ])
        let kenc = KeyDerivation.deriveKey(keySeed: keySeed, mode: .enc)
        #expect(kenc.count == 16)

        // The expected Kenc from ICAO 9303 D.1:
        let expected = Data([
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF,
            0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2,
        ])
        #expect(kenc == expected)
    }

    @Test
    func `ICAO 9303 derive MAC key — Appendix D.1 Kmac`() {
        // Expected Kmac = 7962D9ECE03D1ACD4C76089DCE131543
        let keySeed = Data([
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66,
            0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE,
        ])
        let kmac = KeyDerivation.deriveKey(keySeed: keySeed, mode: .mac)
        #expect(kmac.count == 16)

        // The expected Kmac from ICAO 9303 D.1:
        let expected = Data([
            0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD,
            0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43,
        ])
        #expect(kmac == expected)
    }

    @Test
    func `DES parity adjustment`() {
        // Each byte should have odd number of 1-bits after parity adjustment
        let input = Data([0x00, 0xFF, 0xAA, 0x55, 0x80, 0x01, 0x7E, 0x3C])
        let adjusted = KeyDerivation.adjustParity(input)
        for byte in adjusted {
            #expect(byte.nonzeroBitCount % 2 == 1, "Byte 0x\(String(format: "%02X", byte)) should have odd parity")
        }
    }

    // MARK: - ICAO 9303 Full KDF from MRZ

    @Test
    func `ICAO 9303 full key derivation pipeline`() {
        // ICAO 9303 Part 11, Appendix D.1 official worked example
        // Document number: L898902C<, DOB: 690806, DOE: 940623
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "L898902C<",
            dateOfBirth: "690806",
            dateOfExpiry: "940623"
        )

        // The check digits should match ICAO example: doc=3, dob=1, doe=6
        #expect(mrzKey.contains("L898902C<3"))
        #expect(mrzKey.contains("6908061"))
        #expect(mrzKey.contains("9406236"))
        #expect(mrzKey == "L898902C<369080619406236")

        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let expectedKseed = Data([
            0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66,
            0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE,
        ])
        #expect(kseed == expectedKseed)

        let kenc = KeyDerivation.deriveKey(keySeed: kseed, mode: .enc)
        let kmac = KeyDerivation.deriveKey(keySeed: kseed, mode: .mac)
        let expectedKenc = Data([
            0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF,
            0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2,
        ])
        let expectedKmac = Data([
            0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD,
            0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43,
        ])
        #expect(kenc == expectedKenc)
        #expect(kmac == expectedKmac)

        // Verify keys are deterministic (same inputs → same outputs)
        let kseed2 = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let kenc2 = KeyDerivation.deriveKey(keySeed: kseed2, mode: .enc)
        let kmac2 = KeyDerivation.deriveKey(keySeed: kseed2, mode: .mac)
        #expect(kenc == kenc2)
        #expect(kmac == kmac2)

        // Verify enc and mac keys are different from each other
        #expect(kenc != kmac)

        // Verify DES parity on derived keys
        for i in 0 ..< kenc.count {
            #expect(kenc[i].nonzeroBitCount % 2 == 1, "Kenc byte \(i) should have odd parity")
        }
        for i in 0 ..< kmac.count {
            #expect(kmac[i].nonzeroBitCount % 2 == 1, "Kmac byte \(i) should have odd parity")
        }
    }
}
