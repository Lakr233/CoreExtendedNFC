// Known-answer tests for the crypto primitives, with bytes copied from the
// primary sources. Vectors already asserted elsewhere are not repeated here:
//
// - CryptoTests: AES-128 all-zero key/plaintext, SHA-1("abc"), SHA-256("abc"),
//   RFC 4493 §4 Examples 1-4 (AES-128 CMAC, Mlen = 0/16/40/64),
//   ICAO 9303-11 App. D.1 Kseed/Kenc/Kmac.
// - AESCMACTests: RFC 4493 §4 Example 3 (40-byte message).
// - PassportConformanceTests / BACTests: ICAO 9303-11 App. D.3/D.4 retail MAC
//   values (M.IFD, M.IC, DO'8E' CCs) and the KDF session keys (App. D.3, G.1).
//
// ## Sources
// - [FIPS197]    NIST FIPS 197 (2001), Appendix C "Example Vectors"
//                https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
//                (FIPS 197-upd1 Appendix C now refers to the CSRC examples page)
// - [FIPS197u1]  NIST FIPS 197-upd1 (2023), Appendix B "Cipher Example"
//                docs/references/NIST.FIPS.197-upd1.pdf
// - [CSRC-SHA]   NIST CSRC "Examples with Intermediate Values", SHA1.pdf,
//                SHA224.pdf, SHA256.pdf, SHA384.pdf, SHA512.pdf (FIPS 180-4)
//                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
// - [CSRC-CMAC]  NIST CSRC "Examples with Intermediate Values", AES_CMAC.pdf
//                (SP 800-38B Appendix D points here since the 2016 update)
//                https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
// - [RFC4493]    RFC 4493 §4 "Test Vectors", docs/references/rfc4493.txt
// - [ICAO]       ICAO Doc 9303 Part 11 (8th ed.), Appendix D.1
//                https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
@testable import CoreExtendedNFC
import Foundation
import Testing

/// Parse a hex string, ignoring spaces and newlines as laid out in the sources.
private func vector(_ hex: String) -> Data {
    let digits = hex.filter { !$0.isWhitespace }
    precondition(digits.count % 2 == 0, "odd-length hex vector")
    var bytes = Data(capacity: digits.count / 2)
    var index = digits.startIndex
    while index < digits.endIndex {
        let next = digits.index(index, offsetBy: 2)
        bytes.append(UInt8(digits[index ..< next], radix: 16)!)
        index = next
    }
    return bytes
}

struct CryptoVectorTests {
    // MARK: - AES (FIPS 197)

    /// FIPS 197 Appendix C common plaintext.
    private static let fips197Plaintext = vector("00112233445566778899aabbccddeeff")

    @Test
    func `AES-128 FIPS 197-upd1 Appendix B cipher example`() throws {
        let key = vector("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
        let input = vector("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34")
        // Final state (column-major): 39 02 dc 19 / 25 dc 11 6a / 84 09 85 0b / 1d fb 97 32
        let output = vector("3925841d02dc09fbdc118597196a0b32")
        #expect(try CryptoUtils.aesECBEncrypt(key: key, message: input) == output)
        #expect(try CryptoUtils.aesDecrypt(key: key, message: output, iv: Data(count: 16)) == input)
    }

    @Test(arguments: [
        // C.1 AES-128 (Nk=4, Nr=10): round[10].output
        ("000102030405060708090a0b0c0d0e0f",
         "69c4e0d86a7b0430d8cdb78070b4c55a"),
        // C.2 AES-192 (Nk=6, Nr=12): round[12].output
        ("000102030405060708090a0b0c0d0e0f1011121314151617",
         "dda97ca4864cdfe06eaf70a0ec0d7191"),
        // C.3 AES-256 (Nk=8, Nr=14): round[14].output
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    ])
    func `AES FIPS 197 Appendix C example vectors`(keyHex: String, outputHex: String) throws {
        let key = vector(keyHex)
        let output = vector(outputHex)
        #expect(try CryptoUtils.aesECBEncrypt(key: key, message: Self.fips197Plaintext) == output)
        // Inverse cipher: single-block CBC with a zero IV is the ECB inverse (ioutput).
        #expect(
            try CryptoUtils.aesDecrypt(key: key, message: output, iv: Data(count: 16))
                == Self.fips197Plaintext
        )
    }

    // MARK: - SHA (FIPS 180-4, CSRC examples)

    /// One-block message sample, "abc" (24 bits).
    private static let abc = Data("abc".utf8)
    /// Two-block message sample for SHA-1/224/256 (448 bits).
    private static let message448 = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
    /// Two-block message sample for SHA-384/512 (896 bits).
    private static let message896 = Data(
        ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            + "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").utf8
    )

    @Test
    func `SHA two-block message lengths match the samples`() {
        #expect(Self.message448.count * 8 == 448)
        #expect(Self.message896.count * 8 == 896)
    }

    @Test
    func `SHA-1 two-block message sample (CSRC SHA1.pdf)`() {
        #expect(HashUtils.sha1(Self.message448) == vector("84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1"))
    }

    @Test
    func `SHA-224 one-block and two-block samples (CSRC SHA224.pdf)`() {
        #expect(HashUtils.sha224(Self.abc) == vector("""
        23097D22
        3405D822 8642A477 BDA255B3 2AADBCE4 BDA0B3F7 E36C9DA7
        """))
        #expect(HashUtils.sha224(Self.message448) == vector("""
        75388B16
        512776CC 5DBA5DA1 FD890150 B0C6455C B4F58B19 52522525
        """))
    }

    @Test
    func `SHA-256 two-block message sample (CSRC SHA256.pdf)`() {
        #expect(HashUtils.sha256(Self.message448) == vector("""
        248D6A61 D20638B8
        E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1
        """))
    }

    @Test
    func `SHA-384 one-block and two-block samples (CSRC SHA384.pdf)`() {
        #expect(HashUtils.sha384(Self.abc) == vector("""
        CB00753F 45A35E8B B5A03D69 9AC65007 272C32AB 0EDED163
        1A8B605A 43FF5BED 8086072B A1E7CC23 58BAECA1 34C825A7
        """))
        #expect(HashUtils.sha384(Self.message896) == vector("""
        09330C33 F71147E8 3D192FC7 82CD1B47 53111B17 3B3B05D2
        2FA08086 E3B0F712 FCC7C71A 557E2DB9 66C3E9FA 91746039
        """))
    }

    @Test
    func `SHA-512 one-block and two-block samples (CSRC SHA512.pdf)`() {
        #expect(HashUtils.sha512(Self.abc) == vector("""
        DDAF35A1 93617ABA CC417349 AE204131
        12E6FA4E 89A97EA2 0A9EEEE6 4B55D39A 2192992A 274FC1A8
        36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F
        """))
        #expect(HashUtils.sha512(Self.message896) == vector("""
        8E959B75 DAE313DA 8CF4F728 14FC143F
        8F7779C6 EB9F7FA1 7299AEAD B6889018 501D289E 4900F7E4
        331B99DE C4B5433A C7D329EE B6DD2654 5E96E55B 874BE909
        """))
    }

    // MARK: - CMAC (SP 800-38B, CSRC AES_CMAC.pdf; RFC 4493 §4)

    /// The 64-byte example plaintext shared by every CMAC-AES example; Mlen
    /// 0/16/20/64 use its first Mlen bytes.
    private static let cmacPlaintext = vector("""
    6BC1BEE2 2E409F96 E93D7E11 7393172A
    AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
    30C81C46 A35CE411 E5FBC119 1A0A52EF
    F69F2445 DF4F9B17 AD2B417B E66C3710
    """)

    private static let cmacKey128 = vector("2B7E1516 28AED2A6 ABF71588 09CF4F3C")
    private static let cmacKey192 = vector("8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B")
    private static let cmacKey256 = vector("""
    603DEB10 15CA71BE 2B73AEF0 857D7781
    1F352C07 3B6108D7 2D9810A3 0914DFF4
    """)

    @Test
    func `CMAC-AES128 subkeys (RFC 4493 §4 and CSRC AES_CMAC.pdf)`() throws {
        // RFC 4493 §4 "Subkey Generation": AES-128(key,0), K1, K2.
        #expect(try CryptoUtils.aesECBEncrypt(key: Self.cmacKey128, message: Data(count: 16))
            == vector("7df76b0c 1ab899b3 3e42f047 b91b546f"))
        let (k1, k2) = try AESCMAC.generateSubkeys(key: Self.cmacKey128)
        #expect(k1 == vector("fbeed618 35713366 7c85e08f 7236a8de"))
        #expect(k2 == vector("f7ddac30 6ae266cc f90bc11e e46d513b"))
    }

    @Test
    func `CMAC-AES128 Example 3 Mlen=20 (CSRC AES_CMAC.pdf)`() throws {
        // Examples 1, 2 and 4 equal RFC 4493 §4 Examples 1, 2 and 4 (CryptoTests).
        let message = Data(Self.cmacPlaintext.prefix(20))
        #expect(try AESCMAC.mac(key: Self.cmacKey128, message: message)
            == vector("7D85449E A6EA19C8 23A7BF78 837DFADE"))
    }

    @Test
    func `CMAC-AES192 subkeys (CSRC AES_CMAC.pdf)`() throws {
        #expect(try CryptoUtils.aesECBEncrypt(key: Self.cmacKey192, message: Data(count: 16))
            == vector("22452D8E 49A8A593 9F7321CE EA6D514B"))
        let (k1, k2) = try AESCMAC.generateSubkeys(key: Self.cmacKey192)
        #expect(k1 == vector("448A5B1C 93514B27 3EE6439D D4DAA296"))
        #expect(k2 == vector("8914B639 26A2964E 7DCC873B A9B5452C"))
    }

    @Test(arguments: [
        (0, "D17DDF46 ADAACDE5 31CAC483 DE7A9367"),
        (16, "9E99A7BF 31E71090 0662F65E 617C5184"),
        (20, "3D75C194 ED960704 44A9FA7E C740ECF8"),
        (64, "A1D5DF0E ED790F79 4D775896 59F39A11"),
    ])
    func `CMAC-AES192 Examples 1-4 (CSRC AES_CMAC.pdf)`(mlen: Int, tagHex: String) throws {
        let message = Data(Self.cmacPlaintext.prefix(mlen))
        #expect(try AESCMAC.mac(key: Self.cmacKey192, message: message) == vector(tagHex))
    }

    @Test
    func `CMAC-AES256 subkeys (CSRC AES_CMAC.pdf)`() throws {
        #expect(try CryptoUtils.aesECBEncrypt(key: Self.cmacKey256, message: Data(count: 16))
            == vector("E568F681 94CF76D6 174D4CC0 4310A854"))
        let (k1, k2) = try AESCMAC.generateSubkeys(key: Self.cmacKey256)
        #expect(k1 == vector("CAD1ED03 299EEDAC 2E9A9980 8621502F"))
        #expect(k2 == vector("95A3DA06 533DDB58 5D353301 0C42A0D9"))
    }

    @Test(arguments: [
        (0, "028962F6 1B7BF89E FC6B551F 4667D983"),
        (16, "28A7023F 452E8F82 BD4BF28D 8C37C35C"),
        (20, "156727DC 0878944A 023C1FE0 3BAD6D93"),
        (64, "E1992190 549F6ED5 696A2C05 6C315410"),
    ])
    func `CMAC-AES256 Examples 1-4 (CSRC AES_CMAC.pdf)`(mlen: Int, tagHex: String) throws {
        let message = Data(Self.cmacPlaintext.prefix(mlen))
        #expect(try AESCMAC.mac(key: Self.cmacKey256, message: message) == vector(tagHex))
    }

    // MARK: - DES parity adjustment (ICAO 9303-11 App. D.1)

    @Test(arguments: [
        // Kenc: Ka' -> Ka, Kb' -> Kb
        ("AB94FCEDF2664EDF", "AB94FDECF2674FDF"),
        ("B9B291F85D7F77F2", "B9B391F85D7F76F2"),
        // Kmac: Ka' -> Ka, Kb' -> Kb
        ("7862D9ECE03C1BCD", "7962D9ECE03D1ACD"),
        ("4D77089DCF131442", "4C76089DCE131543"),
    ])
    func `DES parity adjustment matches ICAO 9303-11 Appendix D.1 step 4`(rawHex: String, adjustedHex: String) {
        #expect(KeyDerivation.adjustParity(vector(rawHex)) == vector(adjustedHex))
    }

    @Test
    func `DES parity adjustment sets odd parity in the low bit and keeps the key bits`() {
        // FIPS 46-3: bits 8, 16, ..., 64 are odd-parity bits; the other 7 bits of each byte are key bits.
        let all = Data((0 ... 255).map { UInt8($0) })
        let adjusted = KeyDerivation.adjustParity(all)
        for (raw, out) in zip(all, adjusted) {
            #expect(out & 0xFE == raw & 0xFE)
            #expect(out.nonzeroBitCount % 2 == 1)
        }
    }
}
