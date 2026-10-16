// Published test vectors for the MIFARE / NTAG / ISO 14443 layer, run as executable tests.
//
// ## Sources (proxmark3 at commit e519c1af94b23b4d4f2a17874bd789b52af1623b)
// - proxmark3 client/src/mifare/desfiretest.c
//   https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/desfiretest.c
//   TestCMACSubkeys (l. 84-129), TestAn10922KDFAES (l. 132-147), TestEV2SessionKeys
//   (l. 306-340), TestEV2IVEncode (l. 342-373), TestEV2MAC (l. 376-427),
//   TestTransSessionKeys (l. 430-460). Derivations in client/src/mifare/desfirecrypto.c
//   (MifareKdfAn10922 l. 395, DesfireGenSessionKeyEV2 l. 633, DesfireEV2FillIV l. 682,
//   DesfireEV2CalcCMAC l. 705, DesfireGenTransSessionKeyEV2 l. 723).
//   Not covered here: TDES/DES CMAC and AN10922 2TDEA/3TDEA KDF (the library has no
//   TDES CMAC), LRP (not implemented), CRC16/CRC32 position search (no counterpart).
// - proxmark3 client/src/cmdhfmfu.c GetHF14AMfU_Type GET_VERSION table (l. 2432-2461),
//   ul_family table (l. 172-221), page counts MAX_* (l. 46-66).
//   https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/cmdhfmfu.c
// - proxmark3 client/src/mifare/mifare4.c MFAccessConditions / MFAccessConditionsTrailer
//   (l. 58-78), mfValidateAccessConditions (l. 80-89), mf_get_accesscondition;
//   client/src/cmdhfmf.c CmdHF14AMfAcl named trailers FF0780 / 7F0788 / 787788 (l. 1278-1285).
// - NXP MF1S50YYX_V1 Rev. 3.2 §8.7: Figure 10 (access-bit layout), Table 7 (sector
//   trailer), Table 8 (data blocks).
// - libnfc libnfc/iso14443-subr.c iso14443a_crc / iso14443b_crc (l. 48-102)
//   https://github.com/nfc-tools/libnfc/blob/master/libnfc/iso14443-subr.c
//   and the ISO/IEC 14443-3 Annex B CRC examples.
// - NXP AN10833 Rev. 3.9: Table 3 (ATQA), Table 4 (SAK), Table 5 (ORed SAKs), Figure 1.
//
// All expected values were re-derived independently (python3 -I + openssl AES) before
// being written here.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct MIFAREVectorTests {
    private static func hex(_ string: String) -> Data {
        Data(hexString: string)!
    }

    // MARK: - DESFire: AES CMAC subkeys and AN10922 KDF (desfiretest.c)

    @Test
    func `DESFire AES CMAC subkeys (proxmark3 TestCMACSubkeys, AN10922)`() throws {
        let (k1, k2) = try AESCMAC.generateSubkeys(key: Self.hex("00112233445566778899AABBCCDDEEFF"))
        #expect(k1 == Self.hex("FBC9F75C9413C041DFEE452D3F0706D1"))
        #expect(k2 == Self.hex("F793EEB928278083BFDC8A5A7E0E0D25"))
    }

    @Test
    func `AN10922 AES-128 key diversification is CMAC over 01 ‖ M (proxmark3 TestAn10922KDFAES)`() throws {
        // MifareKdfAn10922 pads 01 ‖ M (18 bytes) to 32 bytes with K2: plain AES-CMAC.
        let key = Self.hex("00112233445566778899AABBCCDDEEFF")
        let input = Self.hex("04782E21801D803042F54E585020416275")
        let diversified = try AESCMAC.mac(key: key, message: Data([0x01]) + input)
        #expect(diversified == Self.hex("A8DD63A3B89D54B37CA802473FDA9175"))
    }

    // MARK: - DESFire EV2 (AN12343 via desfiretest.c)

    @Test(arguments: [
        // AN12343 p. 33-34, Kx = 00..00
        (
            "00000000000000000000000000000000",
            "B04D0787C93EE0CC8CACC8E86F16C6FE",
            "FA659AD0DCA738DD65DC7DC38612AD81",
            "63DC07286289A7A6C0334CA31C314A04",
            "774F26743ECE6AF5033B6AE8522946F6"
        ),
        // proxmark3 non-zero key vector
        (
            "00112233445566778899AABBCCDDEEFF",
            "0123456789ABCDEF0123456789ABCDEF",
            "FEDCBA9876543210FEDCBA9876543210",
            "195428119C8528D59580A73C7C96C6A3",
            "0AF00F6E39F904C4A6388C812D53DC94"
        ),
    ])
    func `EV2 session keys (proxmark3 TestEV2SessionKeys)`(
        key: String,
        rndA: String,
        rndB: String,
        encKey: String,
        macKey: String
    ) throws {
        let keys = try DESFireCommands.deriveEV2SessionKeys(
            staticKey: Self.hex(key),
            rndA: Self.hex(rndA),
            rndB: Self.hex(rndB)
        )
        #expect(keys.sessionENCKey == Self.hex(encKey))
        #expect(keys.sessionMACKey == Self.hex(macKey))
    }

    /// EV2 IV = E(SesAuthENCKey, A5 5A ‖ TI ‖ CmdCtr(LE) ‖ 00*8). The library has no EV2
    /// secure messaging; this checks the AES-ECB primitive it would build on.
    @Test(arguments: [
        ("66A8CB93269DC9BC2885B7A91B9C697B", "ED56F6E6", UInt16(0), "DA0F644A4986275957CF1EC3AF4CCE53"),
        ("445A8626B3338459321232FADF6ADE2B", "11223344", UInt16(5), "177494FCC4F1DAB2AFBE8FAE2057A9D2"),
    ])
    func `EV2 command IV (proxmark3 TestEV2IVEncode)`(key: String, ti: String, counter: UInt16, iv: String) throws {
        let block = Data([0xA5, 0x5A]) + Self.hex(ti)
            + Data([UInt8(counter & 0xFF), UInt8(counter >> 8)]) + Data(count: 8)
        #expect(try CryptoUtils.aesECBEncrypt(key: Self.hex(key), message: block) == Self.hex(iv))
    }

    /// EV2 MACt = odd-indexed bytes of CMAC(SesAuthMACKey, Cmd ‖ CmdCtr(LE) ‖ TI ‖ Data)
    /// (proxmark3 DesfireEV2CalcCMAC → aes_cmac8). Exercises AESCMAC on AN12343 p. 54 inputs.
    @Test(arguments: [
        (UInt8(0x8D), UInt16(0), "0000000019000022" + String(repeating: "22", count: 24), "68F2C28C575A1628"),
        (UInt8(0x00), UInt16(1), "", "0820F68898C2A7F1"),
        (UInt8(0xAD), UInt16(1), "00000000300000", "0D9BE191D5960834"),
        (UInt8(0x00), UInt16(2), String(repeating: "22", count: 25) + String(repeating: "00", count: 23), "A49A44222D926666"),
    ])
    func `EV2 truncated CMAC (proxmark3 TestEV2MAC, AN12343 p. 54)`(
        command: UInt8,
        counter: UInt16,
        data: String,
        expected: String
    ) throws {
        let key = Self.hex("9366FA195EB566F5BD2BAD4020B83002")
        let ti = Self.hex("E2D3AF69")
        let message = Data([command, UInt8(counter & 0xFF), UInt8(counter >> 8)]) + ti
            + (data.isEmpty ? Data() : Self.hex(data))
        let full = [UInt8](try AESCMAC.mac(key: key, message: message))
        let truncated = Data(stride(from: 1, to: 16, by: 2).map { full[$0] })
        #expect(truncated == Self.hex(expected))
    }

    /// Transaction MAC session keys: CMAC(K, 5A|A5 00 01 00 80 ‖ (TMC+1)LE4 ‖ UID).
    @Test(arguments: [
        (
            "66A8CB93269DC9BC2885B7A91B9C697B", UInt32(8), "04010203040506",
            "7C1AD2D9C5C08154A0A4914B401A6598", "119B902A07B18A865B8E1B0060594784"
        ),
        (
            "0123456789ABCDEFFEDCBA9876543210", UInt32(0x1234_5678), "04A1B2C3D4E5F6",
            "8F76D21BAE6765845188BCF9159BE0EC", "6F701DC037A5F0757A7FF667055F4B25"
        ),
    ])
    func `EV2 transaction MAC session keys (proxmark3 TestTransSessionKeys)`(
        key: String,
        counter: UInt32,
        uid: String,
        macKey: String,
        encKey: String
    ) throws {
        let next = counter + 1
        let counterLE = Data([UInt8(next & 0xFF), UInt8((next >> 8) & 0xFF), UInt8((next >> 16) & 0xFF), UInt8(next >> 24)])
        let tail = Data([0x00, 0x01, 0x00, 0x80]) + counterLE + Self.hex(uid)
        #expect(try AESCMAC.mac(key: Self.hex(key), message: Data([0x5A]) + tail) == Self.hex(macKey))
        #expect(try AESCMAC.mac(key: Self.hex(key), message: Data([0xA5]) + tail) == Self.hex(encKey))
    }

    // MARK: - Ultralight / NTAG GET_VERSION (cmdhfmfu.c)

    /// proxmark3 GetHF14AMfU_Type matches 7 bytes; byte 8 (protocol type) is 03h for all.
    /// Types the library models map to their CardType; others must fall back to the
    /// generic 16-page `.mifareUltralight`.
    @Test(arguments: [
        ("0004030101000B03", CardType.mifareUltralightEV1_MF0UL11), // UL EV1 48 (l. 2432)
        ("0004030201000B03", CardType.mifareUltralightEV1_MF0UL11), // UL EV1 48 50pF (l. 2434)
        ("0004030301000B03", CardType.mifareUltralightEV1_MF0UL11), // MF0UL1141DUF (ul_family)
        ("0004030101000E03", CardType.mifareUltralightEV1_MF0UL21), // UL EV1 128 (l. 2435)
        ("0004030201000E03", CardType.mifareUltralightEV1_MF0UL21), // UL EV1 128 50pF (l. 2436)
        ("0004030104000F03", CardType.mifareUltralight), // UL AES 17pF (l. 2437)
        ("0004030204000F03", CardType.mifareUltralight), // UL AES 50pF (l. 2438)
        ("0004030304000F03", CardType.mifareUltralight), // UL AES 75pF (l. 2439)
        ("0004030101001103", CardType.mifareUltralight), // MF0UL3101 (ul_family, unsupported)
        ("0004030101001303", CardType.mifareUltralight), // MF0UL5101 (ul_family, unsupported)
        ("0034210101000E03", CardType.mifareUltralight), // Mikron EV1, non-NXP vendor (l. 2440)
        ("0004040101000B03", CardType.ntag210), // NTAG 210 (l. 2441)
        ("0004040201000B03", CardType.ntag210), // NT2H1011G0DUD (ul_family)
        ("0004040102000B03", CardType.ntag210), // NTAG 210u, MAX_NTAG_210 pages (l. 2442)
        ("0004040202000B03", CardType.ntag210), // NTAG 210u (l. 2443)
        ("0004040101000E03", CardType.ntag212), // NTAG 212 (l. 2444)
        ("0004040201000F03", CardType.ntag213), // NTAG 213 (l. 2445)
        ("0053040201000F03", CardType.mifareUltralight), // Feiju clone, non-NXP vendor (l. 2446)
        ("0004040201010F03", CardType.ntag213), // NTAG 213 C, MAX_NTAG_213 pages (l. 2447)
        ("0004040201001103", CardType.ntag215), // NTAG 215 (l. 2448)
        ("0004040401001103", CardType.ntag215), // NT2H1511F0Dxy (ul_family)
        ("0005340201001103", CardType.mifareUltralight), // Feiju 215 clone (l. 2449)
        ("0004040201001303", CardType.ntag216), // NTAG 216 (l. 2450)
        ("0004040401000F03", CardType.ntag213), // NTAG 213 F (l. 2451)
        ("0004040401001303", CardType.ntag216), // NTAG 216 F (l. 2452)
        ("0004040203000F03", CardType.ntag213), // NTAG 213 TT, MAX_NTAG_213 pages (l. 2453)
        ("0004040205001003", CardType.mifareUltralight), // NTAG 224 DNA (l. 2456)
        ("0004040805001003", CardType.mifareUltralight), // NTAG 224 DNA SD (l. 2457)
        ("0004040502011303", CardType.mifareUltralight), // NTAG I2C 1k (l. 2458)
        ("0004040502011503", CardType.mifareUltralight), // NTAG I2C 2k (l. 2459)
        ("0004040502021303", CardType.mifareUltralight), // NTAG I2C plus 1k (l. 2460)
        ("0004040502021503", CardType.mifareUltralight), // NTAG I2C plus 2k (l. 2461)
    ])
    func `GET_VERSION table (proxmark3 cmdhfmfu.c)`(version: String, expected: CardType) throws {
        #expect(try UltralightVersionResponse(data: Self.hex(version)).cardType == expected)
    }

    /// Chips proxmark3 identifies separately and the library has no model for, but which
    /// the library maps onto an EV1 / NTAG21x memory map of a different size.
    @Test(arguments: [
        // UL Nano 40 (MF0UN0001 / MF0UNH0001): MAX_UL_NANO_40 = 0x0A → 11 pages, not MF0UL11's 20.
        ("0004030102000B03", "UL Nano 40 (MF0UN0001), 11 pages, gets the 20-page MF0UL11 map"),
        ("0004030202000B03", "UL Nano 40 50pF (MF0UNH0001), 11 pages, gets the 20-page MF0UL11 map"),
        // NTAG 223 DNA: MAX_NTAG_223_DNA = 0x3B → 60 pages, not NTAG213's 45.
        ("0004040204000F03", "NTAG 223 DNA (major 04h), 60 pages, gets the 45-page NTAG213 map"),
        ("0004040804000F03", "NTAG 223 DNA SD (subtype 08h), 60 pages, gets the 45-page NTAG213 map"),
    ])
    func `GET_VERSION chips without a library model fall back to the generic map`(version: String, reason: String) throws {
        let type = try UltralightVersionResponse(data: Self.hex(version)).cardType
        // Fixed: cardType now requires major version 01h for the EV1/NTAG21x maps.
        #expect(type == .mifareUltralight, "\(reason)")
    }

    // MARK: - MIFARE Classic access bits (MF1S50 Tables 7/8, proxmark3 mifare4.c)

    /// Encoder for MF1S50 Figure 10, independent from `AccessBits.decode`.
    private static func accessBytes(_ bits: [(c1: Int, c2: Int, c3: Int)]) -> Data {
        var c1 = 0, c2 = 0, c3 = 0
        for (block, b) in bits.enumerated() {
            c1 |= b.c1 << block
            c2 |= b.c2 << block
            c3 |= b.c3 << block
        }
        let byte6 = UInt8(((~c2 & 0xF) << 4) | (~c1 & 0xF))
        let byte7 = UInt8((c1 << 4) | (~c3 & 0xF))
        let byte8 = UInt8((c3 << 4) | c2)
        return Data([byte6, byte7, byte8])
    }

    /// Rows of MF1S50 Table 7 / Table 8 in datasheet order (C1 C2 C3).
    private static let tableRows: [(c1: Int, c2: Int, c3: Int)] = [
        (0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 0), (0, 0, 1), (0, 1, 1), (1, 0, 1), (1, 1, 1),
    ]

    @Test(arguments: 0 ..< 4, 0 ..< 8)
    func `Every access condition decodes for every block (MF1S50 Tables 7 and 8)`(block: Int, row: Int) throws {
        let bits = Self.tableRows[row]
        var all = Array(repeating: (c1: 0, c2: 0, c3: 0), count: 4)
        all[block] = bits
        let decoded = try #require(AccessBits.decode(Self.accessBytes(all)))
        #expect(decoded.count == 4)
        for index in 0 ..< 4 {
            let want = all[index]
            #expect(decoded[index].c1 == (want.c1 == 1))
            #expect(decoded[index].c2 == (want.c2 == 1))
            #expect(decoded[index].c3 == (want.c3 == 1))
            // Library packing: C1 | C2<<1 | C3<<2.
            #expect(Int(decoded[index].condition) == want.c1 | want.c2 << 1 | want.c3 << 2)
        }
        // proxmark3 mf_get_accesscondition packs C1<<2 | C2<<1 | C3; recompute from the decode.
        let pm3 = (decoded[block].c1 ? 4 : 0) | (decoded[block].c2 ? 2 : 0) | (decoded[block].c3 ? 1 : 0)
        #expect(pm3 == bits.c1 << 2 | bits.c2 << 1 | bits.c3)
    }

    @Test(arguments: [
        // cmdhfmf.c l. 1278: transport configuration — data 000, trailer 001 (Table 7 row 5).
        ("FF0780", [(0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 0, 1)]),
        // l. 1280: key B enabler — data 000, trailer 011.
        ("7F0788", [(0, 0, 0), (0, 0, 0), (0, 0, 0), (0, 1, 1)]),
        // l. 1282: no value commands — data 100 (read AB, write B), trailer 011.
        ("787788", [(1, 0, 0), (1, 0, 0), (1, 0, 0), (0, 1, 1)]),
    ])
    func `Named sector trailers from proxmark3 hf mf acl`(bytes: String, expected: [(Int, Int, Int)]) throws {
        let decoded = try #require(AccessBits.decode(Self.hex(bytes)))
        for (index, want) in expected.enumerated() {
            #expect(decoded[index].c1 == (want.0 == 1))
            #expect(decoded[index].c2 == (want.1 == 1))
            #expect(decoded[index].c3 == (want.2 == 1))
        }
        #expect(Self.accessBytes(expected.map { (c1: $0.0, c2: $0.1, c3: $0.2) }) == Self.hex(bytes))
    }

    @Test(arguments: 0 ..< 24)
    func `Any single flipped access bit breaks the complement (mfValidateAccessConditions)`(bit: Int) {
        // Each of the 24 bits sits in exactly one (Cx, ~Cx) pair, so a flip is always invalid.
        var bytes = [UInt8](Self.hex("FF0780"))
        bytes[bit / 8] ^= UInt8(1 << (bit % 8))
        #expect(AccessBits.decode(Data(bytes)) == nil)
    }

    @Test
    func `User byte 9 is ignored and slices decode`() throws {
        let trailer = Self.hex("FFFFFFFFFFFF7F078869FFFFFFFFFFFF")
        let decoded = try #require(AccessBits.decode(trailer[6 ..< 10]))
        #expect(decoded[3].condition == 0b110) // C2 = C3 = 1
    }

    // MARK: - ISO/IEC 14443-3 CRC (Annex B, libnfc iso14443-subr.c)

    @Test(arguments: [
        ("0000", "A01E"), // ISO/IEC 14443-3 Annex B.1
        ("1234", "26CF"), // ISO/IEC 14443-3 Annex B.1
        ("E080", "3173"), // RATS FSDI=8 CID=0, as on air in proxmark3 traces
        ("E050", "BCA5"), // RATS FSDI=5 CID=0
    ])
    func `CRC_A examples`(data: String, crc: String) {
        let (lo, hi) = ISO14443.crcA(Self.hex(data))
        #expect(Data([lo, hi]) == Self.hex(crc))
    }

    @Test(arguments: [
        ("000000", "CCC6"), // ISO/IEC 14443-3 Annex B.2
        ("0FAAFF", "FCD1"), // ISO/IEC 14443-3 Annex B.2
        ("0A123456", "2CF6"), // ISO/IEC 14443-3 Annex B.2
        ("050008", "3973"), // REQB AFI=00 PARAM=08
    ])
    func `CRC_B examples`(data: String, crc: String) {
        let (lo, hi) = ISO14443.crcB(Self.hex(data))
        #expect(Data([lo, hi]) == Self.hex(crc))
    }

    @Test
    func `Frame with appended CRC_A has a zero residue`() {
        // CRC_A over data ‖ CRC_A (LSB first) is 0x0000 for every frame.
        for frame in ["3004", "5000", "E080", "93708804AABB"] {
            var data = Self.hex(frame)
            ISO14443.appendCrcA(&data)
            let (lo, hi) = ISO14443.crcA(data)
            #expect(lo == 0 && hi == 0)
        }
    }

    // MARK: - AN10833 ATQA / SAK (Tables 3, 4, 5, Figure 1)

    @Test(arguments: [
        (UInt16(0x0044), UInt8(0x00), CardType.mifareUltralight), // Ultralight C (T3/T4)
        (UInt16(0x0004), UInt8(0x08), CardType.mifareClassic1K), // Classic EV1 1K 4B (T3/T4)
        (UInt16(0x0044), UInt8(0x08), CardType.mifareClassic1K), // Classic EV1 1K 7B, ATQA 00x4
        (UInt16(0x0002), UInt8(0x18), CardType.mifareClassic4K), // Classic EV1 4K 4B
        (UInt16(0x0042), UInt8(0x18), CardType.mifareClassic4K), // Classic EV1 4K 7B, ATQA 00x2
        (UInt16(0x0004), UInt8(0x10), CardType.mifarePlusSL2_2K), // Plus 2K SL2 4B NUID
        (UInt16(0x0044), UInt8(0x10), CardType.mifarePlusSL2_2K), // Plus 2K SL2 7B
        (UInt16(0x0002), UInt8(0x11), CardType.mifarePlusSL2_4K), // Plus 4K SL2 4B NUID
        (UInt16(0x0042), UInt8(0x11), CardType.mifarePlusSL2_4K), // Plus 4K SL2 7B
        (UInt16(0x0004), UInt8(0x20), CardType.smartMX), // Plus SL3: ATS needed (§2.1)
        (UInt16(0x0042), UInt8(0x20), CardType.smartMX), // Plus 4K SL3 7B
        (UInt16(0x0004), UInt8(0x28), CardType.smartMX), // Table 5 example 1
        (UInt16(0x0002), UInt8(0x38), CardType.smartMX), // Table 5 examples 2/3
        (UInt16(0x0004), UInt8(0x09), CardType.mifareMini), // Figure 1: SAK 09
        (UInt16(0x0344), UInt8(0x20), CardType.mifareDesfire),
    ])
    func `AN10833 ATQA and SAK combinations`(atqa: UInt16, sak: UInt8, expected: CardType) {
        #expect(CardIdentifier.identify(atqaValue: atqa, sak: sak) == expected)
        // Same answer from the ISO/IEC 14443-3 wire order (LSB first).
        let wire = Data([UInt8(atqa & 0xFF), UInt8(atqa >> 8)])
        let value = CardIdentifier.atqaValue(wireOrder: wire)
        #expect(value == atqa)
    }

    @Test
    func `Plus SL1 shares Classic ATQA and SAK (AN10833 Table 4)`() {
        // Plus 2K/SE SL1 answers 0004/08 and Plus 4K SL1 0002/18, identical to Classic,
        // so ATQA/SAK alone can only report a Classic-compatible card.
        let sl1_2K = CardIdentifier.identify(atqaValue: 0x0004, sak: 0x08)
        let sl1_4K = CardIdentifier.identify(atqaValue: 0x0002, sak: 0x18)
        #expect(sl1_2K == .mifareClassic1K || sl1_2K == .mifarePlusSL1_2K)
        #expect(sl1_4K == .mifareClassic4K || sl1_4K == .mifarePlusSL1_4K)
    }

    @Test(arguments: [UInt8(0x19), UInt8(0x01)])
    func `Figure 1 SAKs without a library model stay unknown`(sak: UInt8) {
        // 0x19 = MIFARE Classic 2K, 0x01 = TagNPlay: no CardType, so no misclassification.
        let type = CardIdentifier.identify(atqaValue: 0x0004, sak: sak)
        #expect(type == .unknown(atqa: Data([0x00, 0x04]), sak: sak))
    }
}
