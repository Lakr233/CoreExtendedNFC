// Worked examples from ICAO Doc 9303 run as executable tests.
//
// Every expected value below is copied byte for byte from the published example. Values
// that other suites already pin (Appendix D final SM APDUs, Appendix G.1 PACE trace, the
// Part 5 / Part 6 specimen MRZs) are not repeated; this suite adds the intermediate steps
// and the examples nothing else covers.
//
// ## References
// - ICAO Doc 9303 Part 3 (8th ed.), Appendix A: check digit examples 1–5
// - ICAO Doc 9303 Part 4, §4.2.3 name examples and Appendix A Figure A-1 (TD3 specimen)
// - ICAO Doc 9303 Part 5, §4.2.3 name examples (TD1)
// - ICAO Doc 9303 Part 6, §4.2.3 name examples (TD2)
// - ICAO Doc 9303 Part 10, Appendix A: EF.COM, EF.DG1 (TD1) and EF.DG11 mapping examples
// - ICAO Doc 9303 Part 11, Appendix D: BAC (D.1 key derivation, D.2 MRZ information,
//   D.3 mutual authentication and session keys, D.4 secure messaging)
// - ICAO Doc 9303 Part 11, Appendix F: Active Authentication (RSA, ISO/IEC 9796-2, SHA-1)
// - ICAO Doc 9303 Part 11, Appendix G: PACE Generic Mapping (G.1 ECDH PACEInfo, G.2 DH)
// - ICAO Doc 9303 Part 11, Appendix I: PACE Chip Authentication Mapping
//
// ## Errata in the published examples (not asserted)
// - Part 11 D.2: the composite check digits printed for the two `L898902C<` examples
//   (TD2 '8', TD1 '1') do not follow Part 3 §4.9; both compute to '2'. BAC does not use
//   the composite digit, and the other D.2 composites ('8', '2') are correct.
// - Part 10 A.2.1: the TD1 composite check digit is printed as '4'; it computes to '8'.
// - Part 10 A.2.2: the TD2 DG1 example is 81 characters, not the 72 its length '48' says.
// - Part 4 Figure A-2 (IVANOVA): both MRZ lines are 45 characters instead of 44.
// - Part 10 A.5: telephone '5F12' has length '0E' (14) but prints the 11-character
//   `16125551212`; the prose gives `1-612-555-1212`, which is 14 characters and makes the
//   template length '63' add up, so that value is used.
// - Part 11 H.1: Kπ `591468CD…` is not KDF(K, 3) of the Appendix G MRZ key the text
//   says it reuses, and Integrated Mapping is unsupported, so H is not exercised here.
@testable import CoreExtendedNFC
import Foundation
import Testing

private func icaoHex(_ string: String) -> Data {
    let digits = string.filter { !$0.isWhitespace }
    var data = Data(capacity: digits.count / 2)
    var index = digits.startIndex
    while index < digits.endIndex {
        let next = digits.index(index, offsetBy: 2)
        data.append(UInt8(digits[index ..< next], radix: 16)!)
        index = next
    }
    return data
}

struct ICAOVectorTests {
    // MARK: - Part 11 Appendix D shared values

    private static let dKSeedBAC = icaoHex("239AB9CB282DAF66231DC5A4DF6BFBAE")
    private static let dKEnc = icaoHex("AB94FDECF2674FDFB9B391F85D7F76F2")
    private static let dKMac = icaoHex("7962D9ECE03D1ACD4C76089DCE131543")
    private static let dRndIC = icaoHex("4608F91988702212")
    private static let dRndIFD = icaoHex("781723860C06C226")
    private static let dKIFD = icaoHex("0B795240CB7049B01C19B33E32804F0B")
    private static let dKIC = icaoHex("0B4F80323EB3191CB04970CB4052790B")
    private static let dEIFD = icaoHex("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")
    private static let dMIFD = icaoHex("5F1448EEA8AD90A7")
    private static let dEIC = icaoHex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F")
    private static let dMIC = icaoHex("2F2D235D074D7449")
    private static let dKSEnc = icaoHex("979EC13B1CBFE9DCD01AB0FED307EAE5")
    private static let dKSMac = icaoHex("F1CB1F1FB5ADF208806B89DC579DC1F8")
    private static let dSSC = icaoHex("887022120C06C226")

    // MARK: - Part 11 D.1: keys from Kseed

    @Test
    func `D.1 SHA-1 of Kseed and counter then DES parity gives Kenc and Kmac`() {
        let seed = Self.dKSeedBAC

        let hashEnc = HashUtils.sha1(seed + icaoHex("00000001"))
        #expect(hashEnc == icaoHex("AB94FCEDF2664EDFB9B291F85D7F77F27F2F4A9D"))
        #expect(KeyDerivation.adjustParity(icaoHex("AB94FCEDF2664EDF")) == icaoHex("AB94FDECF2674FDF"))
        #expect(KeyDerivation.adjustParity(icaoHex("B9B291F85D7F77F2")) == icaoHex("B9B391F85D7F76F2"))

        let hashMac = HashUtils.sha1(seed + icaoHex("00000002"))
        #expect(hashMac == icaoHex("7862D9ECE03C1BCD4D77089DCF131442814EA70A"))
        #expect(KeyDerivation.adjustParity(icaoHex("7862D9ECE03C1BCD")) == icaoHex("7962D9ECE03D1ACD"))
        #expect(KeyDerivation.adjustParity(icaoHex("4D77089DCF131442")) == icaoHex("4C76089DCE131543"))

        // The ICAO KDF for 3DES (also used by Chip Authentication) gives the same keys.
        #expect(KeyDerivation.deriveKey(keySeed: seed, counter: 1, mode: .tripleDES) == Self.dKEnc)
        #expect(KeyDerivation.deriveKey(keySeed: seed, counter: 2, mode: .tripleDES) == Self.dKMac)
    }

    // MARK: - Part 11 D.2: MRZ information from four MRZs

    @Test
    func `D.2 TD2 MRZ with a document number longer than 9 characters`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<"
                + "D23145890<UTO3407127M95071227349<<<8"
        )
        #expect(mrz.format == .td2)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "STEVENSON")
        #expect(mrz.firstName == "PETER JOHN")
        #expect(mrz.documentNumber == "D23145890734")
        #expect(mrz.optionalData1 == "")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.dateOfBirth == "340712")
        #expect(mrz.sex == "M")
        #expect(mrz.dateOfExpiry == "950712")

        #expect(MRZKeyGenerator.checkDigit("D23145890734") == "9")
        #expect(MRZKeyGenerator.checkDigit("340712") == "7")
        #expect(MRZKeyGenerator.checkDigit("950712") == "2")
        #expect(MRZKeyGenerator.computeMRZKey(
            documentNumber: mrz.documentNumber,
            dateOfBirth: mrz.dateOfBirth,
            dateOfExpiry: mrz.dateOfExpiry
        ) == "D23145890734934071279507122")
        // Composite: positions 1–10, 14–20, 22–35 of the lower line.
        #expect(MRZKeyGenerator.checkDigit("D23145890<" + "3407127" + "95071227349<<<") == "8")
    }

    @Test
    func `D.2 TD2 MRZ with a 9-character document number gives the D.1 Kseed`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                + "L898902C<3UTO6908061F9406236<<<<<<<8"
        )
        #expect(mrz.format == .td2)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(mrz.documentNumber == "L898902C")
        #expect(mrz.optionalData1 == "")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.dateOfBirth == "690806")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "940623")

        let mrzInformation = MRZKeyGenerator.computeMRZKey(
            documentNumber: mrz.documentNumber,
            dateOfBirth: mrz.dateOfBirth,
            dateOfExpiry: mrz.dateOfExpiry
        )
        #expect(mrzInformation == "L898902C<369080619406236")
        #expect(HashUtils.sha1(Data(mrzInformation.utf8)) == icaoHex("239AB9CB282DAF66231DC5A4DF6BFBAEDF477565"))
        #expect(KeyDerivation.generateKseed(mrzKey: mrzInformation) == Self.dKSeedBAC)
        #expect(KeyDerivation.deriveKey(keySeed: Self.dKSeedBAC, mode: .enc) == Self.dKEnc)
        #expect(KeyDerivation.deriveKey(keySeed: Self.dKSeedBAC, mode: .mac) == Self.dKMac)
    }

    @Test
    func `D.2 TD1 MRZ with a document number longer than 9 characters`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOD23145890<7349<<<<<<<<<<<"
                + "3407127M9507122UTO<<<<<<<<<<<2"
                + "STEVENSON<<PETER<JOHN<<<<<<<<<"
        )
        #expect(mrz.format == .td1)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.documentNumber == "D23145890734")
        #expect(mrz.optionalData1 == "")
        #expect(mrz.dateOfBirth == "340712")
        #expect(mrz.sex == "M")
        #expect(mrz.dateOfExpiry == "950712")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.optionalData2 == "")
        #expect(mrz.lastName == "STEVENSON")
        #expect(mrz.firstName == "PETER JOHN")
        #expect(MRZKeyGenerator.computeMRZKey(
            documentNumber: mrz.documentNumber,
            dateOfBirth: mrz.dateOfBirth,
            dateOfExpiry: mrz.dateOfExpiry
        ) == "D23145890734934071279507122")
        // Composite: upper 6–30, middle 1–7, 9–15, 19–29.
        #expect(MRZKeyGenerator.checkDigit(
            "D23145890<7349<<<<<<<<<<<" + "3407127" + "9507122" + "<<<<<<<<<<<"
        ) == "2")
    }

    @Test
    func `D.2 TD1 MRZ with a 9-character document number`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOL898902C<3<<<<<<<<<<<<<<<"
                + "6908061F9406236UTO<<<<<<<<<<<1"
                + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        )
        #expect(mrz.format == .td1)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.documentNumber == "L898902C")
        #expect(mrz.optionalData1 == "")
        #expect(mrz.dateOfBirth == "690806")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "940623")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(MRZKeyGenerator.computeMRZKey(
            documentNumber: mrz.documentNumber,
            dateOfBirth: mrz.dateOfBirth,
            dateOfExpiry: mrz.dateOfExpiry
        ) == "L898902C<369080619406236")
    }

    // MARK: - Part 11 D.3: authentication and session keys

    @Test
    func `D.3 inspection system computes E_IFD and M_IFD from S`() throws {
        let s = Self.dRndIFD + Self.dRndIC + Self.dKIFD
        #expect(s == icaoHex("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B"))

        let eIFD = try CryptoUtils.tripleDESEncrypt(key: Self.dKEnc, message: s)
        #expect(eIFD == Self.dEIFD)
        let mIFD = try ISO9797MAC.mac(key: Self.dKMac, message: ISO9797Padding.pad(eIFD, blockSize: 8))
        #expect(mIFD == Self.dMIFD)

        let command = CommandAPDU.mutualAuthenticate(data: eIFD + mIFD)
        #expect(command.bytes == icaoHex("0082000028") + Self.dEIFD + Self.dMIFD + icaoHex("28"))
        #expect(CommandAPDU.getChallenge().bytes == icaoHex("0084000008"))
    }

    @Test
    func `D.3 chip response R, E_IC and M_IC, and the derived session keys and SSC`() throws {
        // Chip side (D.3 eMRTD steps 6–8).
        let r = Self.dRndIC + Self.dRndIFD + Self.dKIC
        #expect(r == icaoHex("4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B"))
        #expect(try CryptoUtils.tripleDESEncrypt(key: Self.dKEnc, message: r) == Self.dEIC)
        #expect(try ISO9797MAC.mac(key: Self.dKMac, message: ISO9797Padding.pad(Self.dEIC, blockSize: 8)) == Self.dMIC)

        // Inspection system side: decrypt, then derive.
        #expect(try CryptoUtils.tripleDESDecrypt(key: Self.dKEnc, message: Self.dEIC) == r)
        let kSeed = Data(zip(Self.dKIFD, Self.dKIC).map { $0 ^ $1 })
        #expect(kSeed == icaoHex("0036D272F5C350ACAC50C3F572D23600"))
        #expect(KeyDerivation.deriveKey(keySeed: kSeed, mode: .enc) == Self.dKSEnc)
        #expect(KeyDerivation.deriveKey(keySeed: kSeed, mode: .mac) == Self.dKSMac)
        #expect(Self.dRndIC.suffix(4) + Self.dRndIFD.suffix(4) == Self.dSSC)
    }

    @Test
    func `D.3 and D.4 BAC and EF.COM read reproduce the whole Appendix D trace`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Self.dRndIC, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Self.dEIC + Self.dMIC, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: icaoHex("990290008E08FA855A5D4C50A8ED"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: icaoHex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(
                data: icaoHex(
                    "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74"
                ),
                sw1: 0x90,
                sw2: 0x00
            ),
        ]

        let sm = try await BACHandler.performBAC(
            mrzKey: "L898902C<369080619406236",
            transport: mock,
            rndIFD: Self.dRndIFD,
            kIFD: Self.dKIFD
        )
        let select = try await sm.sendAPDU(.selectEF(id: Data([0x01, 0x1E])))
        let head = try await sm.sendAPDU(CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x04))
        let length = Int(Array(head.data)[1]) + 2
        #expect(length == 22)
        let rest = try await sm.sendAPDU(
            CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x04, le: UInt8(length - 4))
        )

        let sent = mock.sentAPDUs.map(\.bytes)
        #expect(sent.count == 5)
        #expect(sent[0] == icaoHex("0084000008"))
        #expect(sent[1] == icaoHex("0082000028") + Self.dEIFD + Self.dMIFD + icaoHex("28"))
        #expect(sent[2] == icaoHex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"))
        #expect(sent[3] == icaoHex("0CB000000D9701048E08ED6705417E96BA5500"))
        #expect(sent[4] == icaoHex("0CB000040D9701128E082EA28A70F3C7B53500"))
        #expect(select.isSuccess)

        let efCOM = head.data + rest.data
        #expect(efCOM == icaoHex("60145F0104303130365F36063034303030305C026175"))
        let com = try COMParser.parse(efCOM)
        #expect(com.ldsVersion == "0106")
        #expect(com.unicodeVersion == "040000")
        #expect(com.dataGroups == [.dg1, .dg2])
    }

    // MARK: - Part 11 D.4: secure messaging intermediate values

    @Test
    func `D.4 step 1 SELECT EF.COM intermediate values`() throws {
        let cmdHeader = ISO9797Padding.pad(icaoHex("0CA4020C"), blockSize: 8)
        #expect(cmdHeader == icaoHex("0CA4020C80000000"))
        let paddedData = ISO9797Padding.pad(icaoHex("011E"), blockSize: 8)
        #expect(paddedData == icaoHex("011E800000000000"))
        let encrypted = try CryptoUtils.tripleDESEncrypt(key: Self.dKSEnc, message: paddedData)
        #expect(encrypted == icaoHex("6375432908C044F6"))
        let builtDO87 = ASN1Parser.encodeTLV(tag: 0x87, value: Data([0x01]) + encrypted)
        #expect(builtDO87 == icaoHex("8709016375432908C044F6"))
        let m = cmdHeader + builtDO87
        #expect(m == icaoHex("0CA4020C800000008709016375432908C044F6"))

        let n = ISO9797Padding.pad(icaoHex("887022120C06C227") + m, blockSize: 8)
        #expect(n == icaoHex("887022120C06C2270CA4020C800000008709016375432908C044F68000000000"))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: n) == icaoHex("BF8B92D635FF24F8"))

        // Response: MAC over SSC || DO'99'.
        let k = ISO9797Padding.pad(icaoHex("887022120C06C228") + icaoHex("990290 00"), blockSize: 8)
        #expect(k == icaoHex("887022120C06C2289902900080000000"))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: k) == icaoHex("FA855A5D4C50A8ED"))
    }

    @Test
    func `D.4 steps 2 and 3 READ BINARY intermediate values`() throws {
        // Step 2: READ BINARY, offset 0, Le 4.
        let header2 = ISO9797Padding.pad(icaoHex("0CB00000"), blockSize: 8)
        #expect(header2 == icaoHex("0CB0000080000000"))
        let do97a = ASN1Parser.encodeTLV(tag: 0x97, value: Data([0x04]))
        #expect(do97a == icaoHex("970104"))
        let n2 = ISO9797Padding.pad(icaoHex("887022120C06C229") + header2 + do97a, blockSize: 8)
        #expect(n2 == icaoHex("887022120C06C2290CB00000800000009701048000000000"))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: n2) == icaoHex("ED6705417E96BA55"))

        let k2 = ISO9797Padding.pad(
            icaoHex("887022120C06C22A") + icaoHex("8709019FF0EC34F9922651") + icaoHex("99029000"),
            blockSize: 8
        )
        #expect(k2 == icaoHex("887022120C06C22A8709019FF0EC34F992265199029000 80"))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: k2) == icaoHex("AD55CC17140B2DED"))
        let plain2 = try CryptoUtils.tripleDESDecrypt(key: Self.dKSEnc, message: icaoHex("9FF0EC34F9922651"))
        #expect(try ISO9797Padding.strictUnpad(plain2, blockSize: 8) == icaoHex("60145F01"))

        // Step 3: READ BINARY, offset 4, Le 18.
        let header3 = ISO9797Padding.pad(icaoHex("0CB00004"), blockSize: 8)
        #expect(header3 == icaoHex("0CB0000480000000"))
        let do97b = ASN1Parser.encodeTLV(tag: 0x97, value: Data([0x12]))
        #expect(do97b == icaoHex("970112"))
        let n3 = ISO9797Padding.pad(icaoHex("887022120C06C22B") + header3 + do97b, blockSize: 8)
        #expect(n3 == icaoHex("887022120C06C22B0CB00004800000009701128000000000"))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: n3) == icaoHex("2EA28A70F3C7B535"))

        // The spec prints K for step 3 without its padding; the MAC is over the padded K.
        let encrypted3 = icaoHex("FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A")
        let k3 = icaoHex("887022120C06C22C") + icaoHex("871901") + encrypted3 + icaoHex("99029000")
        #expect(k3 == icaoHex(
            "887022120C06C22C871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000"
        ))
        #expect(try ISO9797MAC.mac(key: Self.dKSMac, message: ISO9797Padding.pad(k3, blockSize: 8))
            == icaoHex("C8B2787EAEA07D74"))
        let plain3 = try CryptoUtils.tripleDESDecrypt(key: Self.dKSEnc, message: encrypted3)
        #expect(try ISO9797Padding.strictUnpad(plain3, blockSize: 8)
            == icaoHex("04303130365F36063034303030305C026175"))
    }

    // MARK: - Part 11 Appendix F: Active Authentication

    private static let fRndIFD = icaoHex("F173589974BF40C6")
    private static let fM1 = icaoHex(
        "9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991"
            + "B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F967"
            + "84D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E"
            + "7292E2DCDA3024B47DA8"
    )
    private static let fDigest = icaoHex("C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127")

    @Test
    func `F INTERNAL AUTHENTICATE command carries RND.IFD`() {
        #expect(CommandAPDU.internalAuthenticate(data: Self.fRndIFD).bytes == icaoHex("0088000008F173589974BF40C600"))
    }

    @Test
    func `F message representative is parsed with ISO 9796-2 partial recovery and SHA-1`() throws {
        // Step 9 / Step 12: F = '6A' || M1 || H || 'BC'. The example does not publish the
        // AA public key, so the RSA step itself cannot be replayed; this checks everything
        // ActiveAuthenticationVerifier.verifyRSA does after the RSA public operation.
        let f = icaoHex(
            "6A9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC19"
                + "91B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F9"
                + "6784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD"
                + "4E7292E2DCDA3024B47DA8C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127BC"
        )
        #expect(f.count == 128)
        #expect(Self.fM1.count * 8 == 848)

        let parsed = try #require(ActiveAuthenticationVerifier.parseRecoveredRSASignature(f))
        #expect(parsed.0.algorithmName == "sha1")
        #expect(parsed.0.digestLength == 20)
        #expect(parsed.1 == Self.fM1)
        #expect(parsed.2 == Self.fDigest)

        // Step 7–8 / 16–17: M* = M1 || RND.IFD, D* = SHA-1(M*).
        #expect(HashUtils.sha1(Self.fM1 + Self.fRndIFD) == Self.fDigest)
        #expect(parsed.0.compute(parsed.1 + Self.fRndIFD) == parsed.2)
    }

    // MARK: - Part 11 Appendix G: PACE Generic Mapping

    @Test
    func `G MRZ encoding K and K_pi for the PACE examples`() throws {
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "T22000129",
            dateOfBirth: "640812",
            dateOfExpiry: "101031"
        )
        #expect(mrzKey == "T22000129364081251010318")
        #expect(HashUtils.sha1(Data(mrzKey.utf8)) == icaoHex("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"))
        // Kπ is the same for the AES-128 G.1 and G.2 examples.
        #expect(try PACEHandler.derivePasswordKey(password: mrzKey, keyReference: .mrz, mode: .aes128)
            == icaoHex("89DED1B26624EC1E634C1989302849DD"))
    }

    @Test
    func `G.1 PACEInfo DER from EF.CardAccess is parsed as supported ECDH-GM AES-128 on brainpoolP256r1`() throws {
        let paceInfo = icaoHex("3012060A04007F00070202040202020102 02010D")
        let infos = try CardAccessParser.parse(icaoHex("3114") + paceInfo)
        let info = try #require(infos.paceInfos.first)
        #expect(infos.paceInfos.count == 1)
        #expect(info.protocolOID == "0.4.0.127.0.7.2.2.4.2.2")
        #expect(info.securityProtocol == .paceECDHGMAESCBCCMAC128)
        #expect(info.version == 2)
        #expect(info.parameterID == 13)
        #expect(PACEHandler.isSupported(info))
        #expect(PACEHandler.selectPACEInfo(from: infos) == info)
    }

    private static let g2PACEInfo = icaoHex("3012060A04007F00070202040102020102020100")
    private static let g2KSMac = icaoHex("805A1D27D45A5116F73C54469462B7D8")
    private static let g2PKIC = icaoHex(
        "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152B"
            + "D8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC"
            + "71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064"
            + "386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1"
    )
    private static let g2PKPCD = icaoHex(
        "907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD91155"
            + "1B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08F"
            + "A8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236"
            + "B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4"
    )

    @Test
    func `G.2 DH PACEInfo is parsed and refused before any APDU`() async throws {
        let infos = try CardAccessParser.parse(icaoHex("3114") + Self.g2PACEInfo)
        let info = try #require(infos.paceInfos.first)
        #expect(info.protocolOID == "0.4.0.127.0.7.2.2.4.1.2")
        #expect(info.securityProtocol == .paceDHGMAESCBCCMAC128)
        #expect(info.version == 2)
        #expect(info.parameterID == 0)
        #expect(!PACEHandler.isSupported(info))
        #expect(PACEHandler.selectPACEInfo(from: infos) == nil)

        let mock = MockTransport()
        do {
            _ = try await PACEHandler.performPACE(
                paceInfo: info,
                password: "T22000129364081251010318",
                keyReference: .mrz,
                transport: mock
            )
            Issue.record("DH Generic Mapping should be refused")
        } catch NFCError.unsupportedOperation {
            // expected
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `G.2 MSE Set AT and General Authenticate framing match the DH trace`() throws {
        let oid = icaoHex("04007F00070202040102")
        #expect(CommandAPDU.mseSetAT(oid: oid, keyRef: PACEHandler.KeyReference.mrz.rawValue).bytes
            == icaoHex("0022C1A40F800A04007F000702020401028301 01"))
        #expect(CommandAPDU.generalAuthenticate(data: icaoHex("7C00")).bytes == icaoHex("10860000027C0000"))

        let tIFD = icaoHex("B46DD9BD4D98381F")
        let mutual = CommandAPDU.generalAuthenticate(
            data: PACEHandler.encodeDynamicAuthenticationData(tag: 0x85, value: tIFD),
            isLast: true
        )
        #expect(mutual.bytes == icaoHex("008600000C7C0A8508B46DD9BD4D98381F00"))
    }

    @Test
    func `G.2 nonce, chip key, session keys and tokens from the DH trace`() throws {
        // Encrypted nonce response and its decryption with Kπ.
        let z = try PACEHandler.parseTag80FromDynamicAuth(icaoHex("7C128010854D8DF5827FA6852D1A4FA701CDDDCA"))
        #expect(z == icaoHex("854D8DF5827FA6852D1A4FA701CDDDCA"))
        let s = try CryptoUtils.aesDecrypt(
            key: icaoHex("89DED1B26624EC1E634C1989302849DD"),
            message: z,
            iv: Data(count: 16)
        )
        #expect(s == icaoHex("FA5B7E3E49753A0DB9178B7B9BD898C8"))

        // Key agreement response: '84' carries the chip's ephemeral DH public key.
        let response = icaoHex("7C8183848180") + Self.g2PKIC
        #expect(try PACEHandler.parseTag84FromDynamicAuth(response) == Self.g2PKIC)

        // Session keys from the 1024-bit shared secret.
        let sharedSecret = icaoHex(
            "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3"
                + "8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5"
                + "990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E"
                + "465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD"
        )
        let keys = PACEHandler.derivePACESessionKeys(sharedSecret: sharedSecret, mode: .aes128)
        #expect(keys.ksEnc == icaoHex("2F7F46ADCC9E7E521B45D192FAFA9126"))
        #expect(keys.ksMac == Self.g2KSMac)

        // Token input: 7F49 { 06 OID, 84 DH public key } (DH keys use tag '84').
        let oid = icaoHex("04007F00070202040102")
        func tokenInput(_ publicKey: Data) -> Data {
            ASN1Parser.encodeTLV(
                tag: 0x7F49,
                value: ASN1Parser.encodeTLV(tag: 0x06, value: oid) + ASN1Parser.encodeTLV(tag: 0x84, value: publicKey)
            )
        }
        let inputIFD = tokenInput(Self.g2PKIC)
        #expect(inputIFD == icaoHex("7F49818F060A04007F00070202040102848180") + Self.g2PKIC)
        let inputIC = tokenInput(Self.g2PKPCD)
        #expect(inputIC == icaoHex("7F49818F060A04007F00070202040102848180") + Self.g2PKPCD)
        #expect(try AESCMAC.mac(key: keys.ksMac, message: inputIFD).prefix(8) == icaoHex("B46DD9BD4D98381F"))
        #expect(try AESCMAC.mac(key: keys.ksMac, message: inputIC).prefix(8) == icaoHex("917F37B5C0E6D8D1"))

        // Mutual authentication response: '86' T_IC and '87' CAR "DETESTCVCA00003".
        let final = icaoHex("7C1B8608917F37B5C0E6D8D1870F444554455354435643413030303033")
        #expect(try PACEHandler.parseTag86FromDynamicAuth(final) == icaoHex("917F37B5C0E6D8D1"))
        let car = try ASN1Parser.parseTLV(final).first?.children().first(where: { $0.tag == 0x87 })
        #expect(car.map { String(decoding: $0.value, as: UTF8.self) } == "DETESTCVCA00003")
    }

    // MARK: - Part 11 Appendix I: PACE Chip Authentication Mapping

    @Test
    func `I MRZ encoding K and K_pi for the PACE-CAM example`() throws {
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "C11T002JM",
            dateOfBirth: "960812",
            dateOfExpiry: "231031"
        )
        #expect(mrzKey == "C11T002JM496081222310314")
        #expect(HashUtils.sha1(Data(mrzKey.utf8)) == icaoHex("894D03F148C6265E89845B218856EA34D00EF8E8"))
        #expect(try PACEHandler.derivePasswordKey(password: mrzKey, keyReference: .mrz, mode: .aes128)
            == icaoHex("4E6F6FBF7BE748B932C7B74161BBA9DF"))
    }

    @Test
    func `I.1 PACE-CAM PACEInfo is refused before any APDU`() async throws {
        let infos = try CardAccessParser.parse(icaoHex("3114" + "3012060A04007F00070202040602020102 02010D"))
        let info = try #require(infos.paceInfos.first)
        // id-PACE-ECDH-CAM-AES-CBC-CMAC-128 (BSI TR-03110-3).
        #expect(info.protocolOID == "0.4.0.127.0.7.2.2.4.6.2")
        #expect(info.version == 2)
        #expect(info.parameterID == 13)
        #expect(!PACEHandler.isSupported(info))

        let mock = MockTransport()
        do {
            _ = try await PACEHandler.performPACE(
                paceInfo: info,
                password: "C11T002JM496081222310314",
                keyReference: .mrz,
                transport: mock
            )
            Issue.record("PACE-CAM should be refused")
        } catch NFCError.unsupportedOperation {
            // expected
        }
        #expect(mock.sentAPDUs.isEmpty)
    }

    @Test
    func `I ChipAuthenticationPublicKeyInfo from EF.CardSecurity is parsed`() throws {
        let caInfo = icaoHex(
            "3062060904007F0007020201023052300C060704007F0007010202010D034200"
                + "041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610D"
                + "C884D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E1"
                + "6F02010D"
        )
        #expect(caInfo.count == 0x64)
        let infos = try DG14Parser.parseSecurityInfos(icaoHex("3164") + caInfo, wrapperTag: nil)
        let key = try #require(infos.chipAuthPublicKeyInfos.first)
        #expect(infos.chipAuthPublicKeyInfos.count == 1)
        #expect(key.protocolOID == "0.4.0.127.0.7.2.2.1.2") // id-PK-ECDH
        #expect(key.keyID == 13)
        #expect(key.subjectPublicKey == caInfo[13 ..< 97])
        #expect(key.subjectPublicKey.prefix(2) == icaoHex("3052"))

        // The public point inside the SPKI is PK_IC from the I.1 table.
        let spki = try #require(ASN1Parser.parseTLV(key.subjectPublicKey).first)
        let parts = try spki.children()
        #expect(parts.count == 2)
        #expect(try parts[0].children().map(\.tag) == [0x06, 0x02])
        #expect(DG14Parser.decodeOID(try parts[0].children()[0].value) == "0.4.0.127.0.7.1.2")
        #expect(parts[1].tag == 0x03)
        #expect(parts[1].value == icaoHex("0004") + icaoHex(
            "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8"
                + "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F"
        ))

        // Wrapped as EF.DG14 it parses the same way.
        let dg14 = try DG14Parser.parse(icaoHex("6E66") + icaoHex("3164") + caInfo)
        #expect(dg14.chipAuthPublicKeyInfos == infos.chipAuthPublicKeyInfos)
    }

    // MARK: - Part 3 Appendix A: check digits

    @Test
    func `Part 3 Appendix A check digit examples 1 to 5`() {
        // Example 1: date 27 July 1952.
        #expect(MRZKeyGenerator.checkDigit("520727") == "3")
        // Example 2: 9-character document number AB2134<<<.
        #expect(MRZKeyGenerator.checkDigit("AB2134<<<") == "5")
        // Example 3: TD3 composite over lower-line positions 1–10, 14–20, 22–43.
        let td3Lower = "HA672242<6YTO5802254M9601086<<<<<<<<<<<<<<0"
        #expect(td3Lower.count == 43)
        #expect(MRZKeyGenerator.checkDigit(Self.td3CompositeInput(td3Lower + "8")) == "8")
        // Example 4: TD1 composite over upper 6–30, middle 1–7, 9–15, 19–29.
        let upper = "I<YTOD231458907<<<<<<<<<<<<<<<"
        let middle = "3407127M9507122YTO<<<<<<<<<<<2"
        #expect(MRZKeyGenerator.checkDigit(Self.td1CompositeInput(upper: upper, middle: middle)) == "2")
        // Example 5: TD2 composite over lower-line positions 1–10, 14–20, 22–35.
        let td2Lower = "HA672242<6YTO5802254M9601086<<<<<<<8"
        #expect(MRZKeyGenerator.checkDigit(Self.td2CompositeInput(td2Lower)) == "8")
    }

    // MARK: - Part 4 / Part 3 TD3 specimens

    @Test
    func `Part 4 Figure A-1 TD3 specimen parses with every field and check digit`() throws {
        let upper = "PPUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
        let lower = "L898902C36UTO7408122F3404159ZE184226B<<<<<16"
        let mrz = try MRZData(mrzString: upper + lower)
        #expect(mrz.format == .td3)
        #expect(mrz.documentCode == "PP")
        #expect(mrz.issuingState == "UTO")
        #expect(mrz.lastName == "ERIKSSON")
        #expect(mrz.firstName == "ANNA MARIA")
        #expect(mrz.documentNumber == "L898902C3")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.dateOfBirth == "740812")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "340415")
        #expect(mrz.optionalData1 == "ZE184226B")
        #expect(mrz.optionalData2 == "")

        #expect(MRZKeyGenerator.checkDigit("L898902C3") == "6")
        #expect(MRZKeyGenerator.checkDigit("740812") == "2")
        #expect(MRZKeyGenerator.checkDigit("340415") == "9")
        #expect(MRZKeyGenerator.checkDigit("ZE184226B<<<<<") == "1")
        #expect(MRZKeyGenerator.checkDigit(Self.td3CompositeInput(lower)) == "6")
        #expect(MRZKeyGenerator.computeMRZKey(
            documentNumber: mrz.documentNumber,
            dateOfBirth: mrz.dateOfBirth,
            dateOfExpiry: mrz.dateOfExpiry
        ) == "L898902C3674081223404159")
    }

    @Test
    func `Part 3 TD3 specimen lower line check digits`() {
        // Part 3 §4 figure: expiry 120415, composite 0.
        let lower = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        #expect(MRZKeyGenerator.checkDigit("120415") == "9")
        #expect(MRZKeyGenerator.checkDigit(Self.td3CompositeInput(lower)) == "0")
    }

    @Test
    func `Part 5 and Part 6 specimens have consistent composite check digits`() {
        // Part 5 (TD1) specimen.
        #expect(MRZKeyGenerator.checkDigit(Self.td1CompositeInput(
            upper: "I<UTOD231458907<<<<<<<<<<<<<<<",
            middle: "7408122F1204159UTO<<<<<<<<<<<6"
        )) == "6")
        // Part 6 (TD2) specimen.
        #expect(MRZKeyGenerator.checkDigit(Self.td2CompositeInput("D231458907UTO7408122F1204159<<<<<<<6")) == "6")
    }

    // MARK: - Parts 4, 5 and 6: name field examples

    @Test
    func `Part 4 TD3 name examples split into primary and secondary identifiers`() {
        let cases: [(String, String, String)] = [
            ("PPUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "ERIKSSON", "ANNA MARIA"),
            ("PPUTOHENG<<DEBORAH<MING<LO<<<<<<<<<<<<<<<<<<", "HENG", "DEBORAH MING LO"),
            ("PPUTOSMITH<JONES<<SUSIE<MARGARET<<<<<<<<<<<<", "SMITH JONES", "SUSIE MARGARET"),
            ("PPUTOOCONNOR<<ENYA<SIOBHAN<<<<<<<<<<<<<<<<<<", "OCONNOR", "ENYA SIOBHAN"),
            ("PPUTOVAN<DER<MUELLEN<<MARTIN<<<<<<<<<<<<<<<<", "VAN DER MUELLEN", "MARTIN"),
            ("PPUTOAL<BASRI<<HUDA<MUHAMMAD<JAWAD<<<<<<<<<<", "AL BASRI", "HUDA MUHAMMAD JAWAD"),
            ("PPUTOVILARCHAO<FERNANDEZ<<JOSE<RAMON<<<<<<<<", "VILARCHAO FERNANDEZ", "JOSE RAMON"),
            ("PPUTOARKFREITH<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "ARKFREITH", ""),
            ("PPUTOSATRIYA<SUDARPA<<<<<<<<<<<<<<<<<<<<<<<<", "SATRIYA SUDARPA", ""),
            ("PPUTONILAVADHANANANDA<<CHAYAPA<DEJTHAMRONG<K", "NILAVADHANANANDA", "CHAYAPA DEJTHAMRONG K"),
            ("PPUTONILAVADHANANANDA<<ARNPOL<PETCH<CHARONGU", "NILAVADHANANANDA", "ARNPOL PETCH CHARONGU"),
            ("PPUTOBENNELONG<WOOLOOMOOLOO<WARRANDYTE<W<<DI", "BENNELONG WOOLOOMOOLOO WARRANDYTE W", "DI"),
            ("PPUTOBENNELONG<WOOLOOM<WARRAND<WARNAM<<DINGO", "BENNELONG WOOLOOM WARRAND WARNAM", "DINGO"),
            ("PPUTOBENNEL<WOOLOO<WARRAN<WARNAM<<DINGO<POTO", "BENNEL WOOLOO WARRAN WARNAM", "DINGO POTO"),
            ("PPUTOPAPANDROPOULOUS<<JONATHON<WARREN<TREVOR", "PAPANDROPOULOUS", "JONATHON WARREN TREVOR"),
        ]
        for (line, last, first) in cases {
            #expect(line.count == 44, "\(line)")
            let (parsedLast, parsedFirst) = MRZData.parseNames(String(line.dropFirst(5)))
            #expect(parsedLast == last, "\(line)")
            #expect(parsedFirst == first, "\(line)")
        }
    }

    @Test
    func `Part 5 TD1 name examples split into primary and secondary identifiers`() {
        let cases: [(String, String, String)] = [
            ("NILAVADHANANANDA<<CHAYAPA<DE<K", "NILAVADHANANANDA", "CHAYAPA DE K"),
            ("NILAVADHANANANDA<<ARNPOL<PE<CH", "NILAVADHANANANDA", "ARNPOL PE CH"),
            ("BENNELONG<WOOLOOMOOLOO<W<W<<DI", "BENNELONG WOOLOOMOOLOO W W", "DI"),
            ("BENNELONG<WOOLOOM<WA<WARN<<D<P", "BENNELONG WOOLOOM WA WARN", "D P"),
            ("BENNE<WOOLO<WARRA<WARNA<<DIN<P", "BENNE WOOLO WARRA WARNA", "DIN P"),
            ("PAPANDROPOULOUS<<JONATHON<ALEC", "PAPANDROPOULOUS", "JONATHON ALEC"),
            ("VAN<DER<MUELLEN<<MARTIN<<<<<<<", "VAN DER MUELLEN", "MARTIN"),
            ("AL<BASRI<<HUDA<MUHAMMAD<JAWAD<", "AL BASRI", "HUDA MUHAMMAD JAWAD"),
            ("VILARCHAO<FERNANDEZ<<JOSE<RAMO", "VILARCHAO FERNANDEZ", "JOSE RAMO"),
            ("ARKFREITH<<<<<<<<<<<<<<<<<<<<<", "ARKFREITH", ""),
            ("SATRIYA<SUDARPA<<<<<<<<<<<<<<<", "SATRIYA SUDARPA", ""),
        ]
        for (line, last, first) in cases {
            #expect(line.count == 30, "\(line)")
            let (parsedLast, parsedFirst) = MRZData.parseNames(line)
            #expect(parsedLast == last, "\(line)")
            #expect(parsedFirst == first, "\(line)")
        }
    }

    @Test
    func `Part 6 TD2 name examples split into primary and secondary identifiers`() {
        let cases: [(String, String, String)] = [
            ("I<UTONILAVADHANANANDA<<CHAYAPA<DEJ<K", "NILAVADHANANANDA", "CHAYAPA DEJ K"),
            ("I<UTONILAVADHANANANDA<<ARN<PET<CHARO", "NILAVADHANANANDA", "ARN PET CHARO"),
            ("I<UTOBENNELONG<WOOLOOMOOLOO<W<W<<D<P", "BENNELONG WOOLOOMOOLOO W W", "D P"),
            ("I<UTOBENNELONG<WOOLOOM<WAR<WARN<<D<P", "BENNELONG WOOLOOM WAR WARN", "D P"),
            ("I<UTOBENNEL<WOOLO<WARRA<WARNA<<DIN<P", "BENNEL WOOLO WARRA WARNA", "DIN P"),
            // Spelled JONATHOON in Part 6 §4.2.3.3.
            ("I<UTOPAPANDROPOULOUS<<JONATHOON<ALEC", "PAPANDROPOULOUS", "JONATHOON ALEC"),
            ("I<UTOVAN<DER<MUELLEN<<MARTIN<<<<<<<<", "VAN DER MUELLEN", "MARTIN"),
            ("I<UTOAL<BASRI<<HUDA<MUHAMMAD<JAWAD<<", "AL BASRI", "HUDA MUHAMMAD JAWAD"),
            ("I<UTOVILARCHAO<FERNANDEZ<<JOSE<RAMON", "VILARCHAO FERNANDEZ", "JOSE RAMON"),
            ("I<UTOARKFREITH<<<<<<<<<<<<<<<<<<<<<<", "ARKFREITH", ""),
            ("I<UTOSATRIYA<SUDARPA<<<<<<<<<<<<<<<<", "SATRIYA SUDARPA", ""),
        ]
        for (line, last, first) in cases {
            #expect(line.count == 36, "\(line)")
            let (parsedLast, parsedFirst) = MRZData.parseNames(String(line.dropFirst(5)))
            #expect(parsedLast == last, "\(line)")
            #expect(parsedFirst == first, "\(line)")
        }
    }

    // MARK: - Part 10 Appendix A: LDS mapping examples

    @Test
    func `Part 10 A.1 EF.COM for LDS 1.7 with DG1, DG2, DG4 and DG12`() throws {
        let com = icaoHex("6016" + "5F010430313037" + "5F3606303430303030" + "5C046175766C")
        let parsed = try COMParser.parse(com)
        #expect(parsed.ldsVersion == "0107")
        #expect(parsed.unicodeVersion == "040000")
        #expect(parsed.dataGroups == [.dg1, .dg2, .dg4, .dg12])

        let hypothetical = try COMParser.parse(
            icaoHex("6016" + "5F010431353939" + "5F3606303430303030" + "5C046175766C")
        )
        #expect(hypothetical.ldsVersion == "1599")
    }

    @Test
    func `Part 10 A.2.1 EF.DG1 for a TD1 document`() throws {
        let mrzString = "I<NLDXI85935F86999999990<<<<<<"
            + "7208148F1108268NLD<<<<<<<<<<<4"
            + "VAN<DER<STEEN<<MARIANNE<LOUISE"
        let dg1 = icaoHex("615D5F1F5A") + Data(mrzString.utf8)
        #expect(dg1.count == 0x5D + 2)

        let mrz = try DG1Parser.parse(dg1)
        #expect(mrz.format == .td1)
        #expect(mrz.documentCode == "I")
        #expect(mrz.issuingState == "NLD")
        #expect(mrz.documentNumber == "XI85935F8")
        #expect(mrz.optionalData1 == "999999990")
        #expect(mrz.dateOfBirth == "720814")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "110826")
        #expect(mrz.nationality == "NLD")
        #expect(mrz.optionalData2 == "")
        #expect(mrz.lastName == "VAN DER STEEN")
        #expect(mrz.firstName == "MARIANNE LOUISE")
        #expect(mrz.mrzString == mrzString)

        #expect(MRZKeyGenerator.checkDigit("XI85935F8") == "6")
        #expect(MRZKeyGenerator.checkDigit("720814") == "8")
        #expect(MRZKeyGenerator.checkDigit("110826") == "8")
    }

    @Test
    func `Part 10 A.5 EF.DG11 additional personal details`() throws {
        var body = icaoHex("5C0A5F0E5F115F425F125F13")
        body += icaoHex("5F0E0D") + Data("SMITH<<JOHN<J".utf8)
        body += icaoHex("5F110A") + Data("ANYTOWN<MN".utf8)
        body += icaoHex("5F4217") + Data("123 MAPLE RD<ANYTOWN<MN".utf8)
        body += icaoHex("5F120E") + Data("1-612-555-1212".utf8)
        body += icaoHex("5F130C") + Data("TRAVEL<AGENT".utf8)
        #expect(body.count == 0x63)

        let fields = try DG11Parser.parse(icaoHex("6B63") + body)
        #expect(fields["fullName"] == "SMITH<<JOHN<J")
        #expect(fields["placeOfBirth"] == "ANYTOWN<MN")
        #expect(fields["address"] == "123 MAPLE RD<ANYTOWN<MN")
        #expect(fields["telephone"] == "1-612-555-1212")
        #expect(fields["profession"] == "TRAVEL<AGENT")
        #expect(fields.count == 5)
    }

    // MARK: - Composite check digit inputs (Part 3 §4.9, Parts 4–6 §4.2.4)

    private static func td3CompositeInput(_ lower: String) -> String {
        let c = Array(lower)
        return String(c[0 ..< 10]) + String(c[13 ..< 20]) + String(c[21 ..< 43])
    }

    private static func td2CompositeInput(_ lower: String) -> String {
        let c = Array(lower)
        return String(c[0 ..< 10]) + String(c[13 ..< 20]) + String(c[21 ..< 35])
    }

    private static func td1CompositeInput(upper: String, middle: String) -> String {
        let u = Array(upper)
        let m = Array(middle)
        return String(u[5 ..< 30]) + String(m[0 ..< 7]) + String(m[8 ..< 15]) + String(m[18 ..< 29])
    }
}
