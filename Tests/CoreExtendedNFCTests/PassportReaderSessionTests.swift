// PassportReader session behaviour over a simulated BAC chip.
//
// ## References
// - ICAO Doc 9303 Part 11, §9.7 (BAC) and §9.8 (secure messaging; SM errors end the session)
// - ICAO Doc 9303 Part 11, Appendix D (MRZ key and chip randoms used by the simulator)
// - ISO/IEC 7816-4 §11.3.3: READ BINARY odd INS B1 with offset DO'54, response DO'53
@testable import CoreExtendedNFC
import Foundation
import Testing

struct PassportReaderSessionTests {
    private static let mrzKey = "L898902C<369080619406236"

    @Test
    func `Passport reader surfaces secure messaging failures instead of returning a partial model`() async {
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: Self.makeDG1()])
        chip.plainSuccessForProtectedCommands = true

        await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: chip).readPassport(
                mrzKey: Self.mrzKey,
                dataGroups: [.com, .dg1],
                performActiveAuth: false
            )
        }
    }

    @Test
    func `Passport reader skips data groups the chip reports as absent`() async throws {
        let dg1 = Self.makeDG1()
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: dg1])
        chip.plainNotFoundForMissingFiles = true

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.com, .dg1],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.com] == nil)
        #expect(model.rawDataGroups[.dg1] == dg1)
    }

    @Test
    func `Passport reader fails on a short read instead of returning a truncated data group`() async {
        let dg1 = Self.makeDG1()
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: dg1])
        chip.endOfFileOffset = dg1.count - 10

        await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: chip).readPassport(
                mrzKey: Self.mrzKey,
                dataGroups: [.dg1],
                performActiveAuth: false
            )
        }
    }

    @Test
    func `Passport reader reads data groups larger than 32 KB with READ BINARY B1`() async throws {
        let imageBytes = Data((0 ..< 40000).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let dg2 = ASN1Parser.encodeTLV(tag: 0x75, value: imageBytes)
        let chip = SimulatedBACChip(files: [DataGroupId.dg2.fileID: dg2])

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg2],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg2] == dg2)
        #expect(chip.oddReadBinaryCount > 0)
    }

    @Test
    func `Passport reader honours task cancellation between data groups`() async {
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: Self.makeDG1()])
        let task = Task {
            try await PassportReader(transport: chip).readPassport(
                mrzKey: Self.mrzKey,
                dataGroups: [.dg1],
                performActiveAuth: false
            )
        }
        task.cancel()

        await #expect(throws: CancellationError.self) {
            _ = try await task.value
        }
    }

    private static func makeDG1() -> Data {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
            + "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        return ASN1Parser.encodeTLV(tag: 0x61, value: ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data(mrz.utf8)))
    }
}

/// A BAC-only eMRTD simulator with 3DES secure messaging (ICAO 9303-11 Appendix D randoms).
final class SimulatedBACChip: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])

    var plainSuccessForProtectedCommands = false
    var plainNotFoundForMissingFiles = false
    var endOfFileOffset: Int?
    private(set) var oddReadBinaryCount = 0

    private let files: [Data: Data]
    private let mrzKey = "L898902C<369080619406236"
    private let rndICC = vectorHex("4608F91988702212")
    private let kICC = vectorHex("0B4F80323EB3191CB04970CB4052790B")
    private var sessionKeys: (enc: Data, mac: Data)?
    private var ssc = Data()
    private var selectedFile: Data?

    init(files: [Data: Data]) {
        self.files = files
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw transport is not used in passport APDU tests")
    }

    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        if apdu.cla & 0x0C == 0x0C {
            return try handleProtected(apdu)
        }
        switch apdu.ins {
        case 0xA4 where apdu.p1 == 0x04:
            return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
        case 0x84:
            return ResponseAPDU(data: rndICC, sw1: 0x90, sw2: 0x00)
        case 0x82:
            return try mutualAuthenticate(apdu)
        default:
            // EF.CardAccess and PACE are not supported.
            return ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
        }
    }

    private func mutualAuthenticate(_ apdu: CommandAPDU) throws -> ResponseAPDU {
        let request = try #require(apdu.data)
        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let kenc = KeyDerivation.deriveKey(keySeed: kseed, mode: .enc)
        let kmac = KeyDerivation.deriveKey(keySeed: kseed, mode: .mac)

        let plaintext = try CryptoUtils.tripleDESDecrypt(key: kenc, message: Data(request.prefix(32)))
        let rndIFD = Data(plaintext[0 ..< 8])
        let kIFD = Data(plaintext[16 ..< 32])

        let response = try CryptoUtils.tripleDESEncrypt(key: kenc, message: rndICC + rndIFD + kICC)
        let mac = try ISO9797MAC.mac(key: kmac, message: ISO9797Padding.pad(response, blockSize: 8))

        let seed = Data(zip(kIFD, kICC).map { $0 ^ $1 })
        sessionKeys = (
            KeyDerivation.deriveKey(keySeed: seed, mode: .enc),
            KeyDerivation.deriveKey(keySeed: seed, mode: .mac)
        )
        ssc = Data(rndICC[4 ..< 8]) + Data(rndIFD[4 ..< 8])
        return ResponseAPDU(data: response + mac, sw1: 0x90, sw2: 0x00)
    }

    private func handleProtected(_ apdu: CommandAPDU) throws -> ResponseAPDU {
        guard let keys = sessionKeys else {
            return ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x82)
        }
        if plainSuccessForProtectedCommands {
            return ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
        }

        incrementSSC()
        let nodes = try ASN1Parser.parseTLV(try #require(apdu.data))
        let cryptogram = nodes.first { $0.tag == 0x87 || $0.tag == 0x85 }
        let do97 = nodes.first { $0.tag == 0x97 }
        let mac = try #require(nodes.first { $0.tag == 0x8E })

        var macInput = ssc + ISO9797Padding.pad(Data([apdu.cla, apdu.ins, apdu.p1, apdu.p2]), blockSize: 8)
        if let cryptogram { macInput += ASN1Parser.encodeTLV(tag: cryptogram.tag, value: cryptogram.value) }
        if let do97 { macInput += ASN1Parser.encodeTLV(tag: 0x97, value: do97.value) }
        let expectedMAC = try ISO9797MAC.mac(key: keys.mac, message: ISO9797Padding.pad(macInput, blockSize: 8))
        guard expectedMAC == mac.value else {
            throw NFCError.secureMessagingError("Simulated chip: command MAC mismatch")
        }

        var commandData = Data()
        if let cryptogram {
            let encrypted = cryptogram.tag == 0x87 ? Data(cryptogram.value.dropFirst()) : cryptogram.value
            commandData = ISO9797Padding.unpad(try CryptoUtils.tripleDESDecrypt(key: keys.enc, message: encrypted))
        }
        let le = do97.map { Int($0.value[$0.value.startIndex]) } ?? 0
        let expected = le == 0 ? 256 : le

        let (data, sw): (Data, UInt16)
        switch apdu.ins {
        case 0xA4:
            if files[commandData] != nil {
                selectedFile = commandData
                (data, sw) = (Data(), 0x9000)
            } else if plainNotFoundForMissingFiles {
                incrementSSC()
                return ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
            } else {
                (data, sw) = (Data(), 0x6A82)
            }
        case 0xB0:
            let offset = (Int(apdu.p1 & 0x7F) << 8) | Int(apdu.p2)
            (data, sw) = read(offset: offset, length: expected)
        case 0xB1:
            oddReadBinaryCount += 1
            let offsetNode = try #require(try ASN1Parser.parseTLV(commandData).first { $0.tag == 0x54 })
            let offset = offsetNode.value.reduce(0) { ($0 << 8) | Int($1) }
            // Ne covers the DO'53 header: 2 bytes below 128 content bytes, else 3.
            let content = expected - 2 < 0x80 ? expected - 2 : expected - 3
            let (chunk, status) = read(offset: offset, length: content)
            (data, sw) = (status == 0x9000 ? ASN1Parser.encodeTLV(tag: 0x53, value: chunk) : Data(), status)
        default:
            (data, sw) = (Data(), 0x6D00)
        }

        incrementSSC()
        return try protectResponse(data: data, sw: sw, oddINS: apdu.ins & 0x01 == 0x01, keys: keys)
    }

    private func read(offset: Int, length: Int) -> (Data, UInt16) {
        guard let selectedFile, let file = files[selectedFile] else { return (Data(), 0x6986) }
        let limit = min(endOfFileOffset ?? file.count, file.count)
        guard offset < limit else { return (Data(), 0x6B00) }
        let end = min(offset + length, limit)
        return (Data(file[offset ..< end]), 0x9000)
    }

    private func protectResponse(data: Data, sw: UInt16, oddINS: Bool, keys: (enc: Data, mac: Data)) throws -> ResponseAPDU {
        var objects = Data()
        if !data.isEmpty {
            let encrypted = try CryptoUtils.tripleDESEncrypt(key: keys.enc, message: ISO9797Padding.pad(data, blockSize: 8))
            objects += oddINS
                ? ASN1Parser.encodeTLV(tag: 0x85, value: encrypted)
                : ASN1Parser.encodeTLV(tag: 0x87, value: Data([0x01]) + encrypted)
        }
        objects += Data([0x99, 0x02, UInt8(sw >> 8), UInt8(sw & 0xFF)])
        let mac = try ISO9797MAC.mac(key: keys.mac, message: ISO9797Padding.pad(ssc + objects, blockSize: 8))
        return ResponseAPDU(data: objects + Data([0x8E, 0x08]) + mac, sw1: 0x90, sw2: 0x00)
    }

    private func incrementSSC() {
        var value = ssc.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).bigEndian }
        value &+= 1
        ssc = withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}
