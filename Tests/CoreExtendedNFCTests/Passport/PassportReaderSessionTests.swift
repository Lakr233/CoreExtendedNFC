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

    @Test
    func `Plain 6982 on an EAC data group marks it unavailable and keeps the others`() async throws {
        let dg1 = Self.makeDG1()
        let dg2 = ASN1Parser.encodeTLV(tag: 0x75, value: Data(repeating: 0xAB, count: 300))
        let sod = ASN1Parser.encodeTLV(tag: 0x77, value: Data(repeating: 0x01, count: 40))
        let dg3 = ASN1Parser.encodeTLV(tag: 0x63, value: Data(repeating: 0x02, count: 40))
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.dg2.fileID: dg2,
            DataGroupId.dg3.fileID: dg3,
            DataGroupId.sod.fileID: sod,
        ])
        chip.plainReadStatus = [DataGroupId.dg3.fileID: 0x6982]

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg3, .dg2, .sod],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.rawDataGroups[.dg2] == dg2)
        #expect(model.rawDataGroups[.sod] == sod)
        #expect(model.rawDataGroups[.dg3] == nil)
        #expect(model.dataGroupReadStatus?[.dg3]?.state == .unavailable)
        #expect(model.dataGroupReadStatus?[.dg1]?.state == .read)
    }

    @Test
    func `Data groups neither EF.COM nor the SOD lists are never selected`() async throws {
        let dg1 = Self.makeDG1()
        // COM lists only DG1 (tag 61); the SOD, read as the index, hashes only DG1.
        let com = Self.makeCOM(tags: [0x61])
        let sod = Self.makeUnsignedSOD(hashedDataGroups: [1])
        let chip = SimulatedBACChip(files: [
            DataGroupId.com.fileID: com,
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.sod.fileID: sod,
        ])
        chip.plainNotFoundForMissingFiles = true
        chip.endSessionAfterPlainError = true

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.com, .dg7, .dg1],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.rawDataGroups[.com] == com)
        #expect(model.rawDataGroups[.sod] == sod)
        #expect(model.dataGroupReadStatus?[.dg7]?.state == .notPresent)
        #expect(chip.selectedFileIDs == [vectorHex("011E"), vectorHex("0101"), vectorHex("011D")])
    }

    @Test
    func `EF.COM alone does not rule out a data group the chip has`() async throws {
        let dg1 = Self.makeDG1()
        let dg11 = ASN1Parser.encodeTLV(tag: 0x6B, value: ASN1Parser.encodeTLV(tag: 0x5F0E, value: Data("ANNA".utf8)))
        // An incomplete COM: lists only DG1, although DG11 is on the chip. No SOD.
        let com = Self.makeCOM(tags: [0x61])
        let chip = SimulatedBACChip(files: [
            DataGroupId.com.fileID: com,
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.dg11.fileID: dg11,
        ])
        chip.plainNotFoundForMissingFiles = true

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.com, .dg1, .dg11],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg11] == dg11)
        #expect(model.dataGroupReadStatus?[.dg11]?.state == .read)
        // The SOD was tried once as the index and reported absent.
        #expect(model.dataGroupReadStatus?[.sod]?.state == .unavailable)
        #expect(chip.selectedFileIDs.filter { $0 == vectorHex("011D") }.count == 1)
    }

    @Test
    func `EF.COM omission is settled by the SOD hash list`() async throws {
        let dg1 = Self.makeDG1()
        let dg11 = ASN1Parser.encodeTLV(tag: 0x6B, value: ASN1Parser.encodeTLV(tag: 0x5F0E, value: Data("ANNA".utf8)))
        let com = Self.makeCOM(tags: [0x61])
        let sod = Self.makeUnsignedSOD(hashedDataGroups: [1, 11])
        let chip = SimulatedBACChip(files: [
            DataGroupId.com.fileID: com,
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.dg11.fileID: dg11,
            DataGroupId.sod.fileID: sod,
        ])

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.com, .dg1, .dg11],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg11] == dg11)
        #expect(model.rawDataGroups[.sod] == sod)
    }

    @Test
    func `Progress messages come from the localization catalog with their arguments filled in`() async throws {
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: Self.makeDG1()])
        let messages = LockedValue<[String]>([])

        _ = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1],
            performActiveAuth: false,
            onProgress: { message in messages.withLock { $0.append(message) } }
        )

        // The run's language follows the simulator (en or zh-Hans).
        let delivered = messages.withLock { $0 }
        #expect(delivered.contains("Authenticating…") || delivered.contains("正在认证…"))
        #expect(delivered.contains("Reading DG1 (MRZ) (1/1)…") || delivered.contains("正在读取 DG1 (MRZ)（1/1）…"))

        let zhBundle = try #require(
            Bundle.module.path(forResource: "zh-Hans", ofType: "lproj").flatMap(Bundle.init(path:))
        )
        let format = zhBundle.localizedString(forKey: "Reading %@ (%lld/%lld)…", value: nil, table: nil)
        #expect(String(format: format, "DG1", 1, 1) == "正在读取 DG1（1/1）…")
    }

    @Test
    func `Two EAC data groups refused with plain 6982 are both unavailable`() async throws {
        let dg1 = Self.makeDG1()
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: dg1])
        chip.plainSelectStatus = [
            DataGroupId.dg3.fileID: 0x6982,
            DataGroupId.dg4.fileID: 0x6982,
        ]

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg3, .dg4],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.dataGroupReadStatus?[.dg3]?.state == .unavailable)
        #expect(model.dataGroupReadStatus?[.dg4]?.state == .unavailable)
    }

    @Test
    func `Plain 6982 after a different plain error still ends the session`() async throws {
        let chip = SimulatedBACChip(files: [:])
        chip.plainSelectStatus = [
            DataGroupId.dg11.fileID: 0x6A82,
            DataGroupId.dg12.fileID: 0x6982,
        ]
        let session = try await BACHandler.performBAC(mrzKey: Self.mrzKey, transport: chip)

        await #expect(throws: NFCError.self) { _ = try await session.sendAPDU(.selectEF(id: DataGroupId.dg11.fileID)) }
        #expect(await session.isSessionEnded == false)
        await #expect(throws: NFCError.self) { _ = try await session.sendAPDU(.selectEF(id: DataGroupId.dg12.fileID)) }
        #expect(await session.isSessionEnded)
    }

    @Test
    func `Plain 6982 after another plain 6982 keeps the session`() async throws {
        let chip = SimulatedBACChip(files: [:])
        chip.plainSelectStatus = [
            DataGroupId.dg3.fileID: 0x6982,
            DataGroupId.dg4.fileID: 0x6982,
        ]
        let session = try await BACHandler.performBAC(mrzKey: Self.mrzKey, transport: chip)

        await #expect(throws: NFCError.self) { _ = try await session.sendAPDU(.selectEF(id: DataGroupId.dg3.fileID)) }
        await #expect(throws: NFCError.self) { _ = try await session.sendAPDU(.selectEF(id: DataGroupId.dg4.fileID)) }
        #expect(await session.isSessionEnded == false)
    }

    @Test
    func `Secure messaging ending after a plain error returns the data groups already read`() async throws {
        let dg1 = Self.makeDG1()
        let dg2 = ASN1Parser.encodeTLV(tag: 0x75, value: Data(repeating: 0xAB, count: 64))
        let chip = SimulatedBACChip(files: [DataGroupId.dg1.fileID: dg1, DataGroupId.dg2.fileID: dg2])
        chip.plainNotFoundForMissingFiles = true
        chip.endSessionAfterPlainError = true

        // No COM requested, so DG11 is selected, draws a plain 6A82 and the chip drops SM.
        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg11, .dg2, .dg12],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.rawDataGroups[.dg2] == nil)
        #expect(model.dataGroupReadStatus?[.dg11]?.state == .unavailable)
        #expect(model.dataGroupReadStatus?[.dg2]?.state == .notRead)
        #expect(model.dataGroupReadStatus?[.dg12]?.state == .notRead)
        #expect(chip.selectedFileIDs == [vectorHex("0101"), vectorHex("010B")])
        // Only DG2's SELECT reaches the keyless chip; DG12 is not tried once SM has ended.
        #expect(chip.commandsWithoutSession == 1)
    }

    @Test
    func `A lost tag while reading EF.CardAccess ends the read`() async {
        let transport = MockTransport()
        transport.apduFailures = [0: .tagConnectionLost]

        let error = await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: transport).readPassport(mrzKey: Self.mrzKey, dataGroups: [.dg1])
        }
        guard case .tagConnectionLost? = error else {
            Issue.record("Expected tagConnectionLost, got \(String(describing: error))")
            return
        }
        #expect(transport.sentAPDUs.count == 1)
    }

    @Test
    func `Cancellation while reading EF.CardAccess ends the read`() async {
        let transport = CancellingTransport()

        await #expect(throws: CancellationError.self) {
            _ = try await PassportReader(transport: transport).readPassport(mrzKey: Self.mrzKey, dataGroups: [.dg1])
        }
        #expect(transport.sentCount == 1)
    }

    @Test
    func `A lost tag during PACE ends the read instead of falling back to BAC`() async {
        // PACEInfo { id-PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameterId 12 } (BSI TR-03110-3 A.1.1)
        let cardAccess = vectorHex("3114" + "3012" + "060A04007F00070202040202" + "020102" + "02010C")
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT MF
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF.CardAccess
            ResponseAPDU(data: Data(cardAccess.prefix(4)), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: cardAccess, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT eMRTD application
        ]
        transport.apduFailures = [5: .tagConnectionLost] // MSE:Set AT

        let error = await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: transport).readPassport(mrzKey: Self.mrzKey, dataGroups: [.dg1])
        }
        guard case .tagConnectionLost? = error else {
            Issue.record("Expected tagConnectionLost, got \(String(describing: error))")
            return
        }
        #expect(transport.sentAPDUs.count == 6)
        #expect(transport.sentAPDUs.last?.ins == 0x22)
        #expect(!transport.sentAPDUs.contains { $0.ins == 0x84 })
    }

    @Test
    func `EF.CardAccess longer than 64 KB is rejected from its header`() async {
        // SET with a 4-byte length of 0x9FFFF0 bytes: under the old 10 MB limit, far above 64 KB.
        let transport = MockTransport()
        transport.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT MF
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00), // SELECT EF.CardAccess
            ResponseAPDU(data: vectorHex("31839FFF"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: vectorHex("F0300D060A04"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // SELECT eMRTD application
        ]

        await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: transport).readPassport(mrzKey: Self.mrzKey, dataGroups: [.dg1])
        }
        #expect(transport.sentAPDUs.count(where: { $0.ins == 0xB0 }) == 2)
        #expect(transport.sentAPDUs.count == 5)
        #expect(transport.sentAPDUs.last?.p1 == 0x04)
    }

    @Test
    func `Read order puts COM and DG1 first and EAC data groups last`() {
        #expect(PassportReader.readOrder(for: [.dg3, .sod, .dg2, .dg1, .com, .dg2]) == [.com, .sod, .dg1, .dg2, .dg3])
    }

    // MARK: - COM / SOD as data group index (ICAO 9303-10 §4.6)

    @Test
    func `A COM without a data group list does not hide DG1`() async throws {
        // 60 { 5F01 "0107", 5F36 "040000" } — no tag list (5C).
        let com = vectorTLV(0x60, vectorTLV(0x5F01, Data("0107".utf8)) + vectorTLV(0x5F36, Data("040000".utf8)))
        let dg1 = Self.makeDG1()
        let chip = SimulatedBACChip(files: [DataGroupId.com.fileID: com, DataGroupId.dg1.fileID: dg1])

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.com, .dg1],
            performActiveAuth: false
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.mrz != nil)
    }

    @Test
    func `A requested DG1 that cannot be read fails the read`() async {
        // COM lists only DG2, and the chip has no DG1.
        let com = Self.makeCOM(tags: [0x75])
        let dg2 = ASN1Parser.encodeTLV(tag: 0x75, value: Data(repeating: 0xAB, count: 64))
        let chip = SimulatedBACChip(files: [DataGroupId.com.fileID: com, DataGroupId.dg2.fileID: dg2])

        await #expect(throws: NFCError.self) {
            _ = try await PassportReader(transport: chip).readPassport(
                mrzKey: Self.mrzKey,
                dataGroups: [.com, .dg1, .dg2],
                performActiveAuth: false
            )
        }
    }

    @Test
    func `A data group listed only in the SOD is read and used for Active Authentication`() async throws {
        let com = Self.makeCOM(tags: [0x61, 0x75])
        let dg1 = Self.makeDG1()
        let dg2 = ASN1Parser.encodeTLV(tag: 0x75, value: Data(repeating: 0xAB, count: 64))
        let dg15 = Self.makeDG15()
        let sod = Self.makeUnsignedSOD(hashedDataGroups: [1, 2, 15])
        let chip = SimulatedBACChip(files: [
            DataGroupId.com.fileID: com,
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.dg2.fileID: dg2,
            DataGroupId.dg15.fileID: dg15,
            DataGroupId.sod.fileID: sod,
        ])
        chip.plainNotFoundForMissingFiles = true
        chip.endSessionAfterPlainError = true

        let model = try await PassportReader(transport: chip).readPassport(mrzKey: Self.mrzKey)

        #expect(model.rawDataGroups[.dg15] == dg15)
        #expect(chip.protectedINS.contains(0x88))
        #expect(model.dataGroupReadStatus?[.dg15]?.state == .read)
    }

    @Test
    func `Active Authentication runs before EAC data groups and a session dropped at INTERNAL AUTHENTICATE fails it`() async throws {
        let dg1 = Self.makeDG1()
        let dg15 = Self.makeDG15()
        let dg3 = ASN1Parser.encodeTLV(tag: 0x63, value: Data(repeating: 0x02, count: 40))
        let chip = SimulatedBACChip(files: [
            DataGroupId.dg1.fileID: dg1,
            DataGroupId.dg15.fileID: dg15,
            DataGroupId.dg3.fileID: dg3,
        ])
        // DG11 is absent: its plain 6A82 makes this strict chip drop its keys and answer
        // every later protected command with a plain 6982.
        chip.plainNotFoundForMissingFiles = true
        chip.endSessionAfterPlainError = true
        chip.plain6982WithoutSession = true

        let model = try await PassportReader(transport: chip).readPassport(
            mrzKey: Self.mrzKey,
            dataGroups: [.dg1, .dg3, .dg15, .dg11]
        )

        #expect(model.rawDataGroups[.dg1] == dg1)
        #expect(model.rawDataGroups[.dg15] == dg15)
        // DG15 is present, so a chip that does not sign the challenge fails AA: a clone
        // without the AA private key could drop the session the same way.
        #expect(model.securityReport.activeAuthentication.status == .failed)
        #expect(model.activeAuthResult?.status == .commandFailed)
        #expect(model.dataGroupReadStatus?[.dg3]?.state == .notRead)
        // AA is the last command: DG3 is not selected once the session is known to be over.
        #expect(chip.protectedINS.last == 0x88)
    }

    private static func makeCOM(tags: [UInt8]) -> Data {
        ASN1Parser.encodeTLV(
            tag: 0x60,
            value: ASN1Parser.encodeTLV(tag: 0x5F01, value: Data("0107".utf8))
                + ASN1Parser.encodeTLV(tag: 0x5F36, value: Data("040000".utf8))
                + ASN1Parser.encodeTLV(tag: 0x5C, value: Data(tags))
        )
    }

    /// DG15 with a P-256 SubjectPublicKeyInfo whose point is the curve generator (SEC 2 §2.4.2).
    private static func makeDG15() -> Data {
        let algorithm = vectorTLV(
            0x30,
            vectorTLV(0x06, vectorHex("2A8648CE3D0201")) + vectorTLV(0x06, vectorHex("2A8648CE3D030107"))
        )
        let point = vectorHex(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        return vectorTLV(0x6F, vectorTLV(0x30, algorithm + vectorTLV(0x03, Data([0x00]) + point)))
    }

    /// An unsigned SOD whose LDS security object lists (dummy) hashes for `hashedDataGroups`.
    private static func makeUnsignedSOD(hashedDataGroups: [UInt8]) -> Data {
        let sha256 = vectorTLV(0x30, vectorTLV(0x06, vectorHex("608648016503040201")))
        let hashes = hashedDataGroups.map { number in
            vectorTLV(0x30, vectorTLV(0x02, Data([number])) + vectorTLV(0x04, Data(repeating: number, count: 32)))
        }.reduce(Data(), +)
        let lds = vectorTLV(0x30, vectorTLV(0x02, Data([0x00])) + sha256 + vectorTLV(0x30, hashes))
        let encapContentInfo = vectorTLV(
            0x30,
            vectorTLV(0x06, vectorHex("678108010101")) + vectorTLV(0xA0, vectorTLV(0x04, lds))
        )
        let signedData = vectorTLV(0x30, vectorTLV(0x02, Data([0x03])) + vectorTLV(0x31, sha256) + encapContentInfo)
        let contentInfo = vectorTLV(0x30, vectorTLV(0x06, vectorHex("2A864886F70D010702")) + vectorTLV(0xA0, signedData))
        return vectorTLV(0x77, contentInfo)
    }

    private static func makeDG1() -> Data {
        let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
            + "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        return ASN1Parser.encodeTLV(tag: 0x61, value: ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data(mrz.utf8)))
    }
}

/// A transport whose first command observes the calling task being cancelled.
private final class CancellingTransport: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x01, 0x02, 0x03])
    private(set) var sentCount = 0

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Raw transport is not used")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        sentCount += 1
        throw CancellationError()
    }
}

/// A BAC-only eMRTD simulator with 3DES secure messaging (ICAO 9303-11 Appendix D randoms).
final class SimulatedBACChip: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55])

    var plainSuccessForProtectedCommands = false
    var plainNotFoundForMissingFiles = false
    var endOfFileOffset: Int?
    /// Files that can be selected but whose READ BINARY gets this plain status word
    /// (e.g. 6982 for an EAC-protected DG3 under BAC).
    var plainReadStatus: [Data: UInt16] = [:]
    /// Files whose SELECT gets this plain status word (e.g. 6982 for EAC DG3/DG4).
    var plainSelectStatus: [Data: UInt16] = [:]
    /// ICAO-strict behaviour: after answering with a plain status word the chip deletes
    /// its session keys, and every later protected command gets a plain 6988.
    var endSessionAfterPlainError = false
    /// With `endSessionAfterPlainError`: answer keyless protected commands with a plain
    /// 6982 instead of 6988, as some strict chips do.
    var plain6982WithoutSession = false
    /// INS of every protected command received, in order.
    private(set) var protectedINS: [UInt8] = []
    private(set) var oddReadBinaryCount = 0
    private(set) var selectedFileIDs: [Data] = []
    private(set) var commandsWithoutSession = 0

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
        protectedINS.append(apdu.ins)
        guard let keys = sessionKeys else {
            commandsWithoutSession += 1
            return endSessionAfterPlainError && !plain6982WithoutSession
                ? ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x88)
                : ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x82)
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
            selectedFileIDs.append(commandData)
            if let status = plainSelectStatus[commandData] {
                return plainError(status)
            } else if files[commandData] != nil {
                selectedFile = commandData
                (data, sw) = (Data(), 0x9000)
            } else if plainNotFoundForMissingFiles {
                return plainError(0x6A82)
            } else {
                (data, sw) = (Data(), 0x6A82)
            }
        case 0xB0:
            if let selectedFile, let status = plainReadStatus[selectedFile] {
                return plainError(status)
            }
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

    /// Answer a protected command with an unprotected status word.
    private func plainError(_ sw: UInt16) -> ResponseAPDU {
        incrementSSC()
        if endSessionAfterPlainError {
            sessionKeys = nil
        }
        return ResponseAPDU(data: Data(), sw1: UInt8(sw >> 8), sw2: UInt8(sw & 0xFF))
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
