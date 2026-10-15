// NFC Forum Type 4 Tag test suite.
//
// ## References
// - NFC Forum Type 4 Tag Operation Specification v2.0
// - NFC Forum Type 4 Tag: NDEF AID = D2760000850101
//   https://nfc-forum.org/build/specifications
// - ISO/IEC 7816-4: SELECT by DF name (P1=04), READ BINARY (INS=B0)
// - libnfc nfc-emulate-forum-tag4.c:
//   https://github.com/nfc-tools/libnfc/blob/master/examples/nfc-emulate-forum-tag4.c
@testable import CoreExtendedNFC
import Foundation
import Testing

struct Type4Tests {
    // MARK: - Constants

    @Test
    func `NDEF AID is correct`() {
        #expect(Type4Constants.ndefAID == Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]))
    }

    @Test
    func `CC file ID is E103`() {
        #expect(Type4Constants.ccFileID == Data([0xE1, 0x03]))
    }

    @Test
    func `NDEF file ID is E104`() {
        #expect(Type4Constants.ndefFileID == Data([0xE1, 0x04]))
    }

    // MARK: - CC Parsing

    @Test
    func `Parse valid CC file`() throws {
        // CC: len=000F, ver=20, MLe=003B, MLc=0034
        // TLV: T=04, L=06, FileID=E104, MaxSize=00FE, Read=00, Write=00
        let ccData = Data([
            0x00, 0x0F, // ccLen = 15
            0x20, // mapping version 2.0
            0x00, 0x3B, // MLe = 59
            0x00, 0x34, // MLc = 52
            0x04, 0x06, // NDEF File Control TLV
            0xE1, 0x04, // NDEF file ID
            0x00, 0xFE, // max NDEF size = 254
            0x00, // read access = free
            0x00, // write access = free
        ])

        let cc = try Type4CC(data: ccData)
        #expect(cc.ccLen == 15)
        #expect(cc.mappingVersion == 0x20)
        #expect(cc.mle == 59)
        #expect(cc.mlc == 52)
        #expect(cc.ndefFileID == Data([0xE1, 0x04]))
        #expect(cc.ndefMaxSize == 254)
        #expect(cc.readAccess == 0x00)
        #expect(cc.writeAccess == 0x00)
    }

    @Test
    func `CC parse rejects wrong TLV tag`() {
        var ccData = Data(repeating: 0x00, count: 15)
        ccData[7] = 0x05 // wrong TLV tag (should be 0x04)
        ccData[8] = 0x06

        #expect(throws: NFCError.self) {
            _ = try Type4CC(data: ccData)
        }
    }

    @Test
    func `CC parse rejects short data`() {
        #expect(throws: NFCError.self) {
            _ = try Type4CC(data: Data(repeating: 0x00, count: 10))
        }
    }

    // MARK: - NDEF Read Sequence

    @Test
    func `Full NDEF read sequence via mock`() async throws {
        let mock = MockTransport()

        // NDEF message: "Hello"
        let ndefMessage = Data([0x48, 0x65, 0x6C, 0x6C, 0x6F])

        mock.apduResponses = [
            // 1. SELECT AID → success
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            // 2. SELECT CC file → success
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            // 3. READ CC file (15 bytes)
            ResponseAPDU(data: Data([
                0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x34,
                0x04, 0x06, 0xE1, 0x04, 0x00, 0xFE, 0x00, 0x00,
            ]), sw1: 0x90, sw2: 0x00),
            // 4. SELECT NDEF file → success
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            // 5. READ NDEF length (2 bytes)
            ResponseAPDU(data: Data([0x00, 0x05]), sw1: 0x90, sw2: 0x00),
            // 6. READ NDEF data
            ResponseAPDU(data: ndefMessage, sw1: 0x90, sw2: 0x00),
        ]

        let reader = Type4Reader(transport: mock)
        let ndef = try await reader.readNDEF()
        #expect(ndef == ndefMessage)

        // Verify SELECT AID was first command
        #expect(mock.sentAPDUs[0].ins == 0xA4) // SELECT
        #expect(mock.sentAPDUs[0].p1 == 0x04) // by DF name
    }

    @Test
    func `NDEF read returns empty for zero-length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([
                0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x34,
                0x04, 0x06, 0xE1, 0x04, 0x00, 0xFE, 0x00, 0x00,
            ]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00]), sw1: 0x90, sw2: 0x00),
        ]

        let reader = Type4Reader(transport: mock)
        let ndef = try await reader.readNDEF()
        #expect(ndef.isEmpty)
    }

    // MARK: - Termination and bounds (NFC Forum T4T 2.0/3.0 §5.1)

    private static let ok = ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
    private static let cc20 = Data([
        0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x34,
        0x04, 0x06, 0xE1, 0x04, 0x00, 0x32, 0x00, 0x00,
    ])

    @Test
    func `readNDEF throws on empty 9000 READ BINARY instead of looping`() async {
        let mock = MockTransport()
        mock.apduResponses = [
            Self.ok, Self.ok,
            ResponseAPDU(data: Self.cc20, sw1: 0x90, sw2: 0x00),
            Self.ok,
            ResponseAPDU(data: Data([0x00, 0x05]), sw1: 0x90, sw2: 0x00),
        ] + Array(repeating: Self.ok, count: 50)
        do {
            _ = try await Type4Reader(transport: mock).readNDEF()
            Issue.record("expected throw")
        } catch NFCError.invalidResponse {
        } catch {
            Issue.record("wrong error \(error)")
        }
        #expect(mock.sentAPDUs.count == 6)
    }

    @Test
    func `readNDEF rejects NLEN larger than the NDEF file`() async {
        let mock = MockTransport()
        // Max NDEF file size 0x32 = 50 → NLEN must be <= 48.
        mock.apduResponses = [
            Self.ok, Self.ok,
            ResponseAPDU(data: Self.cc20, sw1: 0x90, sw2: 0x00),
            Self.ok,
            ResponseAPDU(data: Data([0xFF, 0xFF]), sw1: 0x90, sw2: 0x00),
        ]
        await #expect(throws: NFCError.self) {
            _ = try await Type4Reader(transport: mock).readNDEF()
        }
        #expect(mock.sentAPDUs.count == 5)
    }

    @Test
    func `CC parse rejects MLe or MLc of zero`() {
        var noMLc = Self.cc20
        noMLc[5] = 0x00
        noMLc[6] = 0x00
        #expect(throws: NFCError.self) { _ = try Type4CC(data: noMLc) }

        var noMLe = Self.cc20
        noMLe[3] = 0x00
        noMLe[4] = 0x00
        #expect(throws: NFCError.self) { _ = try Type4CC(data: noMLe) }
    }

    @Test
    func `CC parse rejects unsupported major mapping version`() {
        var cc = Self.cc20
        cc[2] = 0x40
        #expect(throws: NFCError.self) { _ = try Type4CC(data: cc) }
    }

    @Test
    func `CC parse accepts T4T 3.0 Extended NDEF File Control TLV`() throws {
        let data = Data([
            0x00, 0x11, 0x30, 0x00, 0xFF, 0x00, 0xFF,
            0x06, 0x08, 0xE1, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ])
        let cc = try Type4CC(data: data)
        #expect(cc.usesExtendedNDEFFile)
        #expect(cc.maxNDEFFileSize == 0x0001_0000)
        #expect(cc.ndefMaxSize == 0xFFFF)
        #expect(cc.ndefFileID == Data([0xE1, 0x04]))
        #expect(cc.ndefLengthFieldSize == 4)
        #expect(cc.encoded == data)
    }

    @Test
    func `Extended NDEF file is read with a 4-byte ENLEN`() async throws {
        let mock = MockTransport()
        let ccHead = Data([
            0x00, 0x11, 0x30, 0x00, 0xFF, 0x00, 0xFF,
            0x06, 0x08, 0xE1, 0x04, 0x00, 0x00, 0x10, 0x00,
        ])
        let message = Data([0xD0, 0x00, 0x00])
        mock.apduResponses = [
            Self.ok, Self.ok,
            ResponseAPDU(data: ccHead, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data([0x00, 0x00]), sw1: 0x90, sw2: 0x00),
            Self.ok,
            ResponseAPDU(data: Data([0x00, 0x00, 0x00, 0x03]), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: message, sw1: 0x90, sw2: 0x00),
        ]
        let ndef = try await Type4Reader(transport: mock).readNDEF()
        #expect(ndef == message)
        // CC tail read at offset 15, ENLEN read with Le = 4, data read at offset 4.
        #expect(mock.sentAPDUs[3].p2 == 15)
        #expect(mock.sentAPDUs[5].le == 4)
        #expect(mock.sentAPDUs[6].p2 == 4)
    }

    @Test
    func `writeNDEF chunks by MLc and writes NLEN last`() async throws {
        let mock = MockTransport()
        let cc = Data([
            0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x02,
            0x04, 0x06, 0xE1, 0x04, 0x00, 0x32, 0x00, 0x00,
        ])
        mock.apduResponses = [Self.ok, Self.ok, ResponseAPDU(data: cc, sw1: 0x90, sw2: 0x00)]
            + Array(repeating: Self.ok, count: 10)
        try await Type4Reader(transport: mock).writeNDEF(Data([1, 2, 3]))

        let updates = mock.sentAPDUs.filter { $0.ins == 0xD6 }
        #expect(updates.map(\.p2) == [0, 2, 4, 0])
        #expect(updates.map { $0.data ?? Data() } == [Data([0, 0]), Data([1, 2]), Data([3]), Data([0, 3])])
    }
}
