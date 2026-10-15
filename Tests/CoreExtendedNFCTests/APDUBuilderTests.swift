// APDU builder test suite.
//
// ## References
// - ISO/IEC 7816-4:2020: APDU structure (CLA INS P1 P2 Lc Data Le)
// - ISO/IEC 7816-4: SELECT (INS=A4), READ BINARY (INS=B0)
// - NFC Forum Type 4 Tag: NDEF AID D2760000850101
// - NXP DESFire: ISO 7816 wrapping [90 CMD 00 00 Lc Data 00]
// - libnfc iso7816.h: ISO 7816 APDU defines
//   https://github.com/nfc-tools/libnfc/blob/master/libnfc/iso7816.h
@testable import CoreExtendedNFC
import Foundation
import Testing

struct APDUBuilderTests {
    @Test
    func `SELECT NDEF AID APDU bytes`() {
        let ndefAID = Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01])
        let apdu = CommandAPDU.select(aid: ndefAID)
        let bytes = apdu.bytes

        // Expected: [00 A4 04 00 07 D2760000850101 00]
        #expect(bytes[0] == 0x00) // CLA
        #expect(bytes[1] == 0xA4) // INS
        #expect(bytes[2] == 0x04) // P1
        #expect(bytes[3] == 0x00) // P2
        #expect(bytes[4] == 0x07) // Lc
        #expect(Data(bytes[5 ..< 12]) == ndefAID)
        #expect(bytes[12] == 0x00) // Le
        #expect(bytes.count == 13)
    }

    @Test
    func `DESFire wrap command with data`() {
        let apdu = CommandAPDU.desfireWrap(command: 0x5A, data: Data([0x01, 0x02, 0x03]))
        let bytes = apdu.bytes

        // Expected: [90 5A 00 00 03 010203 00]
        #expect(bytes[0] == 0x90)
        #expect(bytes[1] == 0x5A)
        #expect(bytes[2] == 0x00)
        #expect(bytes[3] == 0x00)
        #expect(bytes[4] == 0x03) // Lc
        #expect(bytes[5] == 0x01)
        #expect(bytes[6] == 0x02)
        #expect(bytes[7] == 0x03)
        #expect(bytes[8] == 0x00) // Le
    }

    @Test
    func `DESFire wrap command without data`() {
        let apdu = CommandAPDU.desfireWrap(command: 0x6A)
        let bytes = apdu.bytes

        // Expected: [90 6A 00 00 00] — no Lc/data since data is nil
        #expect(bytes[0] == 0x90)
        #expect(bytes[1] == 0x6A)
        #expect(bytes[2] == 0x00)
        #expect(bytes[3] == 0x00)
        #expect(bytes[4] == 0x00) // Le
        #expect(bytes.count == 5)
    }

    @Test
    func `READ BINARY APDU`() {
        let apdu = CommandAPDU.readBinary(offset: 0x0000, length: 0x0F)
        let bytes = apdu.bytes
        #expect(bytes[0] == 0x00) // CLA
        #expect(bytes[1] == 0xB0) // INS
        #expect(bytes[2] == 0x00) // P1 (offset high)
        #expect(bytes[3] == 0x00) // P2 (offset low)
        #expect(bytes[4] == 0x0F) // Le
    }

    @Test
    func `CoreNFC expected length maps short Le zero to 256`() {
        let apdu = CommandAPDU.internalAuthenticate(data: Data(repeating: 0xAA, count: 8))
        #expect(apdu.le == 0x00)
        #expect(apdu.nfcExpectedResponseLength == 256)
    }

    @Test
    func `CoreNFC expected length maps missing Le to wildcard`() {
        let apdu = CommandAPDU.selectPassportApplication()
        #expect(apdu.le == nil)
        #expect(apdu.nfcExpectedResponseLength == -1)
    }

    @Test
    func `ResponseAPDU success check`() {
        let resp = ResponseAPDU(data: Data([0x01, 0x02]), sw1: 0x90, sw2: 0x00)
        #expect(resp.isSuccess)
        #expect(resp.statusWord == 0x9000)
        #expect(!resp.needsGetResponse)
        #expect(!resp.hasMoreFrames)
    }

    @Test
    func `ResponseAPDU needs GET RESPONSE`() {
        let resp = ResponseAPDU(data: Data(), sw1: 0x61, sw2: 0x10)
        #expect(!resp.isSuccess)
        #expect(resp.needsGetResponse)
        #expect(resp.sw2 == 0x10) // 16 more bytes available
    }

    @Test
    func `ResponseAPDU DESFire AF chaining`() {
        let resp = ResponseAPDU(data: Data([0xAA, 0xBB]), sw1: 0x91, sw2: 0xAF)
        #expect(!resp.isSuccess)
        #expect(resp.hasMoreFrames)
    }

    @Test
    func `ResponseAPDU parse from raw bytes`() throws {
        let raw = Data([0x01, 0x02, 0x03, 0x90, 0x00])
        let resp = ResponseAPDU(rawResponse: raw)
        #expect(resp != nil)
        #expect(resp?.data == Data([0x01, 0x02, 0x03]))
        let parsed = try #require(resp)
        #expect(parsed.isSuccess)
    }

    @Test
    func `ResponseAPDU parse from too-short raw returns nil`() {
        let resp = ResponseAPDU(rawResponse: Data([0x90]))
        #expect(resp == nil)
    }
}

/// ISO/IEC 7816-4 §5.1 extended-length encoding and §11.2 odd-INS binary offsets.
struct APDUEncodingTests {
    @Test
    func `Case 3E: data longer than 255 bytes uses extended Lc`() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xD6, p1: 0x00, p2: 0x00, data: Data(count: 300))
        let bytes = apdu.bytes
        #expect(apdu.isExtendedLength)
        #expect(Data(bytes.prefix(7)) == Data([0x00, 0xD6, 0x00, 0x00, 0x00, 0x01, 0x2C]))
        #expect(bytes.count == 7 + 300)
    }

    @Test
    func `Case 2E: Ne above 256 uses 00 Le1 Le2`() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, expectedResponseLength: 1000)
        #expect(apdu.bytes == Data([0x00, 0xB0, 0x00, 0x00, 0x00, 0x03, 0xE8]))
        #expect(apdu.nfcExpectedResponseLength == 1000)
        #expect(apdu.le == 0x00)
    }

    @Test
    func `Case 2E: Ne 65536 encodes as 0000`() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, expectedResponseLength: 65536)
        #expect(apdu.bytes == Data([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00]))
    }

    @Test
    func `Case 4E: extended Lc and two-byte Le`() {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xD6, p1: 0x00, p2: 0x00,
            data: Data(repeating: 0xAB, count: 300), expectedResponseLength: 256
        )
        let bytes = apdu.bytes
        #expect(Data(bytes.prefix(7)) == Data([0x00, 0xD6, 0x00, 0x00, 0x00, 0x01, 0x2C]))
        #expect(Data(bytes.suffix(2)) == Data([0x01, 0x00]))
        #expect(bytes.count == 7 + 300 + 2)
    }

    @Test
    func `Short encoding is unchanged at the 255 and 256 boundaries`() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xD6, p1: 0x00, p2: 0x00, data: Data(count: 255), le: 0x00)
        let bytes = apdu.bytes
        #expect(!apdu.isExtendedLength)
        #expect(bytes[4] == 0xFF)
        #expect(bytes.last == 0x00)
        #expect(bytes.count == 4 + 1 + 255 + 1)
        #expect(apdu.expectedResponseLength == 256)
    }

    @Test
    func `Short Le initializer and explicit Ne compare equal`() {
        let short = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 0x00)
        let explicit = CommandAPDU(cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, expectedResponseLength: 256)
        #expect(short == explicit)
    }

    @Test
    func `READ BINARY offsets up to 0x7FFF stay in P1 P2`() {
        let apdu = CommandAPDU.readBinary(offset: 0x7FFF, length: 0x10)
        #expect(apdu.bytes == Data([0x00, 0xB0, 0x7F, 0xFF, 0x10]))
    }

    @Test
    func `READ BINARY at offset 0x8000 uses odd INS with offset DO 54`() {
        // Before: P1 bit 8 was masked, so this encoded as B0 00 00 and re-read offset 0.
        let apdu = CommandAPDU.readBinary(offset: 0x8000, length: 0x10)
        #expect(apdu.ins == 0xB1)
        #expect(apdu.p1 == 0x00)
        #expect(apdu.p2 == 0x00)
        #expect(apdu.data == Data([0x54, 0x02, 0x80, 0x00]))
        // Ne covers the DO'53 header (53 10) plus 16 content bytes.
        #expect(apdu.bytes == Data([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02, 0x80, 0x00, 0x12]))
    }

    @Test
    func `UPDATE BINARY at offset 0x8000 uses D7 with DO 54 and DO 53`() {
        let apdu = CommandAPDU.updateBinary(offset: 0x8000, data: Data([0x01, 0x02]))
        #expect(apdu.bytes == Data([0x00, 0xD7, 0x00, 0x00, 0x08, 0x54, 0x02, 0x80, 0x00, 0x53, 0x02, 0x01, 0x02]))
    }

    @Test
    func `UPDATE BINARY below 0x8000 keeps D6`() {
        let apdu = CommandAPDU.updateBinary(offset: 0x1234, data: Data([0xAA]))
        #expect(apdu.bytes == Data([0x00, 0xD6, 0x12, 0x34, 0x01, 0xAA]))
    }

    @Test
    func `Passport READ BINARY chunk never wraps offsets beyond 15 bits`() {
        let apdu = CommandAPDU.readBinaryChunk(offset: 0x8000, length: 0xA0)
        #expect(!(apdu.ins == 0xB0 && apdu.p1 == 0x00 && apdu.p2 == 0x00))
        #expect(apdu.ins == 0xB1)
        #expect(apdu.data == Data([0x54, 0x02, 0x80, 0x00]))
        #expect(apdu.expectedResponseLength == 0xA0 + 3) // 53 81 A0 header
    }

    @Test
    func `Passport READ BINARY chunk encodes offsets above 0xFFFF in three bytes`() {
        let apdu = CommandAPDU.readBinaryChunk(offset: 0x12345, length: 0xFF)
        #expect(apdu.data == Data([0x54, 0x03, 0x01, 0x23, 0x45]))
        #expect(apdu.expectedResponseLength == 256) // short Le, content clamped to 253
        #expect(apdu.le == 0x00)
    }

    @Test
    func `Passport READ BINARY chunk tolerates negative arguments`() {
        let apdu = CommandAPDU.readBinaryChunk(offset: -1, length: -5)
        #expect(apdu.bytes == Data([0x00, 0xB0, 0x00, 0x00, 0x00]))
    }

    @Test
    func `Odd-INS READ BINARY response is unwrapped from DO 53`() throws {
        let command = CommandAPDU.readBinary(offset: 0x9000, length: 3)
        let response = ResponseAPDU(data: Data([0x53, 0x03, 0xAA, 0xBB, 0xCC]), sw1: 0x90, sw2: 0x00)
        #expect(try response.binaryData(for: command) == Data([0xAA, 0xBB, 0xCC]))

        let longForm = ResponseAPDU(data: Data([0x53, 0x81, 0x02, 0x01, 0x02]), sw1: 0x90, sw2: 0x00)
        #expect(try longForm.binaryData(for: command) == Data([0x01, 0x02]))
    }

    @Test
    func `Odd-INS READ BINARY rejects malformed DO 53`() {
        let command = CommandAPDU.readBinary(offset: 0x9000, length: 3)
        let wrongTag = ResponseAPDU(data: Data([0x54, 0x01, 0xAA]), sw1: 0x90, sw2: 0x00)
        let truncated = ResponseAPDU(data: Data([0x53, 0x05, 0xAA]), sw1: 0x90, sw2: 0x00)
        #expect(throws: NFCError.self) { _ = try wrongTag.binaryData(for: command) }
        #expect(throws: NFCError.self) { _ = try truncated.binaryData(for: command) }
    }

    @Test
    func `Even-INS READ BINARY response passes through`() throws {
        let command = CommandAPDU.readBinary(offset: 0, length: 3)
        let response = ResponseAPDU(data: Data([0x53, 0x03, 0xAA]), sw1: 0x90, sw2: 0x00)
        #expect(try response.binaryData(for: command) == Data([0x53, 0x03, 0xAA]))
    }

    @Test
    func `6Cxx exposes the corrected Ne`() {
        #expect(ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x10).correctedExpectedLength == 16)
        #expect(ResponseAPDU(data: Data(), sw1: 0x6C, sw2: 0x00).correctedExpectedLength == 256)
        #expect(ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00).correctedExpectedLength == nil)
    }

    @Test
    func `Raw response parsing rebases the data`() throws {
        let raw = Data([0xFF, 0x01, 0x02, 0x90, 0x00]).dropFirst()
        let response = try #require(ResponseAPDU(rawResponse: raw))
        #expect(response.data == Data([0x01, 0x02]))
        #expect(response.data.startIndex == 0)
    }
}
