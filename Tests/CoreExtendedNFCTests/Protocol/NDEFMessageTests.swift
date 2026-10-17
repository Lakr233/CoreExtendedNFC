// NDEF message parsing/serialisation conformance tests.
//
// ## References
// - NFC Forum NDEF 1.0 §2.3.3 (record chunks), §3.2.6 (TNF 0x06 "Unchanged")
// - NFC Forum URI RTD 1.0 §3.2.2 (identifier codes 0x24–0xFF are RFU → no prefix)
// - NFC Forum Text RTD 1.0 §3.4 (UTF-16 without BOM is big-endian)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NDEFMessageTests {
    // MARK: URI prefix codes

    @Test
    func `URI record with RFU prefix code is decoded without a prefix`() {
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x55]), payload: Data([0x24]) + Data("example".utf8))
        #expect(record.parsedPayload == .uri("example"))

        let highCode = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x55]), payload: Data([0xFF]) + Data("x".utf8))
        #expect(highCode.parsedPayload == .uri("x"))
        #expect(highCode.displayValue == "x")
    }

    @Test
    func `URI record with last defined prefix code 0x23`() {
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x55]), payload: Data([0x23]) + Data("sn:x".utf8))
        #expect(record.parsedPayload == .uri("urn:nfc:sn:x"))
    }

    // MARK: Text encoding

    @Test
    func `UTF-16 text without BOM is big-endian`() {
        // Status 0x82: UTF-16, language code length 2.
        let payload = Data([0x82]) + Data("en".utf8) + Data([0x00, 0x48, 0x00, 0x69])
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x54]), payload: payload)
        #expect(record.parsedPayload == .text(languageCode: "en", text: "Hi"))
    }

    @Test
    func `UTF-16 text honours a little-endian BOM`() {
        let payload = Data([0x82]) + Data("en".utf8) + Data([0xFF, 0xFE, 0x48, 0x00, 0x69, 0x00])
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x54]), payload: payload)
        #expect(record.parsedPayload == .text(languageCode: "en", text: "Hi"))
    }

    @Test
    func `UTF-16 text honours a big-endian BOM`() {
        let payload = Data([0x82]) + Data("en".utf8) + Data([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69])
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x54]), payload: payload)
        #expect(record.parsedPayload == .text(languageCode: "en", text: "Hi"))
    }

    @Test
    func `Text record truncates language codes to 63 bytes`() throws {
        let language = String(repeating: "a", count: 70)
        let record = NDEFRecord.text("Hello", languageCode: language)
        #expect(record.payload.first == 0x3F)
        let parsed = try NDEFMessage(data: NDEFMessage(records: [record]).data).records[0].parsedPayload
        #expect(parsed == .text(languageCode: String(repeating: "a", count: 63), text: "Hello"))
    }

    // MARK: Chunked records (NDEF 1.0 §2.3.3)

    private static let chunkedMessage = Data(
        [0xB2, 0x0A, 0x03] + Array("text/plain".utf8) + Array("abc".utf8) // MB CF SR, TNF=MIME
            + [0x36, 0x00, 0x02] + Array("de".utf8) // CF SR, TNF=Unchanged
            + [0x56, 0x00, 0x01] + Array("f".utf8) // ME SR, TNF=Unchanged
    )

    @Test
    func `Chunked record payloads are reassembled`() throws {
        let message = try NDEFMessage(data: Self.chunkedMessage)
        #expect(message.records == [
            NDEFRecord(typeNameFormat: .mimeMedia, type: Data("text/plain".utf8), payload: Data("abcdef".utf8)),
        ])
    }

    @Test
    func `Chunk sequence followed by a normal record`() throws {
        var data = Self.chunkedMessage
        data[data.startIndex + 13 + 5 + 3] = 0x16 // terminating chunk without ME
        data.append(contentsOf: [0x51, 0x01, 0x01, 0x55, 0x00]) // ME SR well-known "U", empty prefix
        let message = try NDEFMessage(data: data)
        #expect(message.records.count == 2)
        #expect(message.records[0].payload == Data("abcdef".utf8))
        #expect(message.records[1].parsedPayload == .uri(""))
    }

    @Test
    func `Middle chunk with a type is rejected`() {
        let data = Data([0xB2, 0x01, 0x01, 0x78, 0x61] + [0x56, 0x01, 0x01, 0x78, 0x62])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    @Test
    func `Unterminated chunk sequence is rejected`() {
        // Initial chunk only; the message ends before a terminating chunk.
        let data = Data([0xB2, 0x01, 0x01, 0x78, 0x61])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    @Test
    func `Chunk flag together with message end is rejected`() {
        let data = Data([0xF2, 0x01, 0x01, 0x78, 0x61])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    @Test
    func `TNF Unchanged outside a chunk sequence is rejected`() {
        let data = Data([0xD6, 0x00, 0x01, 0x61])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    // MARK: Robustness

    @Test
    func `Sliced Data parses from its start index`() throws {
        let full = Data([0xFF]) + NDEFMessage.uri("https://example.com").data
        let message = try NDEFMessage(data: full.dropFirst())
        #expect(message.records.first?.parsedPayload == .uri("https://example.com"))
    }

    @Test
    func `Serialising a type longer than 255 bytes does not trap`() throws {
        let longType = String(repeating: "a", count: 300)
        let message = NDEFMessage(records: [.mime(type: longType, data: Data([0x01]))])
        let data = message.data
        #expect(data[1] == 0xFF)
        #expect(throws: NFCError.self) { _ = try message.validatedData() }
    }

    @Test
    func `Serialising an ID longer than 255 bytes does not trap`() {
        let record = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x54]), identifier: Data(count: 256), payload: Data([0x00]))
        let message = NDEFMessage(records: [record])
        #expect(message.data[3] == 0xFF) // header, type length, payload length, ID length
        #expect(throws: NFCError.self) { _ = try message.validatedData() }
    }

    @Test
    func `validatedData matches data for encodable messages`() throws {
        let message = NDEFMessage(records: [.uri("https://example.com"), .text("Hi")])
        #expect(try message.validatedData() == message.data)
        #expect(throws: NFCError.self) { _ = try NDEFMessage(records: []).validatedData() }
    }

    // MARK: MB / ME position

    // NFC Forum NDEF 1.0 §3.2.1: MB is set on the first record of a message and on
    // no other record. A message whose first record lacks MB is malformed.
    @Test
    func `First record without MB is rejected`() {
        let data = Data([0x11, 0x01, 0x01, 0x55, 0x00, 0xD1, 0x01, 0x01, 0x55, 0x00])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    // NFC Forum NDEF 1.0 §3.2.1: MB must not be set on a later record.
    @Test
    func `MB on a record after the first is rejected`() {
        let data = Data([0x91, 0x01, 0x01, 0x55, 0x00, 0xD1, 0x01, 0x01, 0x55, 0x00])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: data) }
    }

    // NFC Forum NDEF 1.0 §3.2.2: ME is set on the last record only, so a record after
    // the ME record and a message whose last record lacks ME are both malformed.
    @Test
    func `ME on a non-last record or missing ME is rejected`() {
        let earlyEnd = Data([0xD1, 0x01, 0x01, 0x55, 0x00, 0x51, 0x01, 0x01, 0x55, 0x00])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: earlyEnd) }
        let missingEnd = Data([0x91, 0x01, 0x01, 0x55, 0x00, 0x11, 0x01, 0x01, 0x55, 0x00])
        #expect(throws: NFCError.self) { _ = try NDEFMessage(data: missingEnd) }
    }

    // NFC Forum NDEF 1.0 §3.2.1 / §3.2.2 / §2.3.3: MB on the first record, ME on the
    // last, plain records in between and chunk sequences are all valid.
    @Test
    func `Messages with MB first and ME last still parse`() throws {
        let three = Data([
            0x91, 0x01, 0x01, 0x55, 0x00,
            0x11, 0x01, 0x01, 0x55, 0x00,
            0x51, 0x01, 0x01, 0x55, 0x00,
        ])
        #expect(try NDEFMessage(data: three).records.count == 3)

        let chunked = Data([0xB1, 0x01, 0x01, 0x55, 0x00, 0x56, 0x00, 0x01, 0x41])
        let records = try NDEFMessage(data: chunked).records
        #expect(records.count == 1)
        #expect(records.first?.payload == Data([0x00, 0x41]))
    }
}
