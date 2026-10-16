// NDEF and NFC Forum tag-mapping test vectors from public, citable sources.
//
// Each vector is bytes in -> parsed structure, and where the library can build
// the same structure, structure -> the same bytes out.
//
// ## Sources (pinned commits; line numbers refer to these revisions)
// - [ndeflib] github.com/nfcpy/ndeflib @ 2afb429d7f8cd98d9f673f4ea9f2cbbc8b5795c7
//   tests/test_record.py, test_message.py, test_text.py, test_uri.py, test_smartposter.py
// - [nfcpy] github.com/nfcpy/nfcpy @ 8a195262fe86167845d282ba5bc9cdaadf6441c4
//   tests/test_tag_tt2.py, test_tag_tt3.py, test_tag_tt4.py
// - [CTS] Android CTS tests/tests/ndef/src/android/ndef/cts/NdefTest.java
//   (mirror github.com/TeamWin/android_cts, branch android-13 @ b71af6ce9446d700f806cb3b4d6b96ec7b56380a)
// - [libnfc] github.com/nfc-tools/libnfc @ 3fa0751ad58fb0053d3de2e61bbbd4066259104c
//   examples/nfc-emulate-forum-tag2.c, utils/nfc-emulate-forum-tag4.c
// - [NTAG424] NXP NT4H2421Gx default CC file, as quoted in
//   github.com/AndroidCrypto/Ntag424SdmFeature README.md ("Default content of file 1")
// - [SparkFun] docs.sparkfun.com/SparkFun_ST25DV64KC_Arduino_Library/
//   sparkfun-st25dv64kc-arduino-library-examples/ex_08_NDEF_URI (ST25DV64KC CC + TLV)
//
// ## Transformations
// ndeflib's `Record._encode` / `_decode` handle one record with MB = ME = 0
// (test_message.py:14 shows the same empty record as the message `D00000`).
// Those single-record vectors are therefore used as one-record messages with
// MB | ME (C0h) OR-ed into the header byte.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NDEFVectorTests {
    // MARK: - Helpers

    /// Hex string (whitespace ignored) to bytes.
    private static func hex(_ string: String) -> Data {
        let digits = Array(string.filter { !$0.isWhitespace })
        precondition(digits.count.isMultiple(of: 2), "odd hex digit count in \(string)")
        return Data(stride(from: 0, to: digits.count, by: 2).map {
            UInt8(String(digits[$0 ... $0 + 1]), radix: 16)!
        })
    }

    private static func ascii(_ string: String) -> Data {
        Data(string.utf8)
    }

    /// Type 2 memory: CC in page 3 and `data` laid out from page 4.
    private static func type2Pages(cc: String, data: String) -> [MemoryDump.Page] {
        let bytes = hex(data)
        precondition(bytes.count.isMultiple(of: 4))
        return [MemoryDump.Page(number: 3, data: hex(cc))]
            + stride(from: 0, to: bytes.count, by: 4).enumerated().map {
                MemoryDump.Page(number: UInt8(4 + $0.offset), data: Data(bytes[$0.element ..< $0.element + 4]))
            }
    }

    /// Type 5 memory split into 4-byte blocks starting at block 0.
    private static func type5Blocks(_ bytes: Data) -> [MemoryDump.Block] {
        let padded = bytes + Data(repeating: 0x00, count: (4 - bytes.count % 4) % 4)
        return stride(from: 0, to: padded.count, by: 4).enumerated().map {
            MemoryDump.Block(number: $0.offset, data: Data(padded[$0.element ..< $0.element + 4]))
        }
    }

    /// CTS pattern: 1, 2, ..., 8 repeated, `count` bytes long.
    private static func ctsPattern(_ count: Int) -> Data {
        Data((0 ..< count).map { UInt8($0 % 8 + 1) })
    }

    private static func record(
        _ tnf: NDEFTypeNameFormat,
        type: Data = Data(),
        id: Data = Data(),
        payload: Data = Data()
    ) -> NDEFRecord {
        NDEFRecord(typeNameFormat: tnf, type: type, identifier: id, payload: payload)
    }

    // MARK: - NDEF record encoding: ndeflib test_record.py:216-226 (TestEncode.valid_encode_data)

    @Test
    func `ndeflib single-record encodings round-trip as one-record messages`() throws {
        // (record, ndeflib encoding with MB = ME = 0)
        let vectors: [(NDEFRecord, String)] = [
            (Self.record(.empty), "100000"),
            (Self.record(.wellKnown, type: Self.ascii("X")), "110100 58"),
            (Self.record(.mimeMedia, type: Self.ascii("text/plain")), "120a00 746578742f706c61696e"),
            (Self.record(.absoluteURI, type: Self.ascii("http://a.b/c")), "130c00 687474703a2f2f612e622f63"),
            (Self.record(.external, type: Self.ascii("a.com:type")), "140A00 612e636f6d3a74797065"),
            (Self.record(.unknown), "150000"),
            (Self.record(.wellKnown, type: Self.ascii("X"), id: Self.ascii("id")), "19010002 586964"),
            (
                Self.record(.wellKnown, type: Self.ascii("X"), id: Self.ascii("id"), payload: Self.ascii("payload")),
                "19010702 5869647061796c6f6164"
            ),
            (
                Self.record(.wellKnown, type: Self.ascii("X"), id: Self.ascii("id"), payload: Data(repeating: 0x70, count: 256)),
                "09010000010002 586964" + String(repeating: "70", count: 256)
            ),
        ]
        for (record, encoded) in vectors {
            var expected = Self.hex(encoded)
            expected[0] |= 0xC0 // MB | ME for a one-record message
            #expect(NDEFMessage(records: [record]).data == expected, "encode \(encoded)")
            #expect(try NDEFMessage(data: expected).records == [record], "decode \(encoded)")
        }
    }

    @Test
    func `ndeflib 1 MiB payload uses the 4-byte PAYLOAD_LENGTH`() throws {
        // ndeflib test_record.py:237-240 (TestEncode.test_limit): '050000100000' + 0x100000 zero bytes.
        let payload = Data(repeating: 0x00, count: 0x10_0000)
        let expected = Self.hex("C50000100000") + payload
        let record = Self.record(.unknown, payload: payload)
        #expect(NDEFMessage(records: [record]).data == expected)
        #expect(try NDEFMessage(data: expected).records == [record])
    }

    // MARK: - NDEF message framing: ndeflib test_message.py

    @Test
    func `ndeflib message framing sets MB on the first and ME on the last record`() throws {
        // test_message.py:12-17 (test_message_set_1)
        let vectors: [(String, Int)] = [
            ("D00000", 1),
            ("900000 500000", 2),
            ("900000 100000 500000", 3),
        ]
        for (encoded, count) in vectors {
            let records = Array(repeating: Self.record(.empty), count: count)
            #expect(NDEFMessage(records: records).data == Self.hex(encoded), "encode \(encoded)")
            #expect(try NDEFMessage(data: Self.hex(encoded)).records == records, "decode \(encoded)")
        }
    }

    @Test
    func `ndeflib empty chunk pair is reassembled into one Unknown record`() throws {
        // test_message.py:18 ('B50000 560000'). ndeflib returns the raw chunks
        // [Record('unknown'), Record('unchanged')]; NDEF 1.0 §2.3.3 reassembly gives one record.
        let records = try NDEFMessage(data: Self.hex("B50000 560000")).records
        #expect(records == [Self.record(.unknown)])
    }

    @Test
    func `ndeflib malformed messages are rejected`() {
        // test_message.py:60-65 (test_message_set_2, strict) and 83-94 (test_message_set_3),
        // the latter also prefixed with '900000' as at test_message.py:103.
        let strict = ["150000 160000 560000", "950000 960000 560000", "950000 160000 160000", "B50000 160000 760000"]
        let truncated = [
            "19", "1901", "190101", "19010101", "19010101aa", "19010101aabb",
            "19000000", "18010000", "18000001", "18000100",
        ]
        for encoded in strict + truncated + truncated.map({ "900000" + $0 }) {
            #expect(throws: (any Error).self, "\(encoded)") { try NDEFMessage(data: Self.hex(encoded)) }
        }
        // test_record.py:291-309 (TestDecode.wrong_decode_data) buffer underflows, with MB | ME.
        for encoded in ["C7", "C0", "C000", "C00000", "C0000000", "C000000000", "D9010101", "D901010154", "D90101015449"] {
            #expect(throws: (any Error).self, "\(encoded)") { try NDEFMessage(data: Self.hex(encoded)) }
        }
    }

    @Test
    func `ndeflib long-format empty record decodes`() throws {
        // test_record.py:287 ('00 00 00 00 00 00') with MB | ME; also CTS NdefTest.java:124-126.
        let records = try NDEFMessage(data: Self.hex("C0 00 00000000")).records
        #expect(records == [Self.record(.empty)])
        #expect(NDEFMessage(records: records).data == Self.hex("D00000"))
    }

    @Test
    func `TNF field constraints of NDEF 1.0 section 3.2.6 are enforced`() {
        // ndeflib test_record.py:297, 302, 304, 305 (MB | ME added) and CTS NdefTest.java:102:
        // TNF 00h must have TYPE_LENGTH, ID_LENGTH and PAYLOAD_LENGTH = 0; TNF 05h must
        // have TYPE_LENGTH = 0. Both ndeflib and Android reject these records.
        let vectors = [
            "D0010000", // TNF Empty with a type   (ndeflib "TYPE_LENGTH must be 0 for TNF value 0")
            "D800000100", // TNF Empty with an ID  (ndeflib "ID_LENGTH must be 0"; CTS {D8,0,0,1,0})
            "D0000100", // TNF Empty with payload  (ndeflib "PAYLOAD_LENGTH must be 0 for TNF value 0")
            "D5010000", // TNF Unknown with a type (ndeflib "TYPE_LENGTH must be 0 for TNF value 5")
        ]
        for encoded in vectors {
            #expect(throws: (any Error).self, "\(encoded)") { try NDEFMessage(data: Self.hex(encoded)) }
        }
    }

    @Test
    func `TNF field constraints of NDEF 1.0 section 3.2.6 are enforced when serialising`() throws {
        // The same records as above (ndeflib test_record.py:297, 302, 304, 305; CTS
        // NdefTest.java:102), plus TNF 06h outside a chunk and the reserved TNF 07h,
        // are refused by validatedData() before they can reach a tag.
        let invalid = [
            Self.record(.empty, type: Data([0x00])),
            Self.record(.empty, id: Data([0x00])),
            Self.record(.empty, payload: Data([0x00])),
            Self.record(.unknown, type: Data([0x00])),
            Self.record(.unchanged),
            Self.record(.reserved),
        ]
        for record in invalid {
            #expect(throws: NFCError.self, "\(record)") { try NDEFMessage(records: [record]).validatedData() }
        }
        // TNF 05h with an ID and a payload stays valid (CTS NdefTest.java:434-481).
        #expect(try NDEFMessage(records: [Self.record(.unknown, id: Data([9]), payload: Data([9]))]).validatedData()
            == Data([0xDD, 0, 1, 1, 9, 9]))
        // NDEF 1.0 §3.2.6: a reserved TNF 07h is read like Unknown (no type allowed) …
        #expect(try NDEFMessage(data: Self.hex("D70000")).records.first?.typeNameFormat == .reserved)
        #expect(throws: NFCError.self) { try NDEFMessage(data: Self.hex("D7010041")) }
        // … but is never written.
        #expect(throws: NFCError.self) {
            try NDEFMessage(records: [NDEFRecord(typeNameFormat: .reserved, type: Data(), payload: Data())]).validatedData()
        }
    }

    // MARK: - Android CTS NdefTest.java

    @Test
    func `CTS invalid NDEF messages are rejected`() {
        // NdefTest.java:89-116 (testInvalidParsing), minus the trailing-data cases below.
        let vectors: [[UInt8]] = [
            [],
            [0xD0],
            [0xD0, 0],
            [0x50, 0, 0],
            [0x90, 0, 0],
            [0xC0, 0, 0, 0],
            [0xC0, 0, 0, 0, 0],
            [0xD8, 1, 3, 1, 0, 0, 0, 0],
            [0x90, 0, 0, 0x10, 0, 0],
            [0xF5, 0, 0],
            [0xD6, 0, 0],
            [0xB6, 0, 1, 1, 0x56, 0, 1, 2],
            [0xC5, 0, 0xFF, 0xFF, 0xFF, 0xFF],
        ]
        for bytes in vectors {
            #expect(throws: (any Error).self, "\(Data(bytes).hexString)") { try NDEFMessage(data: Data(bytes)) }
        }
    }

    @Test
    func `CTS messages with bytes after the ME record are rejected`() {
        // NdefTest.java:94, 98, 100 ("too long"). Android rejects data after the record
        // carrying ME.
        let vectors: [[UInt8]] = [
            [0xD0, 0, 0, 0, 0],
            [0xC0, 0, 0, 0, 0, 0, 0],
            [0xD8, 1, 3, 1, 0, 0, 0, 0, 0, 0],
        ]
        for bytes in vectors {
            #expect(throws: (any Error).self, "\(Data(bytes).hexString)") { try NDEFMessage(data: Data(bytes)) }
        }
    }

    @Test
    func `CTS valid NDEF messages decode and canonical ones re-encode`() throws {
        // NdefTest.java:118-308 (testValidParsing). `canonical` marks byte strings the
        // serialiser reproduces exactly (short records where possible, IL only with an ID).
        let pattern255 = Self.ctsPattern(255)
        let pattern256 = Self.ctsPattern(256)
        let vectors: [(bytes: Data, records: [NDEFRecord], canonical: Bool)] = [
            (Data([0xD0, 0, 0]), [Self.record(.empty)], true),
            (Data([0xC0, 0, 0, 0, 0, 0]), [Self.record(.empty)], false),
            (Data([0xD8, 0, 0, 0]), [Self.record(.empty)], false),
            (Data([0xD9, 0, 0, 1, 0]), [Self.record(.wellKnown, id: Data([0]))], true),
            (Data([0xC9, 0, 0, 0, 0, 0, 1, 0]), [Self.record(.wellKnown, id: Data([0]))], false),
            (Data([0xD1, 0, 3, 1, 2, 3]), [Self.record(.wellKnown, payload: Data([1, 2, 3]))], true),
            (Data([0xD1, 1, 3, 9, 1, 2, 3]), [Self.record(.wellKnown, type: Data([9]), payload: Data([1, 2, 3]))], true),
            (
                Data([0xD9, 1, 3, 1, 8, 9, 1, 2, 3]),
                [Self.record(.wellKnown, type: Data([8]), id: Data([9]), payload: Data([1, 2, 3]))], true
            ),
            (
                Data([0xC9, 1, 0, 0, 0, 3, 1, 8, 9, 1, 2, 3]),
                [Self.record(.wellKnown, type: Data([8]), id: Data([9]), payload: Data([1, 2, 3]))], false
            ),
            (Data([0x90, 0, 0, 0x50, 0, 0]), Array(repeating: Self.record(.empty), count: 2), true),
            (Data([0x90, 0, 0, 0x10, 0, 0, 0x50, 0, 0]), Array(repeating: Self.record(.empty), count: 3), true),
            // Chunked records (NDEF 1.0 §2.3.3).
            (Data([0xB5, 0, 1, 1, 0x56, 0, 1, 2]), [Self.record(.unknown, payload: Data([1, 2]))], false),
            (Data([0xB5, 0, 0, 0x36, 0, 1, 1, 0x56, 0, 1, 2]), [Self.record(.unknown, payload: Data([1, 2]))], false),
            (
                Data([0xBA, 1, 0, 1, 8, 9, 0x36, 0, 1, 1, 0x56, 0, 1, 2]),
                [Self.record(.mimeMedia, type: Data([8]), id: Data([9]), payload: Data([1, 2]))], false
            ),
            (
                Data([
                    0xB4, 1, 1, 0x21, 1, 0x36, 0, 2, 2, 3, 0x16, 0, 1, 4,
                    0x10, 0, 0,
                    0x32, 1, 2, 0x21, 11, 12, 0x36, 0, 1, 13, 0x56, 0, 1, 14,
                ]),
                [
                    Self.record(.external, type: Data([0x21]), payload: Data([1, 2, 3, 4])),
                    Self.record(.empty),
                    Self.record(.mimeMedia, type: Data([0x21]), payload: Data([11, 12, 13, 14])),
                ],
                false
            ),
            // SR boundary: 255-byte payload in long format, 256-byte payload, 255-byte type and ID.
            (Data([0xC5, 0, 0, 0, 0, 0xFF]) + pattern255, [Self.record(.unknown, payload: pattern255)], false),
            (Data([0xC5, 0, 0, 0, 1, 0]) + pattern256, [Self.record(.unknown, payload: pattern256)], true),
            (Data([0xD2, 0xFF, 0]) + pattern255, [Self.record(.mimeMedia, type: pattern255)], true),
            (Data([0xDA, 0, 0, 0xFF]) + pattern255, [Self.record(.mimeMedia, id: pattern255)], true),
        ]
        for vector in vectors {
            let label = vector.bytes.prefix(16).hexString
            #expect(try NDEFMessage(data: vector.bytes).records == vector.records, "decode \(label)")
            if vector.canonical {
                #expect(NDEFMessage(records: vector.records).data == vector.bytes, "encode \(label)")
            }
        }
    }

    @Test
    func `CTS smart poster with a URL and no title`() throws {
        // NdefTest.java:296-307: Smart Poster wrapping createUri("http://www.google.com").
        let bytes = Self.hex("d1 02 0f 53 70 d1 01 0b 55 01 67 6f 6f 67 6c 65 2e 63 6f 6d")
        let message = try NDEFMessage(data: bytes)
        #expect(message.records.count == 1)
        #expect(message.records[0].parsedPayload == .smartPoster(uri: "http://www.google.com", title: nil))
        #expect(NDEFMessage(records: [.smartPoster(uri: "http://www.google.com")]).data == bytes)
    }

    @Test
    func `CTS createUri encodings`() throws {
        // NdefTest.java:310-328 (testCreateUri)
        let vectors: [(String, Data)] = [
            ("http://www.nfc.com", Data([0xD1, 1, 8, 0x55, 0x01]) + Self.ascii("nfc.com")),
            ("tel:+35891234567", Data([0xD1, 1, 13, 0x55, 0x05]) + Self.ascii("+35891234567")),
            ("foo", Data([0xD1, 1, 4, 0x55, 0x00]) + Self.ascii("foo")),
            ("\u{00A2}", Data([0xD1, 1, 3, 0x55, 0x00, 0xC2, 0xA2])),
        ]
        for (uri, bytes) in vectors {
            #expect(NDEFMessage.uri(uri).data == bytes, "encode \(uri)")
            #expect(try NDEFMessage(data: bytes).records.first?.parsedPayload == .uri(uri), "decode \(uri)")
        }
    }

    @Test
    func `CTS Android Application Record is an external type`() throws {
        // NdefTest.java:400-431 (testCreateApplicationRecord)
        let bytes = Data([0xD4, 0x0F, 0x0B]) + Self.ascii("android.com:pkg") + Self.ascii("com.foo.bar")
        let records = try NDEFMessage(data: bytes).records
        #expect(records == [Self.record(.external, type: Self.ascii("android.com:pkg"), payload: Self.ascii("com.foo.bar"))])
        #expect(records[0].parsedPayload == .external(type: "android.com:pkg", data: Self.ascii("com.foo.bar")))
        #expect(NDEFMessage(records: [.external(type: "android.com:pkg", data: Self.ascii("com.foo.bar"))]).data == bytes)
    }

    @Test
    func `CTS toByteArray encodings`() {
        // NdefTest.java:434-481 (testToByteArray). The TNF_EMPTY vectors (D8 0 0 0 ...) are
        // left out: Android sets IL with a zero-length ID for them, which is not canonical.
        #expect(NDEFMessage(records: [Self.record(.unknown, id: Data([9]))]).data == Data([0xDD, 0, 0, 1, 9]))
        #expect(NDEFMessage(records: [Self.record(.external, type: Data([9]))]).data == Data([0xD4, 1, 0, 9]))
        #expect(NDEFMessage(records: [Self.record(.unknown, payload: Data([9]))]).data == Data([0xD5, 0, 1, 9]))
        #expect(
            NDEFMessage(records: [Self.record(.unknown, payload: Self.ctsPattern(256))]).data
                == Data([0xC5, 0, 0, 0, 1, 0]) + Self.ctsPattern(256)
        )
    }

    @Test
    func `Absolute-URI record takes its URI from the TYPE field`() {
        // NDEF 1.0 §3.2.6: for TNF 03h the TYPE field holds the absolute URI.
        // CTS NdefTest.java:485-487 (testToUri: TNF_ABSOLUTE_URI type "http://www.android.com",
        // no payload -> http://www.android.com); ndeflib test_record.py:220 encodes
        // 'http://a.b/c' into the TYPE field ('130c00 687474703a2f2f612e622f63').
        let android = Self.record(.absoluteURI, type: Self.ascii("http://www.android.com"))
        let ndeflib = Self.record(.absoluteURI, type: Self.ascii("http://a.b/c"))
        #expect(android.parsedPayload == .uri("http://www.android.com"))
        #expect(ndeflib.parsedPayload == .uri("http://a.b/c"))
    }

    @Test
    func `Smart Poster falls back to an absolute-URI child record`() {
        // CTS NdefTest.java testToUri: Android's toUri() takes a Smart Poster's URI from its
        // first URI or absolute-URI child. A URI ("U") record still wins when both exist.
        let absolute = Self.record(.absoluteURI, type: Self.ascii("http://a.b/c"))
        let onlyAbsolute = NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Self.ascii("Sp"),
            payload: NDEFMessage(records: [absolute, .text("Title")]).data
        )
        #expect(onlyAbsolute.parsedPayload == .smartPoster(uri: "http://a.b/c", title: "Title"))
        let both = NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Self.ascii("Sp"),
            payload: NDEFMessage(records: [absolute, .uri("https://example.com")]).data
        )
        #expect(both.parsedPayload == .smartPoster(uri: "https://example.com", title: nil))
    }

    // MARK: - RTD Text: ndeflib test_text.py

    @Test
    func `ndeflib Text payloads decode`() {
        // test_text.py:40-47 (test_decode_valid_data)
        let vectors: [(String, String, String)] = [
            ("02656e", "", "en"),
            ("026465", "", "de"),
            ("02656e48656c6c6f", "Hello", "en"),
            ("82656efffe480065006c006c006f00", "Hello", "en"), // UTF-16 with LE BOM
            ("02656cce94", "\u{0394}", "el"),
            ("82656cfffe9403", "\u{0394}", "el"), // UTF-16 with LE BOM
        ]
        for (payload, text, language) in vectors {
            #expect(
                NDEFRecord.parseTextPayload(Self.hex(payload)) == .text(languageCode: language, text: text),
                "\(payload)"
            )
        }
        // test_text.py:52: "01" — language code length exceeds payload.
        #expect(NDEFRecord.parseTextPayload(Self.hex("01")) == .unknown(data: Self.hex("01")))
    }

    @Test
    func `ndeflib Text messages encode and decode`() throws {
        // test_text.py:71-77 (text_messages)
        let single = Self.hex("D101075402656e54455854")
        #expect(NDEFMessage.text("TEXT", languageCode: "en").data == single)
        #expect(try NDEFMessage(data: single).records.map(\.parsedPayload) == [.text(languageCode: "en", text: "TEXT")])

        let pair = Self.hex("9101075402656e54585431 5101075402656e54585432")
        #expect(NDEFMessage(records: [.text("TXT1"), .text("TXT2")]).data == pair)
        #expect(
            try NDEFMessage(data: pair).records.map(\.parsedPayload)
                == [.text(languageCode: "en", text: "TXT1"), .text(languageCode: "en", text: "TXT2")]
        )
    }

    // MARK: - RTD URI: ndeflib test_uri.py (every identifier code 00h-23h)

    @Test
    func `ndeflib URI identifier codes decode and abbreviate`() {
        // test_uri.py:73-110 (test_decode_valid_data)
        let vectors: [(String, String)] = [
            ("006e66637079", "nfcpy"),
            ("016e66637079", "http://www.nfcpy"),
            ("026e66637079", "https://www.nfcpy"),
            ("036e66637079", "http://nfcpy"),
            ("046e66637079", "https://nfcpy"),
            ("053031323334", "tel:01234"),
            ("066e66637079", "mailto:nfcpy"),
            ("076e66637079", "ftp://anonymous:anonymous@nfcpy"),
            ("086e66637079", "ftp://ftp.nfcpy"),
            ("096e66637079", "ftps://nfcpy"),
            ("0a6e66637079", "sftp://nfcpy"),
            ("0b6e66637079", "smb://nfcpy"),
            ("0c6e66637079", "nfs://nfcpy"),
            ("0d6e66637079", "ftp://nfcpy"),
            ("0e6e66637079", "dav://nfcpy"),
            ("0f6e66637079", "news:nfcpy"),
            ("106e66637079", "telnet://nfcpy"),
            ("116e66637079", "imap:nfcpy"),
            ("126e66637079", "rtsp://nfcpy"),
            ("136e66637079", "urn:nfcpy"),
            ("146e66637079", "pop:nfcpy"),
            ("156e66637079", "sip:nfcpy"),
            ("166e66637079", "sips:nfcpy"),
            ("176e66637079", "tftp:nfcpy"),
            ("186e66637079", "btspp://nfcpy"),
            ("196e66637079", "btl2cap://nfcpy"),
            ("1a6e66637079", "btgoep://nfcpy"),
            ("1b6e66637079", "tcpobex://nfcpy"),
            ("1c6e66637079", "irdaobex://nfcpy"),
            ("1d6e66637079", "file://nfcpy"),
            ("1e3132333435", "urn:epc:id:12345"),
            ("1f3132333435", "urn:epc:tag:12345"),
            ("203132333435", "urn:epc:pat:12345"),
            ("213132333435", "urn:epc:raw:12345"),
            ("223132333435", "urn:epc:12345"),
            ("233132333435", "urn:nfc:12345"),
        ]
        #expect(vectors.count == NDEFRecord.uriPrefixMap.count)
        for (payload, uri) in vectors {
            #expect(NDEFRecord.parseURIPayload(Self.hex(payload)) == .uri(uri), "decode \(payload)")
            // Longest-prefix abbreviation yields the same identifier code.
            #expect(NDEFRecord.uri(uri).payload == Self.hex(payload), "encode \(uri)")
        }
        // test_uri.py:117-120 (test_decode_relax_data): RFU codes 24h and FFh decode without a prefix.
        #expect(NDEFRecord.parseURIPayload(Self.hex("246e66637079")) == .uri("nfcpy"))
        #expect(NDEFRecord.parseURIPayload(Self.hex("ff6e66637079")) == .uri("nfcpy"))
    }

    @Test
    func `ndeflib URI messages encode and decode`() throws {
        // test_uri.py:142-150 (uri_messages)
        let vectors: [(String, [String])] = [
            ("D1010a55036e666370792e6f7267", ["http://nfcpy.org"]),
            ("91010a55036e666370792e6f7267 51010a55046e666370792e6f7267", ["http://nfcpy.org", "https://nfcpy.org"]),
            ("D101115500736d74703a2f2f6e666370792e6f7267", ["smtp://nfcpy.org"]),
        ]
        for (encoded, uris) in vectors {
            #expect(NDEFMessage(records: uris.map { .uri($0) }).data == Self.hex(encoded), "encode \(encoded)")
            #expect(
                try NDEFMessage(data: Self.hex(encoded)).records.map(\.parsedPayload) == uris.map { .uri($0) },
                "decode \(encoded)"
            )
        }
    }

    // MARK: - Smart Poster: ndeflib test_smartposter.py

    @Test
    func `ndeflib Smart Poster payloads decode`() {
        // test_smartposter.py:164-180 (test_decode_valid_data). Action ("act"), size ("s"),
        // type ("t") and icon records are ignored by the decoder; URI and title are checked.
        let vectors: [(String, String, String?)] = [
            ("d101015500", "", nil),
            ("d1010a55036e666370792e6f7267", "http://nfcpy.org", nil),
            ("9101015500 5101085402656e6e66637079", "", "nfcpy"),
            ("9101015500 510108540264656e66637079", "", "nfcpy"),
            ("9101015500 51030161637400", "", nil),
            ("9101015500 5101047300000001", "", nil),
            ("9101015500 51010374612f62", "", nil),
            ("9101015500 520908 696d6167652f706e67 89504e470d0a1a0a", "", nil),
            ("9101015500 520901766964656f2f6d703400", "", nil),
            ("9101015500 520901696d6167652f706e6701", "", nil),
            ("9101015500 520901696d6167652f67696601", "", nil),
        ]
        for (payload, uri, title) in vectors {
            #expect(NDEFRecord.parseSmartPoster(Self.hex(payload)) == .smartPoster(uri: uri, title: title), "\(payload)")
        }
    }

    @Test
    func `ndeflib Smart Poster messages encode and decode`() throws {
        // test_smartposter.py:233-242 (smartposter_messages) and 245-247.
        let built: [(String, NDEFRecord, String, String?)] = [
            ("d102055370 d101015500", .smartPoster(uri: ""), "", nil),
            ("d1020e5370 d1010a55036e666370792e6f7267", .smartPoster(uri: "http://nfcpy.org"), "http://nfcpy.org", nil),
            (
                "d1021a5370 91010a55036e666370792e6f7267 5101085402656e6e66637079",
                .smartPoster(uri: "http://nfcpy.org", title: "nfcpy"), "http://nfcpy.org", "nfcpy"
            ),
        ]
        for (encoded, record, uri, title) in built {
            let bytes = Self.hex(encoded)
            #expect(NDEFMessage(records: [record]).data == bytes, "encode \(encoded)")
            #expect(try NDEFMessage(data: bytes).records.map(\.parsedPayload) == [.smartPoster(uri: uri, title: title)])
        }

        // Title plus Action record: decode, and the raw records re-encode byte for byte.
        let withAction = Self.hex("d102215370 91010a55036e666370792e6f7267 1101085402656e6e66637079 51030161637400")
        let records = try NDEFMessage(data: withAction).records
        #expect(records.map(\.parsedPayload) == [.smartPoster(uri: "http://nfcpy.org", title: "nfcpy")])
        #expect(NDEFMessage(records: records).data == withAction)
        #expect(try NDEFRecord.parseMessage(records[0].payload).count == 3)

        // Nested message ending in an empty record.
        let trailingEmpty = Self.hex("d102085370 9101015500 500000")
        #expect(try NDEFMessage(data: trailingEmpty).records.map(\.parsedPayload) == [.smartPoster(uri: "", title: nil)])
    }

    // MARK: - Type 2 Tag memory images: nfcpy test_tag_tt2.py, libnfc

    @Test
    func `nfcpy Type 2 NDEF detection vectors`() {
        // test_tag_tt2.py:541-551 (test_read_unsupported_cc): CC E0100100 / E1200100 -> no NDEF.
        for cc in ["E0100100", "E1200100"] {
            #expect(NDEFTagMapping.extractType2Message(from: Self.type2Pages(cc: cc, data: "0303d000 fe000000")) == nil)
        }
        // test_tag_tt2.py:553-564 (test_read_until_memory_end): only NULL TLVs in the 8-byte area.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100100", data: "00000000 00000000 ffffffff ffffffff")
        ) == nil)
        // test_tag_tt2.py:566-577 (test_read_until_terminator)
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100100", data: "feffffff ffffffff ffffffff ffffffff")
        ) == nil)
        // test_tag_tt2.py:579-591 (test_read_over_unknown_tlv): skip TLV F0h with length 0.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100100", data: "f0000303 d0000000 ffffffff ffffffff")
        ) == Self.hex("d00000"))
        // test_tag_tt2.py:593-610 (test_read_excessive_length_tlv): 3-byte length D000h runs past the area.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100100", data: "03ffd000 00000000 ffffffff ffffffff")
        ) == nil)
        // test_tag_tt2.py:612-624 (test_read_invalid_lock_rsvd_tlv): Lock and Memory Control TLVs skipped.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100200", data: "0104ffff ffff0202 ffff0303 d00000fe")
        ) == Self.hex("d00000"))
    }

    @Test
    func `nfcpy Type 2 empty NDEF messages after Lock Control TLVs`() {
        // test_tag_tt2.py:434-452 (test_protect_static_default_lockbits): NULL, NDEF TLV length 0, Terminator.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(cc: "E1100200", data: "000300fe 00000000 00000000 00000000")
        ) == Data())
        // test_tag_tt2.py:485-514 (test_protect_dynamic_locktlv_lockbits): Lock Control TLV 01 03 a01023.
        #expect(NDEFTagMapping.extractType2Message(
            from: Self.type2Pages(
                cc: "E1100800",
                data: "00000103 a0102300 0300fe00 00000000" + String(repeating: "00000000", count: 12)
            )
        ) == Data())
    }

    @Test
    func `nfcpy Type 2 NDEF TLV split by Memory and Lock Control reserved bytes`() {
        // test_tag_tt2.py:626-644 (test_read_with_all_tlv_types): Memory Control TLV 02 03 700402
        // reserves page 7 and Lock Control TLV 01 03 c01022 puts 2 lock bytes at page 0Ch;
        // NFC Forum T2T 1.0 §2.3.4 / §2.3.5 require skipping both while reading the NDEF TLV.
        let allTLVs = Self.type2Pages(
            cc: "E110060f",
            data: "000103c0 10220203 70040200 ffffffff 0313d500 10000102 03040506 0708090a"
                + " ffff0b0c 0d0e0f00 fe000000 00000000"
        )
        // test_tag_tt2.py:393-410 (test_format_with_wipe): Memory Control TLV 02 03 630202
        // reserves 2 bytes at page 6 byte 3, inside the NDEF TLV value.
        let wiped = Self.type2Pages(cc: "E1100200", data: "02036302 020305d5 000231ff ff320000")
        #expect(NDEFTagMapping.extractType2Message(from: allTLVs) == Self.hex("d50010000102030405060708090a0b0c0d0e0f"))
        #expect(NDEFTagMapping.extractType2Message(from: wiped) == Self.hex("d500023132"))
    }

    @Test
    func `Type 2 control TLV areas follow T2T section 2.3.4 and 2.3.5`() {
        // test_tag_tt2.py:626-644: Lock Control 01 03 c01022 -> page 0Ch × 2^2, 16 bits = 2 bytes.
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x01, value: Self.hex("c01022")) == 48 ..< 50)
        // Memory Control 02 03 700402 -> page 7 × 2^2, 4 bytes.
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x02, value: Self.hex("700402")) == 28 ..< 32)
        // test_tag_tt2.py:485-514: Lock Control 01 03 a01023 -> page 0Ah × 2^3 = 80, 16 bits.
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x01, value: Self.hex("a01023")) == 80 ..< 82)
        // Size 00h means 256 (256 lock bits = 32 bytes, 256 reserved bytes).
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x01, value: Self.hex("100002")) == 4 ..< 36)
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x02, value: Self.hex("100002")) == 4 ..< 260)
        // A value that is not 3 bytes long declares nothing (test_tag_tt2.py:612-624).
        #expect(NDEFTagMapping.type2ControlArea(tag: 0x01, value: Self.hex("ffffffff")) == nil)
    }

    /// Replay the page writes a mock transport received onto `pages`.
    private static func applyingWrites(_ commands: [Data], to pages: [MemoryDump.Page]) -> [MemoryDump.Page] {
        var byNumber = Dictionary(uniqueKeysWithValues: pages.map { ($0.number, $0.data) })
        for command in commands where command.first == 0xA2 {
            byNumber[command[command.startIndex + 1]] = Data(command.dropFirst(2))
        }
        return byNumber.keys.sorted().map { MemoryDump.Page(number: $0, data: byNumber[$0]!) }
    }

    @Test
    func `Type 2 write keeps control TLVs and stops before reserved bytes`() async throws {
        // Lock Control 01 03 c01022 puts 2 lock bytes at 48 (page 0Ch) and Memory Control
        // 02 03 a00402 reserves page 0Ah, both inside the 48-byte data area: the NDEF TLV
        // goes after the control TLVs and nothing from page 0Ah on is written.
        let before = Self.type2Pages(
            cc: "E1100600",
            data: "000103c0 10220203 a0040200" + " 00000000 00000000 00000000 a5a5a5a5"
                + " 00000000 5a5a0000 00000000 00000000 00000000"
        )
        let transport = MockTransport()
        // Only NULL TLVs follow the control TLVs in pages 4-6, so pages 7-10 are read too.
        transport.responses = [Self.hex("E1100600 000103c0 10220203 a0040200"), Self.hex("00000000 00000000 00000000 a5a5a5a5")]
            + Array(repeating: Data([0x0A]), count: 7)
        let message = NDEFMessage.text("Hi")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .mifareUltralight, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            transport: transport
        )

        let written = Set(transport.sentCommands.filter { $0.first == 0xA2 }.map { $0[$0.startIndex + 1] })
        #expect(written == Set(4 ... 9))
        let after = Self.applyingWrites(transport.sentCommands, to: before)
        #expect(after.first { $0.number == 4 }?.data == Self.hex("000103c0"))
        #expect(after.first { $0.number == 6 }?.data.prefix(3) == Self.hex("a00402"))
        #expect(after.first { $0.number == 10 }?.data == Self.hex("a5a5a5a5"))
        #expect(NDEFTagMapping.extractType2Message(from: after) == message.data)
    }

    @Test
    func `Type 2 write reads further pages for a control TLV past page 6`() async throws {
        // An Ultralight C style Lock Control TLV (01 03 a01044 -> bytes 160-161, past the
        // 144-byte data area) after ten NULL TLVs runs into page 7, so pages 7-10 are read too.
        let transport = MockTransport()
        transport.responses = [
            Self.hex("E1101200 00000000 00000000 00000103"),
            Self.hex("a0104403 00fe0000 00000000 00000000"),
        ] + Array(repeating: Data([0x0A]), count: 37)
        let message = NDEFMessage.text("Hi")
        try await CoreExtendedNFC.writeNDEF(
            message,
            info: CardInfo(type: .mifareUltralightC, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
            transport: transport
        )
        #expect(transport.sentCommands.prefix(2) == [Data([0x30, 0x03]), Data([0x30, 0x07])])
        let blank = Self.type2Pages(cc: "E1101200", data: String(repeating: "00000000", count: 36))
        let after = Self.applyingWrites(transport.sentCommands, to: blank)
        #expect(after.first { $0.number == 6 }?.data == Self.hex("00000103"))
        #expect(after.first { $0.number == 7 }?.data.prefix(3) == Self.hex("a01044"))
        #expect(NDEFTagMapping.extractType2Message(from: after) == message.data)
    }

    @Test
    func `Type 2 write is refused when reserved bytes share a page with the control TLVs`() {
        // Memory Control 02 03 510402 reserves bytes 21-24, inside page 5 next to the TLV;
        // the NDEF TLV 03 00 after the reserved bytes confirms it is a control TLV.
        #expect(throws: NFCError.self) {
            try NDEFTagMapping.type2WriteLayout(
                leadingBytes: Self.hex("02035104 02000000 000300fe"),
                dataAreaOffset: 16,
                capacity: 48
            )
        }
        // Without control TLVs the whole data area is used, exactly as before.
        let plain = try? NDEFTagMapping.type2WriteLayout(
            leadingBytes: Self.hex("0300fe00 00000000 00000000"),
            dataAreaOffset: 16,
            capacity: 48
        )
        #expect(plain?.preservedPrefix == Data())
        #expect(plain?.capacity == 48)
        #expect(plain?.endsDataArea == true)
    }

    @Test
    func `nfcpy Type 2 write without terminator and length-last order`() throws {
        // test_tag_tt2.py:677-696 (test_write_without_terminator)
        let before = Self.type2Pages(cc: "E1100100", data: "0305d500 023132fe 00000000 00000000")
        #expect(NDEFTagMapping.extractType2Message(from: before) == Self.hex("d500023132"))

        // 8-byte data area; the 8-byte NDEF TLV fills it, so no Terminator TLV.
        let area = try NDEFTagMapping.buildType2Area(message: Self.hex("d50003313233"), capacity: 8)
        #expect(area == Self.hex("0306d500 03313233"))

        // nfcpy writes: a2 04 0300d500, a2 05 03313233, a2 04 0306d500.
        let order = NDEFTagMapping.lengthLastWriteOrder(
            [(4, Data(area[0 ..< 4])), (5, Data(area[4 ..< 8]))],
            blockSize: 4,
            tlvOffset: 16
        )
        #expect(order.map(\.block) == [4, 5, 4])
        #expect(order.map(\.data) == [Self.hex("0300d500"), Self.hex("03313233"), Self.hex("0306d500")])
    }

    @Test
    func `nfcpy Type 2 three-byte TLV length`() throws {
        // test_tag_tt2.py:698-740 (test_write_long_length_field): CC E1102100 (264-byte area),
        // message 'd500fc' + 252 zero bytes; final pages 04 = 03ff00ff, 05 = d500fc00, 44h = 000000fe.
        let message = Self.hex("d500fc") + Data(repeating: 0x00, count: 252)
        let area = try NDEFTagMapping.buildType2Area(message: message, capacity: 0x21 * 8)
        #expect(area.count == 264)
        #expect(area[0 ..< 4] == Self.hex("03ff00ff"))
        #expect(area[4 ..< 8] == Self.hex("d500fc00"))
        #expect(area[256 ..< 260] == Self.hex("000000fe")) // page 44h
        #expect(area[260...].allSatisfy { $0 == 0x00 })

        let writes = stride(from: 0, to: area.count, by: 4).map { (block: 4 + $0 / 4, data: Data(area[$0 ..< $0 + 4])) }
        let order = NDEFTagMapping.lengthLastWriteOrder(writes, blockSize: 4, tlvOffset: 16)
        #expect(order.last?.block == 4)
        #expect(order.last?.data == Self.hex("03ff00ff")) // nfcpy's last command: a2 04 03ff00ff

        let pages = [MemoryDump.Page(number: 3, data: Self.hex("E1102100"))]
            + writes.map { MemoryDump.Page(number: UInt8($0.block), data: $0.data) }
        #expect(NDEFTagMapping.extractType2Message(from: pages) == message)
    }

    @Test
    func `libnfc Type 2 emulator memory image`() throws {
        // libnfc examples/nfc-emulate-forum-tag2.c:98-118 (__nfcforum_tag2_memory_area):
        // read-only CC E1 10 06 0F, NDEF TLV 03 21 with a Smart Poster, no Terminator TLV.
        let image = Self.hex(
            "00000000 00000000 0000FFFF E110060F"
                + " 0321d102 1c537091 01095402 656e4c69"
                + " 626e6663 51010b55 036c6962 6e66632e"
                + " 6f726700 00000000 00000000 00000000"
        )
        let pages = stride(from: 0, to: image.count, by: 4).map {
            MemoryDump.Page(number: UInt8($0 / 4), data: Data(image[$0 ..< $0 + 4]))
        }
        let message = try #require(NDEFTagMapping.extractType2Message(from: pages))
        #expect(message.count == 33)
        let records = try NDEFMessage(data: message).records
        #expect(records.map(\.parsedPayload) == [.smartPoster(uri: "http://libnfc.org", title: "Libnfc")])
        #expect(NDEFMessage(records: records).data == message)

        // CC3 = 0Fh: no write access.
        #expect(throws: NFCError.tagLocked) {
            try NDEFTagMapping.type2WritableCapacity(
                cc: Self.hex("E110060F"),
                memoryMap: UltralightMemoryMap.forType(.ntag213)
            )
        }
    }

    // MARK: - Type 3 Tag attribute block: nfcpy test_tag_tt3.py

    @Test
    func `nfcpy Type 3 attribute information blocks`() throws {
        // test_tag_tt3.py:633-722 (test_ndef_read) and 724-770 (test_ndef_write).
        let readWrite = try FeliCaAttributeInfo(data: Self.hex("10 02 02 00 03 00 00 00 00 00 01 00 00 27 00 3f"))
        #expect(readWrite.version == 0x10)
        #expect(readWrite.nbr == 2)
        #expect(readWrite.nbw == 2)
        #expect(readWrite.nmaxb == 3) // capacity 48
        #expect(readWrite.writeFlag == 0x00)
        #expect(readWrite.rwFlag == 0x01)
        #expect(readWrite.ndefLength == 39)

        let readOnly = try FeliCaAttributeInfo(data: Self.hex("10 02 02 00 03 00 00 00 00 00 00 00 00 00 00 17"))
        #expect(readOnly.rwFlag == 0x00)
        #expect(readOnly.ndefLength == 0)

        // Checksum error (test_tag_tt3.py:700-708).
        #expect(throws: NFCError.checksumMismatch) {
            try FeliCaAttributeInfo(data: Self.hex("20 02 02 00 03 00 00 00 00 00 01 00 00 27 00 3f"))
        }

        // Write procedure attribute blocks (test_tag_tt3.py:755-767).
        let empty = try FeliCaAttributeInfo(data: Self.hex("10 02 02 00 03 00 00 00 00 00 01 00 00 00 00 18"))
        #expect(empty.encoded(writeFlag: 0x0F) == Self.hex("1002020003000000000f010000000027"))
        #expect(empty.encoded(writeFlag: 0x00, ndefLength: 0x27) == Self.hex("1002020003000000000001000027003f"))

        // Format vectors (test_tag_tt3.py:532-534, 562-564, 588-590, 614-616): checksum and re-encoding.
        for block in [
            "1f 03 02 0007 00000000 00 01 000000 002c",
            "1f 0F 0D 0007 00000000 00 01 000000 0043",
            "1f 0F 0C FFFF 00000000 00 01 000000 0239",
            "1f 0F 0D 0000 00000000 00 01 000000 003C",
        ] {
            let info = try FeliCaAttributeInfo(data: Self.hex(block))
            #expect(info.encoded() == Self.hex(block), "\(block)")
        }
    }

    private static let nfcpyType3Blocks = [
        "10 02 02 00 03 00 00 00 00 00 01 00 00 27 00 3f",
        "d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f",
        "72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46",
        "43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00",
    ]

    @Test
    func `nfcpy Type 3 NDEF read`() async throws {
        // test_tag_tt3.py:633-670: Nbr = 2, so blocks 1-2 are read together, then block 3.
        let transport = NDEFVectorFeliCaTransport(blocks: Self.nfcpyType3Blocks.map { Self.hex($0) })
        let message = try await FeliCaType3Reader(transport: transport).readNDEF()
        #expect(message == Self.hex(Self.nfcpyType3Blocks[1...].joined()).prefix(39))
        #expect(transport.reads == [[Self.hex("8000")], [Self.hex("8001"), Self.hex("8002")], [Self.hex("8003")]])
        #expect(
            try NDEFMessage(data: message).records.map(\.parsedPayload)
                == [.smartPoster(uri: "http://nfc-forum.org", title: "NFC Forum")]
        )
    }

    @Test
    func `nfcpy Type 3 NDEF write`() async throws {
        // test_tag_tt3.py:724-770 (test_ndef_write)
        let transport = NDEFVectorFeliCaTransport(blocks: [
            Self.hex("10 02 02 00 03 00 00 00 00 00 01 00 00 00 00 18"),
            Data(repeating: 0, count: 16), Data(repeating: 0, count: 16), Data(repeating: 0, count: 16),
        ])
        let message = Self.hex(
            "d1022253 7091010e 55036e66 632d666f 72756d2e 6f726751 010c5402 656e4e46 4320466f 72756d"
        )
        try await FeliCaType3Reader(transport: transport).writeNDEF(message)

        let writes = transport.writes
        #expect(writes.count == 4)
        guard writes.count == 4 else { return }
        // 1. Attribute block with WriteFlag 0Fh. nfcpy keeps Ln = 0 here
        //    ('1002020003000000000f010000000027'); the library already stores the new Ln,
        //    which the spec allows because WriteFlag 0Fh marks the NDEF invalid anyway.
        #expect(writes[0].blockList == [Self.hex("8000")])
        #expect(writes[0].data.first?.prefix(11) == Self.hex("1002020003000000000f01"))
        // 2. Blocks 1 and 2 in one UPDATE (Nbw = 2).
        #expect(writes[1].blockList == [Self.hex("8001"), Self.hex("8002")])
        #expect(writes[1].data == [Self.hex("d10222537091010e55036e66632d666f"), Self.hex("72756d2e6f726751010c5402656e4e46")])
        // 3. Block 3 zero-padded.
        #expect(writes[2].blockList == [Self.hex("8003")])
        #expect(writes[2].data == [Self.hex("4320466f72756d000000000000000000")])
        // 4. Attribute block with WriteFlag 00h and Ln = 27h.
        #expect(writes[3].blockList == [Self.hex("8000")])
        #expect(writes[3].data == [Self.hex("1002020003000000000001000027003f")])
    }

    // MARK: - Type 4 Tag CC file: nfcpy test_tag_tt4.py, libnfc, NTAG 424 DNA

    @Test
    func `Type 4 CC files from nfcpy, libnfc and NTAG 424 DNA`() throws {
        // nfcpy test_tag_tt4.py:304-309 (test_discover_ndef_access_rights): capacity 62 = 0040h - 2.
        let access: [(String, UInt8, UInt8)] = [
            ("000f 20 003b 0034 04 06 e104 0040 00 00", 0x00, 0x00),
            ("000f 20 003b 0034 04 06 e104 0040 80 00", 0x80, 0x00),
            ("000f 20 003b 0034 04 06 e104 0040 00 80", 0x00, 0x80),
            ("000f 20 003b 0034 04 06 e104 0040 81 81", 0x81, 0x81),
        ]
        for (file, read, write) in access {
            let cc = try Type4CC(data: Self.hex(file))
            #expect(cc.ccLen == 15 && cc.mappingVersion == 0x20 && cc.mle == 0x3B && cc.mlc == 0x34)
            #expect(cc.ndefFileID == Self.hex("e104"))
            #expect(Int(cc.maxNDEFFileSize) - cc.ndefLengthFieldSize == 62)
            #expect(cc.readAccess == read && cc.writeAccess == write)
            #expect(!cc.usesExtendedNDEFFile)
            #expect(cc.encoded == Self.hex(file))
        }

        // libnfc utils/nfc-emulate-forum-tag4.c:97-111 (nfcforum_capability_container), and
        // the mapping 1.0 variant set at :374 (CC[2] = 10h).
        let libnfc = Self.hex("000F 20 0054 00FF 04 06 E104 FFFE 00 00")
        let libnfcCC = try Type4CC(data: libnfc)
        #expect(libnfcCC.mle == 0x54 && libnfcCC.mlc == 0xFF && libnfcCC.ndefMaxSize == 0xFFFE)
        #expect(libnfcCC.encoded == libnfc)
        var libnfcV1 = libnfc
        libnfcV1[2] = 0x10
        #expect(try Type4CC(data: libnfcV1).mappingVersion == 0x10)

        // NTAG 424 DNA CC file (AndroidCrypto/Ntag424SdmFeature README.md:82, :85).
        let ntag = try Type4CC(data: Self.hex("000F20003A00340406E10401000000"))
        #expect(ntag.mle == 0x3A && ntag.mlc == 0x34 && ntag.ndefMaxSize == 0x0100 && ntag.writeAccess == 0x00)
        #expect(try Type4CC(data: Self.hex("000F20003A00340406E104010000FF")).writeAccess == 0xFF)
    }

    @Test
    func `nfcpy Type 4 CC rejection and version vectors`() {
        // test_tag_tt4.py:336-343 (invalid control TLV 05 05) and 366-374 (CC only 14 bytes long).
        #expect(throws: (any Error).self) { try Type4CC(data: Self.hex("000f 20 003b 0034 05 05 e104 0040 00 00")) }
        #expect(throws: (any Error).self) { try Type4CC(data: Self.hex("000e 20 003b 0034 04 06 e104 0040 00")) }

        // test_tag_tt4.py:347-352 (test_discover_ndef_version): 1.0, 2.0, 3.0 accepted, 4.0 rejected.
        for version in ["10", "20", "30"] {
            #expect(throws: Never.self) { try Type4CC(data: Self.hex("000f \(version) 003b 0034 04 06 e104 0040 00 00")) }
        }
        #expect(throws: (any Error).self) { try Type4CC(data: Self.hex("000f 40 003b 0034 04 06 e104 0040 00 00")) }
    }

    @Test
    func `nfcpy Type 4 NDEF read APDU sequence`() async throws {
        // test_tag_tt4.py:310-333 (test_discover_ndef_access_rights): NLEN 000Eh, then the URI record.
        let ok = ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
        let mock = MockTransport()
        mock.apduResponses = [
            ok,
            ok,
            ResponseAPDU(data: Self.hex("000f 20 003b 0034 04 06 e104 0040 00 00"), sw1: 0x90, sw2: 0x00),
            ok,
            ResponseAPDU(data: Self.hex("000e"), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Self.hex("d1010a55036e666370792e6f7267"), sw1: 0x90, sw2: 0x00),
        ]
        let message = try await Type4Reader(transport: mock).readNDEF()
        #expect(try NDEFMessage(data: message).records.map(\.parsedPayload) == [.uri("http://nfcpy.org")])

        let sent = mock.sentAPDUs.map(\.bytes)
        #expect(sent.count == 6)
        guard sent.count == 6 else { return }
        #expect(sent[0] == Self.hex("00a4040007d276000085010100"))
        #expect(sent[1] == Self.hex("00a4000c02e103"))
        // nfcpy reads the CC as 2 + 13 bytes ('00b0000002', '00b000020d'); the library reads 15 at once.
        #expect(sent[2] == Self.hex("00b000000f"))
        #expect(sent[3] == Self.hex("00a4000c02e104"))
        #expect(sent[4] == Self.hex("00b0000002"))
        #expect(sent[5] == Self.hex("00b000020e"))
    }

    @Test
    func `libnfc Type 4 NDEF file`() throws {
        // libnfc utils/nfc-emulate-forum-tag4.c:339-345 (ndef_file): NLEN 0021h + Smart Poster.
        let file = Self.hex(
            "0021 d1021c53 70910109 5402656e 4c69626e 66635101 0b55036c 69626e66 632e6f72 67"
        )
        let cc = try Type4CC(data: Self.hex("000F 20 0054 00FF 04 06 E104 FFFE 00 00"))
        let message = Data(file.dropFirst(cc.ndefLengthFieldSize))
        #expect(message.count == 0x21)
        #expect(cc.encodeNDEFFile(message) == file)
        #expect(
            try NDEFMessage(data: message).records.map(\.parsedPayload)
                == [.smartPoster(uri: "http://libnfc.org", title: "Libnfc")]
        )
    }

    // MARK: - Type 5 Tag CC: SparkFun ST25DV64KC example

    private static let sparkFunTLV = hex("03 11 D1 01 0D 55 02") + ascii("sparkfun.com") + hex("FE")

    @Test
    func `SparkFun ST25DV 8-byte CC and URI TLV`() throws {
        // CC "0xE2 0x40 0x00 0x01 0x00 0x00 0x03 0xFF": E2h two-byte addressing, version 1.0,
        // MBREAD, MLEN = (8192 - 8) / 8 = 03FFh. TLV "0x03 0x11 0xD1 0x01 0x0D 0x55 0x02 sparkfun.com 0xFE".
        let cc = Self.hex("E2 40 00 01 00 00 03 FF")
        #expect(try NDEFTagMapping.type5CCLength(firstBlock: cc) == 8)
        #expect(NDEFTagMapping.type5DataAreaLength(leadingBytes: cc) == 8184)

        let message = try #require(NDEFTagMapping.extractType5Message(from: Self.type5Blocks(cc + Self.sparkFunTLV)))
        #expect(message == NDEFMessage.uri("https://www.sparkfun.com").data)
        #expect(try NDEFMessage(data: message).records.map(\.parsedPayload) == [.uri("https://www.sparkfun.com")])
        #expect(try NDEFTagMapping.encodeNDEFTLV(message) == Self.sparkFunTLV)

        // Formatting the same 8 KiB tag (2048 blocks of 4 bytes) reproduces the CC except
        // byte 3: the library advertises no MBREAD feature (00h instead of 01h).
        let blocks = try NDEFTagMapping.buildType5Blocks(
            message: message,
            blockSize: 4,
            blockCount: 2048,
            addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
        )
        #expect(blocks[0] + blocks[1] == Self.hex("E2 40 00 00 00 00 03 FF"))
        #expect(blocks[2...].reduce(Data(), +).prefix(Self.sparkFunTLV.count) == Self.sparkFunTLV)
    }

    @Test
    func `SparkFun ST25DV 4-byte CC`() throws {
        // tag.writeCCFile4Byte(0xE1404000): E1h, version 1.0, MLEN 40h (512 bytes).
        let cc = Self.hex("E1 40 40 00")
        #expect(try NDEFTagMapping.type5CCLength(firstBlock: cc) == 4)
        #expect(NDEFTagMapping.type5DataAreaLength(leadingBytes: cc) == 512)
        let message = NDEFTagMapping.extractType5Message(from: Self.type5Blocks(cc + Self.sparkFunTLV))
        #expect(message == NDEFMessage.uri("https://www.sparkfun.com").data)
    }
}

/// FeliCa transport over an in-memory NDEF service that records block lists.
private final class NDEFVectorFeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    let systemCode = Data([0x12, 0xFC])
    private(set) var blocks: [Data]
    private(set) var reads: [[Data]] = []
    private(set) var writes: [(blockList: [Data], data: [Data])] = []

    init(blocks: [Data]) {
        self.blocks = blocks
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    private func blockNumber(_ element: Data) throws -> Int {
        let bytes = [UInt8](element)
        switch bytes.count {
        case 2: return Int(bytes[1])
        case 3: return Int(bytes[1]) | Int(bytes[2]) << 8
        default: throw NFCError.invalidResponse(element)
        }
    }

    func readWithoutEncryption(serviceCode _: Data, blockList: [Data]) async throws -> [Data] {
        reads.append(blockList)
        return try blockList.map { element in
            let number = try blockNumber(element)
            guard number < blocks.count else { throw NFCError.felicaBlockReadFailed(statusFlag: 0xA1) }
            return blocks[number]
        }
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList: [Data], blockData: [Data]) async throws {
        writes.append((blockList, blockData))
        for (element, data) in zip(blockList, blockData) {
            let number = try blockNumber(element)
            while blocks.count <= number {
                blocks.append(Data(repeating: 0, count: 16))
            }
            blocks[number] = data
        }
    }

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        nodeCodeList.map { _ in Data([0x00, 0x00]) }
    }
}
