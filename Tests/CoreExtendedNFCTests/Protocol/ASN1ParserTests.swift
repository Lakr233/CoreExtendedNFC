// ASN.1 BER-TLV parser test suite.
//
// ## References
// - ITU-T X.690 (2021): BER/DER encoding rules
//   https://www.itu.int/rec/T-REC-X.690
// - ITU-T X.690 Section 8.1.2: Tag encoding (single-byte vs multi-byte with 0x1F mask)
// - ITU-T X.690 Section 8.1.2.2: Constructed bit (bit 6 = 0x20)
// - ITU-T X.690 Section 8.1.3: Length encoding (short-form < 128, long-form 0x81/0x82/0x83)
// - ITU-T X.690 Section 8.1.3.6: Indefinite-length (0x80) — not supported by DER
// - ISO/IEC 7816-4: TLV structures in smartcard data objects
@testable import CoreExtendedNFC
import Foundation
import Testing

struct ASN1ParserTests {
    // MARK: - Tag Parsing

    // ITU-T X.690 Section 8.1.2: identifier octets

    @Test
    func `Parse single-byte tag`() throws {
        let data = Data([0x61, 0x02, 0xAA, 0xBB])
        let (tag, bytesConsumed) = try ASN1Parser.parseTag(data, at: 0)
        #expect(tag == 0x61)
        #expect(bytesConsumed == 1)
    }

    @Test
    func `Parse two-byte tag (0x5F1F)`() throws {
        let data = Data([0x5F, 0x1F, 0x02, 0xAA, 0xBB])
        let (tag, bytesConsumed) = try ASN1Parser.parseTag(data, at: 0)
        #expect(tag == 0x5F1F)
        #expect(bytesConsumed == 2)
    }

    @Test
    func `Parse two-byte tag (0x7F61)`() throws {
        let data = Data([0x7F, 0x61, 0x00])
        let (tag, bytesConsumed) = try ASN1Parser.parseTag(data, at: 0)
        #expect(tag == 0x7F61)
        #expect(bytesConsumed == 2)
    }

    // MARK: - Length Parsing

    @Test
    func `Parse short-form length (< 128)`() throws {
        let data = Data([0x10])
        let (length, bytesConsumed) = try ASN1Parser.parseLength(data, at: 0)
        #expect(length == 16)
        #expect(bytesConsumed == 1)
    }

    @Test
    func `Parse long-form length 0x81 XX (128-255)`() throws {
        let data = Data([0x81, 0xA0])
        let (length, bytesConsumed) = try ASN1Parser.parseLength(data, at: 0)
        #expect(length == 160)
        #expect(bytesConsumed == 2)
    }

    @Test
    func `Parse long-form length 0x82 XX XX (256-65535)`() throws {
        let data = Data([0x82, 0x01, 0x00])
        let (length, bytesConsumed) = try ASN1Parser.parseLength(data, at: 0)
        #expect(length == 256)
        #expect(bytesConsumed == 3)
    }

    @Test
    func `Parse long-form length 0x83 XX XX XX`() throws {
        let data = Data([0x83, 0x01, 0x00, 0x00])
        let (length, bytesConsumed) = try ASN1Parser.parseLength(data, at: 0)
        #expect(length == 65536)
        #expect(bytesConsumed == 4)
    }

    @Test
    func `Indefinite length (0x80) throws error`() {
        let data = Data([0x80])
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseLength(data, at: 0)
        }
    }

    // MARK: - Length Encoding

    @Test
    func `Encode short-form length`() {
        let encoded = ASN1Parser.encodeLength(16)
        #expect(encoded == Data([0x10]))
    }

    @Test
    func `Encode length 0x81 range`() {
        let encoded = ASN1Parser.encodeLength(160)
        #expect(encoded == Data([0x81, 0xA0]))
    }

    @Test
    func `Encode length 0x82 range`() {
        let encoded = ASN1Parser.encodeLength(256)
        #expect(encoded == Data([0x82, 0x01, 0x00]))
    }

    @Test
    func `Encode length 0x83 range`() {
        let encoded = ASN1Parser.encodeLength(65536)
        #expect(encoded == Data([0x83, 0x01, 0x00, 0x00]))
    }

    // MARK: - Full TLV Parsing

    @Test
    func `Parse simple TLV sequence`() throws {
        // Tag 0x02, Length 2, Value [0xAA, 0xBB]
        let data = Data([0x02, 0x02, 0xAA, 0xBB])
        let nodes = try ASN1Parser.parseTLV(data)

        #expect(nodes.count == 1)
        #expect(nodes[0].tag == 0x02)
        #expect(nodes[0].length == 2)
        #expect(nodes[0].value == Data([0xAA, 0xBB]))
    }

    @Test
    func `Parse multiple TLV nodes`() throws {
        // Two nodes: [02 01 AA] [04 02 BB CC]
        let data = Data([0x02, 0x01, 0xAA, 0x04, 0x02, 0xBB, 0xCC])
        let nodes = try ASN1Parser.parseTLV(data)

        #expect(nodes.count == 2)
        #expect(nodes[0].tag == 0x02)
        #expect(nodes[0].value == Data([0xAA]))
        #expect(nodes[1].tag == 0x04)
        #expect(nodes[1].value == Data([0xBB, 0xCC]))
    }

    @Test
    func `Parse constructed node and extract children`() throws {
        // Constructed tag 0x61 containing [02 01 AA]
        let data = Data([0x61, 0x03, 0x02, 0x01, 0xAA])
        let nodes = try ASN1Parser.parseTLV(data)

        #expect(nodes.count == 1)
        #expect(nodes[0].tag == 0x61)
        #expect(nodes[0].isConstructed)

        let children = try nodes[0].children()
        #expect(children.count == 1)
        #expect(children[0].tag == 0x02)
        #expect(children[0].value == Data([0xAA]))
    }

    @Test
    func `Skip zero padding bytes`() throws {
        let data = Data([0x00, 0x00, 0x02, 0x01, 0xAA])
        let nodes = try ASN1Parser.parseTLV(data)
        #expect(nodes.count == 1)
        #expect(nodes[0].tag == 0x02)
    }

    @Test
    func `Primitive tag is not constructed`() throws {
        let data = Data([0x02, 0x01, 0xAA])
        let nodes = try ASN1Parser.parseTLV(data)
        #expect(!nodes[0].isConstructed)
    }

    // MARK: - TLV Encoding

    @Test
    func `Encode TLV round-trip`() throws {
        let value = Data([0x01, 0x02, 0x03])
        let encoded = ASN1Parser.encodeTLV(tag: 0x04, value: value)
        let nodes = try ASN1Parser.parseTLV(encoded)

        #expect(nodes.count == 1)
        #expect(nodes[0].tag == 0x04)
        #expect(nodes[0].value == value)
    }

    @Test
    func `Encode TLV with multi-byte tag`() {
        let encoded = ASN1Parser.encodeTLV(tag: 0x5F1F, value: Data([0xAA]))
        // Should be: [5F 1F 01 AA]
        #expect(encoded == Data([0x5F, 0x1F, 0x01, 0xAA]))
    }

    // MARK: - findTag

    @Test
    func `findTag searches recursively`() throws {
        // 61 05 [5F1F 02 AA BB]
        let data = Data([0x61, 0x05, 0x5F, 0x1F, 0x02, 0xAA, 0xBB])
        let nodes = try ASN1Parser.parseTLV(data)

        let found = ASN1Parser.findTag(0x5F1F, in: nodes)
        #expect(found != nil)
        #expect(found?.value == Data([0xAA, 0xBB]))
    }

    @Test
    func `findTag returns nil when not found`() throws {
        let data = Data([0x02, 0x01, 0xAA])
        let nodes = try ASN1Parser.parseTLV(data)
        let found = ASN1Parser.findTag(0x99, in: nodes)
        #expect(found == nil)
    }

    // MARK: - Error Cases

    @Test
    func `Truncated data throws error`() {
        // Length says 5 bytes but only 2 available
        let data = Data([0x02, 0x05, 0xAA, 0xBB])
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTLV(data)
        }
    }

    @Test
    func `Empty tag offset throws error`() {
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTag(Data(), at: 0)
        }
    }
}

/// Malformed-input hardening (X.690 §8.1.2.4, §8.1.3.5). Every case here trapped or
/// mis-parsed before the length/tag caps and sliced-Data handling were added.
struct ASN1ParserHardeningTests {
    @Test
    func `8-byte long-form length that overflows to negative throws`() {
        // 0x88 FF×8 accumulates to -1; 0x88 80 00… to Int.min.
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTLV(Data([0x04, 0x88] + [UInt8](repeating: 0xFF, count: 8)))
        }
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTLV(Data([0x04, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0]))
        }
    }

    @Test
    func `8-byte long-form length of Int max throws`() {
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTLV(Data([0x30, 0x88, 0x7F] + [UInt8](repeating: 0xFF, count: 7)))
        }
    }

    @Test
    func `Length with more than four length octets throws`() {
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseLength(Data([0x85, 0x00, 0x00, 0x00, 0x00, 0x01]), at: 0)
        }
    }

    @Test
    func `Four-octet long-form length parses`() throws {
        let (length, consumed) = try ASN1Parser.parseLength(Data([0x84, 0x00, 0x01, 0x00, 0x00]), at: 0)
        #expect(length == 65536)
        #expect(consumed == 5)
    }

    @Test
    func `Length larger than the remaining data throws`() {
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTLV(Data([0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]))
        }
    }

    @Test
    func `Sliced Data is parsed relative to its start index`() throws {
        let sliced = Data([0xAA, 0xBB, 0x04, 0x01, 0x05]).dropFirst(2)
        #expect(sliced.startIndex == 2)

        let (tag, tagBytes) = try ASN1Parser.parseTag(sliced, at: 0)
        #expect(tag == 0x04)
        #expect(tagBytes == 1)

        let (length, lengthBytes) = try ASN1Parser.parseLength(sliced, at: 1)
        #expect(length == 1)
        #expect(lengthBytes == 1)

        let nodes = try ASN1Parser.parseTLV(sliced)
        #expect(nodes == [TLVNode(tag: 0x04, length: 1, value: Data([0x05]))])
    }

    @Test
    func `Tags longer than four bytes throw`() {
        // 1F 81 82 83 04: first octet + four subsequent octets.
        #expect(throws: NFCError.self) {
            _ = try ASN1Parser.parseTag(Data([0x1F, 0x81, 0x82, 0x83, 0x04, 0x00]), at: 0)
        }
    }

    @Test
    func `Four-byte tag parses and reports its constructed bit`() throws {
        // 3F 81 82 01: constructed (bit 6 of the first octet), three subsequent octets.
        let nodes = try ASN1Parser.parseTLV(Data([0x3F, 0x81, 0x82, 0x01, 0x02, 0x04, 0x00]))
        #expect(nodes.count == 1)
        #expect(nodes[0].tag == 0x3F81_8201)
        #expect(nodes[0].isConstructed)
        #expect(TLVNode(tag: 0x1F81_8201, length: 0, value: Data()).isConstructed == false)
    }

    @Test
    func `encodeLength uses four octets above 0xFFFFFF`() {
        #expect(ASN1Parser.encodeLength(0x0100_0000) == Data([0x84, 0x01, 0x00, 0x00, 0x00]))
        #expect(ASN1Parser.encodeLength(0x01_0000) == Data([0x83, 0x01, 0x00, 0x00]))
    }

    @Test
    func `encodeTLV writes four-byte tags`() {
        #expect(ASN1Parser.encodeTLV(tag: 0x3F81_8201, value: Data([0xAB]))
            == Data([0x3F, 0x81, 0x82, 0x01, 0x01, 0xAB]))
    }

    @Test
    func `findTag survives hostile nesting depth`() {
        // 20 000 nested SEQUENCEs around an OCTET STRING. Unbounded recursion overflowed the stack.
        let depth = 20000
        var headers: [Data] = []
        var innerLength = 2 // 04 00
        for _ in 0 ..< depth {
            let header = Data([0x30]) + ASN1Parser.encodeLength(innerLength)
            headers.append(header)
            innerLength += header.count
        }
        var data = Data(capacity: innerLength)
        for header in headers.reversed() {
            data.append(header)
        }
        data.append(contentsOf: [0x04, 0x00])

        let nodes = (try? ASN1Parser.parseTLV(data)) ?? []
        #expect(nodes.count == 1)
        #expect(ASN1Parser.findTag(0x04, in: nodes) == nil)
    }

    @Test
    func `findTag still finds shallow nested tags`() throws {
        let nodes = try ASN1Parser.parseTLV(Data([0x30, 0x05, 0x31, 0x03, 0x04, 0x01, 0x7A]))
        #expect(ASN1Parser.findTag(0x04, in: nodes)?.value == Data([0x7A]))
    }
}
