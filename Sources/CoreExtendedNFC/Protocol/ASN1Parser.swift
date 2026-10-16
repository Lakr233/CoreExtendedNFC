import Foundation

/// A parsed BER-TLV node.
///
/// Reference: ITU-T X.690 (2021) BER/DER encoding rules.
/// https://www.itu.int/rec/T-REC-X.690
public struct TLVNode: Sendable, Equatable {
    /// Tag value (1, 2, or 3 bytes encoded as UInt).
    public let tag: UInt

    /// Decoded length of the value.
    public let length: Int

    /// Raw value bytes.
    public let value: Data

    /// Whether the first tag byte marks this as a constructed node.
    public var isConstructed: Bool {
        ASN1Parser.isConstructedTag(tag)
    }

    /// Parse the value as a sequence of child TLV nodes.
    /// Only valid for constructed nodes.
    public func children() throws -> [TLVNode] {
        try ASN1Parser.parseTLV(value)
    }
}

/// Tag, length and value position of one BER-TLV node, without a copy of the value.
///
/// Returned by ``ASN1Parser/parseTLVHeaders(_:)``; `valueRange` indexes into the
/// `Data` that was parsed.
public struct TLVHeader: Sendable, Equatable {
    public let tag: UInt
    public let length: Int
    public let valueRange: Range<Data.Index>

    public init(tag: UInt, length: Int, valueRange: Range<Data.Index>) {
        self.tag = tag
        self.length = length
        self.valueRange = valueRange
    }

    /// Whether the first tag byte marks this as a constructed node.
    public var isConstructed: Bool {
        ASN1Parser.isConstructedTag(tag)
    }
}

/// BER-TLV parser used by ICAO 9303 data groups and related ASN.1 payloads.
///
/// Supports:
/// - Multi-byte tags up to ``maxTagBytes`` bytes (e.g., 0x5F1F, 0x7F61)
/// - Definite lengths in short form or long form with up to ``maxLengthBytes`` length octets
/// - Recursive parsing of constructed nodes
///
/// Malformed input (truncated tags, lengths that overflow or exceed the remaining data,
/// indefinite lengths) throws ``NFCError/dataGroupParseFailed(_:)``; it never traps.
/// Offsets passed to ``parseTag(_:at:)`` and ``parseLength(_:at:)`` are relative to
/// `data.startIndex`, so sliced `Data` is safe to pass.
public enum ASN1Parser {
    /// Longest tag accepted, in bytes (first octet plus subsequent octets).
    public static let maxTagBytes = 4

    /// Most long-form length octets accepted (X.690 §8.1.3.5). Four octets cover 4 GiB,
    /// far beyond any NFC file; ICAO 9303 itself never uses more than three.
    public static let maxLengthBytes = 4

    /// Parse all TLV nodes from the given data.
    ///
    /// Each node's `value` is a copy indexed from zero. To walk large nested input
    /// without copying every level, use ``parseTLVHeaders(_:)``.
    public static func parseTLV(_ data: Data) throws -> [TLVNode] {
        try parseTLVHeaders(data).map { header in
            TLVNode(tag: header.tag, length: header.length, value: Data(data[header.valueRange]))
        }
    }

    /// Parse the TLV nodes of one nesting level without copying their values.
    ///
    /// Same rules and errors as ``parseTLV(_:)``; each header's
    /// ``TLVHeader/valueRange`` indexes into `data` itself, so `data[header.valueRange]`
    /// is a slice of the same storage that can be parsed again for the next level.
    public static func parseTLVHeaders(_ data: Data) throws -> [TLVHeader] {
        let base = data.startIndex
        var headers: [TLVHeader] = []
        var offset = 0

        while offset < data.count {
            // Skip zero padding.
            if data[base + offset] == 0x00 {
                offset += 1
                continue
            }

            let (tag, tagBytes) = try parseTag(data, at: offset)
            offset += tagBytes

            guard offset < data.count else {
                throw NFCError.dataGroupParseFailed("Unexpected end of data after tag 0x\(String(tag, radix: 16, uppercase: true))")
            }

            let (length, lengthBytes) = try parseLength(data, at: offset)
            offset += lengthBytes

            let available = data.count - offset
            guard length <= available else {
                throw NFCError.dataGroupParseFailed(
                    "TLV length \(length) exceeds data at offset \(offset), available \(available)"
                )
            }

            headers.append(TLVHeader(tag: tag, length: length, valueRange: (base + offset) ..< (base + offset + length)))
            offset += length
        }

        return headers
    }

    /// Whether the first octet of `tag` has the constructed bit (X.690 §8.1.2.5).
    public static func isConstructedTag(_ tag: UInt) -> Bool {
        var firstTagByte = tag
        while firstTagByte > 0xFF {
            firstTagByte >>= 8
        }
        return (firstTagByte & 0x20) != 0
    }

    /// Parse a tag at the given offset (relative to `data.startIndex`). Returns (tag, bytesConsumed).
    public static func parseTag(_ data: Data, at offset: Int) throws -> (UInt, Int) {
        guard offset >= 0, offset < data.count else {
            throw NFCError.dataGroupParseFailed("Cannot parse tag: offset \(offset) out of bounds")
        }

        let base = data.startIndex
        let firstByte = data[base + offset]

        // Single-byte tag: lower 5 bits are not all 1.
        if (firstByte & 0x1F) != 0x1F {
            return (UInt(firstByte), 1)
        }

        // Multi-byte tag: subsequent octets keep bit 8 set until the last one (X.690 §8.1.2.4).
        var tag = UInt(firstByte)
        var pos = offset + 1

        while true {
            guard pos < data.count else {
                throw NFCError.dataGroupParseFailed("Incomplete multi-byte tag at offset \(offset)")
            }
            guard pos - offset < maxTagBytes else {
                throw NFCError.dataGroupParseFailed("Tag at offset \(offset) is longer than \(maxTagBytes) bytes")
            }
            let byte = data[base + pos]
            tag = (tag << 8) | UInt(byte)
            pos += 1
            if byte & 0x80 == 0 {
                break
            }
        }

        return (tag, pos - offset)
    }

    /// Parse a BER length at the given offset (relative to `data.startIndex`).
    /// Returns (length, bytesConsumed). The length is always non-negative.
    public static func parseLength(_ data: Data, at offset: Int) throws -> (Int, Int) {
        guard offset >= 0, offset < data.count else {
            throw NFCError.dataGroupParseFailed("Cannot parse length: offset \(offset) out of bounds")
        }

        let base = data.startIndex
        let firstByte = data[base + offset]

        // Short form: bit 8 is 0.
        if firstByte & 0x80 == 0 {
            return (Int(firstByte), 1)
        }

        // Long form: low 7 bits encode the number of length bytes.
        let numBytes = Int(firstByte & 0x7F)

        // Indefinite length is not supported.
        guard numBytes > 0 else {
            throw NFCError.dataGroupParseFailed("Indefinite length not supported")
        }

        guard numBytes <= maxLengthBytes else {
            throw NFCError.dataGroupParseFailed("Unsupported length size \(numBytes) at offset \(offset)")
        }

        guard numBytes <= data.count - offset - 1 else {
            throw NFCError.dataGroupParseFailed("Incomplete length encoding at offset \(offset)")
        }

        var length = 0
        for i in 0 ..< numBytes {
            length = (length << 8) | Int(data[base + offset + 1 + i])
        }

        return (length, 1 + numBytes)
    }

    /// Encode a length value to BER definite form (short form below 0x80, otherwise
    /// the shortest long form). Negative values are encoded as zero.
    public static func encodeLength(_ length: Int) -> Data {
        let length = UInt64(max(length, 0))
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        let bytes = bigEndianBytes(length)
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }

    /// Encode a complete TLV structure. The tag is written as its big-endian octets.
    public static func encodeTLV(tag: UInt, value: Data) -> Data {
        var result = Data(bigEndianBytes(UInt64(tag)))
        result.append(encodeLength(value.count))
        result.append(value)
        return result
    }

    /// Minimal big-endian representation (at least one byte).
    public static func bigEndianBytes(_ value: UInt64) -> [UInt8] {
        var bytes: [UInt8] = []
        var remaining = value
        repeat {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining != 0
        return bytes
    }

    /// Deepest nesting ``findTag(_:in:)`` descends into. Real ICAO/ISO structures nest a
    /// handful of levels; the cap keeps hostile input from exhausting the stack.
    public static let maxSearchDepth = 32

    /// Find the first node with the given tag in a parsed TLV sequence.
    public static func findTag(_ tag: UInt, in nodes: [TLVNode]) -> TLVNode? {
        findTag(tag, in: nodes, depth: 0)
    }

    public static func findTag(_ tag: UInt, in nodes: [TLVNode], depth: Int) -> TLVNode? {
        for node in nodes {
            if node.tag == tag {
                return node
            }
            if depth < maxSearchDepth, node.isConstructed,
               let found = findTag(tag, inValueOf: node.value, depth: depth + 1)
            {
                return found
            }
        }
        return nil
    }

    /// ``findTag(_:in:depth:)`` over the encoded children in `data`, walking slices so
    /// only the node that is found gets its value copied. A level that does not parse
    /// is skipped, as `try? node.children()` would.
    private static func findTag(_ tag: UInt, inValueOf data: Data, depth: Int) -> TLVNode? {
        guard let headers = try? parseTLVHeaders(data) else { return nil }
        for header in headers {
            if header.tag == tag {
                return TLVNode(tag: header.tag, length: header.length, value: Data(data[header.valueRange]))
            }
            if depth < maxSearchDepth, header.isConstructed,
               let found = findTag(tag, inValueOf: data[header.valueRange], depth: depth + 1)
            {
                return found
            }
        }
        return nil
    }
}
