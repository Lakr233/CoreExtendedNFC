import Foundation

/// ISO 7816-4 Command APDU.
///
/// Both short and extended length encodings are supported (ISO/IEC 7816-4 §5.1):
/// the extended form is used automatically when the command data is longer than
/// 255 bytes or more than 256 response bytes are expected.
public struct CommandAPDU: Sendable, Equatable {
    /// Largest Nc an APDU can encode (extended Lc).
    public static let maxCommandDataLength = 65535
    /// Largest Ne an APDU can encode (extended Le `0000`).
    public static let maxExpectedResponseLength = 65536

    public let cla: UInt8
    public let ins: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: Data?

    /// Ne: the maximum number of response data bytes expected, in `1 ... 65536`,
    /// or `nil` when the command has no Le field.
    public let expectedResponseLength: Int?

    /// Short-form Le byte. `0x00` means 256 bytes, and is also reported when
    /// ``expectedResponseLength`` exceeds 256 (extended Le); read
    /// ``expectedResponseLength`` for the exact value.
    public var le: UInt8? {
        guard let expectedResponseLength else { return nil }
        return expectedResponseLength >= 256 ? 0x00 : UInt8(expectedResponseLength)
    }

    /// Create a command with a short-form Le byte (`0x00` means 256 bytes).
    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data? = nil, le: UInt8? = nil) {
        self.init(
            cla: cla,
            ins: ins,
            p1: p1,
            p2: p2,
            data: data,
            expectedResponseLength: le.map { $0 == 0x00 ? 256 : Int($0) }
        )
    }

    /// Create a command with an explicit Ne. Values outside `1 ... 65536` are clamped
    /// into that range; pass `nil` for no Le field.
    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data? = nil, expectedResponseLength: Int?) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedResponseLength = expectedResponseLength.map {
            Swift.min(Swift.max($0, 1), Self.maxExpectedResponseLength)
        }
    }

    /// `true` when ``bytes`` uses extended Lc/Le fields.
    public var isExtendedLength: Bool {
        (data?.count ?? 0) > 255 || (expectedResponseLength ?? 0) > 256
    }

    /// Encode to raw bytes per ISO/IEC 7816-4 §5.1:
    /// short `[CLA, INS, P1, P2, (Lc, Data...,) (Le)]`, or extended
    /// `[CLA, INS, P1, P2, (00, Lc1, Lc2, Data...,) (00?, Le1, Le2)]`.
    ///
    /// Never traps. Command data longer than ``maxCommandDataLength`` cannot be encoded;
    /// its Lc is clamped to 65535 and such a command must not be sent.
    public var bytes: Data {
        var result = Data([cla, ins, p1, p2])
        let extended = isExtendedLength
        let body = data ?? Data()

        if !body.isEmpty {
            if extended {
                let lc = Swift.min(body.count, Self.maxCommandDataLength)
                result.append(contentsOf: [0x00, UInt8(lc >> 8), UInt8(lc & 0xFF)])
            } else {
                result.append(UInt8(body.count))
            }
            result.append(body)
        }

        if let le, let ne = expectedResponseLength {
            if extended {
                // Extended Le: two bytes, 0000 = 65536; preceded by 00 when there is no Lc field.
                let value = ne >= Self.maxExpectedResponseLength ? 0 : ne
                if body.isEmpty { result.append(0x00) }
                result.append(contentsOf: [UInt8(value >> 8), UInt8(value & 0xFF)])
            } else {
                result.append(le)
            }
        }
        return result
    }

    /// The value CoreNFC expects for `expectedResponseLength`: `-1` for no Le field,
    /// otherwise Ne (CoreNFC rejects `0`, which in short encoding means 256).
    public var nfcExpectedResponseLength: Int {
        expectedResponseLength ?? -1
    }

    /// A copy of this command with a different Ne, e.g. to re-issue it after `6Cxx`.
    public func withExpectedResponseLength(_ length: Int?) -> CommandAPDU {
        CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2, data: data, expectedResponseLength: length)
    }

    /// Wrap a DESFire native command in ISO 7816 framing.
    /// Format: [0x90, CMD, 0x00, 0x00, LEN, DATA..., 0x00]
    public static func desfireWrap(command: UInt8, data: Data? = nil) -> CommandAPDU {
        CommandAPDU(
            cla: 0x90,
            ins: command,
            p1: 0x00,
            p2: 0x00,
            data: data,
            le: 0x00
        )
    }

    // MARK: - Common APDUs

    /// SELECT by AID (DF name).
    public static func select(aid: Data) -> CommandAPDU {
        CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: aid, le: 0x00)
    }

    /// SELECT by file ID.
    public static func selectFile(id: Data) -> CommandAPDU {
        CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x00, p2: 0x0C, data: id)
    }

    /// READ BINARY from the current file.
    ///
    /// Offsets up to `0x7FFF` use INS `B0` with the offset in `P1 || P2` (P1 bit 8 = 0).
    /// Larger offsets cannot be encoded that way, so INS `B1` is used with an offset
    /// data object `54` (ISO/IEC 7816-4 §11.2.3). The card then wraps the content in
    /// DO `53`; unwrap it with ``ResponseAPDU/binaryData(for:)``. Because Ne also covers
    /// the DO `53` header, a `B1` read may return a few bytes fewer than `length`.
    public static func readBinary(offset: UInt16, length: UInt8) -> CommandAPDU {
        binaryRead(offset: Int(offset), expectedLength: length == 0x00 ? 256 : Int(length))
    }

    /// UPDATE BINARY to the current file.
    ///
    /// Offsets up to `0x7FFF` use INS `D6` with the offset in `P1 || P2`. Larger offsets
    /// use INS `D7` with data objects `54` (offset) and `53` (content), per
    /// ISO/IEC 7816-4 §11.2 (odd-INS data-object form).
    public static func updateBinary(offset: UInt16, data: Data) -> CommandAPDU {
        if offset <= maxShortBinaryOffset {
            return CommandAPDU(
                cla: 0x00,
                ins: 0xD6,
                p1: UInt8(offset >> 8),
                p2: UInt8(offset & 0xFF),
                data: data
            )
        }
        let body = offsetDataObject(Int(offset)) + ASN1Parser.encodeTLV(tag: 0x53, value: data)
        return CommandAPDU(cla: 0x00, ins: 0xD7, p1: 0x00, p2: 0x00, data: body)
    }

    /// GET RESPONSE for chained responses (`SW1 == 0x61`).
    public static func getResponse(length: UInt8) -> CommandAPDU {
        CommandAPDU(cla: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, le: length)
    }

    // MARK: - Binary offset encoding

    /// Largest offset that fits in `P1 || P2` of an even-INS READ/UPDATE BINARY (15 bits).
    public static let maxShortBinaryOffset = 0x7FFF

    /// Build a READ BINARY for `offset` expecting `expectedLength` content bytes (`1 ... 256`).
    /// Negative offsets are treated as `0`.
    public static func binaryRead(offset: Int, expectedLength: Int) -> CommandAPDU {
        let offset = Swift.max(offset, 0)
        let wanted = Swift.min(Swift.max(expectedLength, 1), 256)

        if offset <= maxShortBinaryOffset {
            return CommandAPDU(
                cla: 0x00,
                ins: 0xB0,
                p1: UInt8(offset >> 8),
                p2: UInt8(offset & 0xFF),
                expectedResponseLength: wanted
            )
        }

        // Odd INS: the response is `53 L content`, so Ne must leave room for the DO header.
        // Stay within short Le (≤ 256 bytes) so cards without extended length still work.
        let content = Swift.min(wanted, 253)
        let header = content < 0x80 ? 2 : 3
        return CommandAPDU(
            cla: 0x00,
            ins: 0xB1,
            p1: 0x00,
            p2: 0x00,
            data: offsetDataObject(offset),
            expectedResponseLength: content + header
        )
    }

    /// Offset data object `54` with at least two value bytes, big-endian.
    public static func offsetDataObject(_ offset: Int) -> Data {
        var value: [UInt8] = []
        var remaining = UInt64(Swift.max(offset, 0))
        repeat {
            value.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining != 0
        while value.count < 2 {
            value.insert(0x00, at: 0)
        }
        return Data([0x54, UInt8(value.count)] + value)
    }
}

/// ISO 7816-4 Response APDU.
public struct ResponseAPDU: Sendable, Equatable {
    public let data: Data
    public let sw1: UInt8
    public let sw2: UInt8

    public init(data: Data, sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    /// Parse a raw response where the last 2 bytes are SW1 and SW2.
    public init?(rawResponse: Data) {
        guard rawResponse.count >= 2 else { return nil }
        data = Data(rawResponse.dropLast(2))
        sw1 = rawResponse[rawResponse.endIndex - 2]
        sw2 = rawResponse[rawResponse.endIndex - 1]
    }

    /// Status word as combined UInt16.
    public var statusWord: UInt16 {
        UInt16(sw1) << 8 | UInt16(sw2)
    }

    /// `true` when `SW1 == 0x90` and `SW2 == 0x00`.
    public var isSuccess: Bool {
        sw1 == 0x90 && sw2 == 0x00
    }

    /// `true` when a SELECT by AID was refused because the card does not carry that
    /// application: `6A82` (file or application not found), `6A86` (incorrect P1-P2),
    /// `6A81` (function not supported), `6999` (applet selection failed), or
    /// `6D00` / `6E00` (instruction or class not supported, e.g. no ISO SELECT at all).
    public var isApplicationNotFound: Bool {
        [0x6A82, 0x6A86, 0x6A81, 0x6999, 0x6D00, 0x6E00].contains(statusWord)
    }

    /// `true` when more data is available via GET RESPONSE.
    public var needsGetResponse: Bool {
        sw1 == 0x61
    }

    /// For `6Cxx` ("wrong Le field"), the Ne the card asks the command to be
    /// re-issued with (`xx`, where `00` means 256). `nil` for any other status.
    public var correctedExpectedLength: Int? {
        guard sw1 == 0x6C else { return nil }
        return sw2 == 0x00 ? 256 : Int(sw2)
    }

    /// `true` when the card requests a DESFire Additional Frame.
    public var hasMoreFrames: Bool {
        sw1 == 0x91 && sw2 == 0xAF
    }

    /// The file content returned for a READ BINARY `command`.
    ///
    /// For INS `B0` this is ``data`` unchanged. For INS `B1` the content is the value
    /// of the leading DO `53` (ISO/IEC 7816-4 §11.2.3); an empty response yields empty
    /// content, and anything else throws ``NFCError/invalidResponse(_:)``.
    public func binaryData(for command: CommandAPDU) throws -> Data {
        guard command.ins == 0xB1, !data.isEmpty else {
            return data
        }
        let bytes = Data(data)
        guard bytes[0] == 0x53 else {
            throw NFCError.invalidResponse(bytes)
        }
        let length: Int
        let lengthBytes: Int
        do {
            (length, lengthBytes) = try ASN1Parser.parseLength(bytes, at: 1)
        } catch {
            throw NFCError.invalidResponse(bytes)
        }
        let start = 1 + lengthBytes
        guard length <= bytes.count - start else {
            throw NFCError.invalidResponse(bytes)
        }
        return Data(bytes[start ..< start + length])
    }
}
