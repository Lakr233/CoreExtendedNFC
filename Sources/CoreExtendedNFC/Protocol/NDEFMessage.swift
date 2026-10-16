import Foundation

/// NFC Forum NDEF Type Name Format values.
public enum NDEFTypeNameFormat: UInt8, Sendable, Equatable {
    case empty = 0x00
    case wellKnown = 0x01
    case mimeMedia = 0x02
    case absoluteURI = 0x03
    case external = 0x04
    case unknown = 0x05
    case unchanged = 0x06
    case reserved = 0x07
}

/// Parsed representation of an NDEF message.
public struct NDEFMessage: Sendable, Equatable {
    public let records: [NDEFRecord]

    public init(records: [NDEFRecord]) {
        self.records = records
    }

    public init(data: Data) throws {
        records = try NDEFRecord.parseMessage(data)
    }

    /// Serialised message bytes (NDEF 1.0 §3). Never traps: a type or ID longer than
    /// 255 bytes cannot be encoded and is truncated to 255 bytes here. Use
    /// ``validatedData()`` before writing to a tag to reject such records instead.
    public var data: Data {
        NDEFRecord.serializeMessage(records)
    }

    /// Serialised message bytes, throwing ``NFCError/invalidParameter(_:)`` when a
    /// record cannot be encoded (type or ID longer than 255 bytes, payload longer than
    /// 2³² − 1 bytes, or no records at all) or breaks the per-TNF rules of NDEF 1.0
    /// §3.2.6: an Empty record (TNF 00h) with a type, ID or payload, an Unknown record
    /// (TNF 05h) with a type, or a record with TNF 06h (Unchanged, only valid on chunks,
    /// which the serialiser never produces) or 07h (Reserved).
    public func validatedData() throws -> Data {
        guard !records.isEmpty else {
            throw NFCError.invalidParameter("An NDEF message needs at least one record")
        }
        for record in records {
            if let violation = NDEFRecord.tnfViolation(
                record.typeNameFormat,
                typeLength: record.type.count,
                identifierLength: record.identifier.count,
                payloadLength: record.payload.count
            ) {
                throw NFCError.invalidParameter(violation)
            }
            guard record.typeNameFormat != .unchanged else {
                throw NFCError.invalidParameter("TNF Unchanged (06h) is only valid on middle and terminating chunks")
            }
            guard record.typeNameFormat != .reserved else {
                throw NFCError.invalidParameter("NDEF TNF 07h is reserved and must not be written")
            }
            guard record.type.count <= 0xFF else {
                throw NFCError.invalidParameter("NDEF record type is \(record.type.count) bytes; the limit is 255")
            }
            guard record.identifier.count <= 0xFF else {
                throw NFCError.invalidParameter("NDEF record ID is \(record.identifier.count) bytes; the limit is 255")
            }
            guard UInt64(record.payload.count) <= UInt64(UInt32.max) else {
                throw NFCError.invalidParameter("NDEF record payload is too large")
            }
        }
        return data
    }

    public static func text(_ text: String, languageCode: String = "en") -> NDEFMessage {
        NDEFMessage(records: [.text(text, languageCode: languageCode)])
    }

    public static func uri(_ uri: String) -> NDEFMessage {
        NDEFMessage(records: [.uri(uri)])
    }
}

/// Parsed representation of one NDEF record.
public struct NDEFRecord: Sendable, Equatable {
    public enum Payload: Sendable, Equatable {
        case empty
        case text(languageCode: String, text: String)
        case uri(String)
        case mime(type: String, data: Data)
        case smartPoster(uri: String?, title: String?)
        case external(type: String, data: Data)
        case unknown(data: Data)
    }

    public let typeNameFormat: NDEFTypeNameFormat
    public let type: Data
    public let identifier: Data
    public let payload: Data

    public init(
        typeNameFormat: NDEFTypeNameFormat,
        type: Data,
        identifier: Data = Data(),
        payload: Data
    ) {
        self.typeNameFormat = typeNameFormat
        self.type = type
        self.identifier = identifier
        self.payload = payload
    }

    public var parsedPayload: Payload {
        switch typeNameFormat {
        case .empty:
            return .empty
        case .wellKnown:
            if type == Data([0x54]) {
                return Self.parseTextPayload(payload)
            }
            if type == Data([0x55]) {
                return Self.parseURIPayload(payload)
            }
            if type == Data([0x53, 0x70]) {
                return Self.parseSmartPoster(payload)
            }
        case .mimeMedia:
            return .mime(type: String(data: type, encoding: .utf8) ?? type.hexString, data: payload)
        case .absoluteURI:
            // NDEF 1.0 §3.2.6: for TNF 03h the TYPE field holds the absolute URI
            // (RFC 3986); the payload, if any, is the resource it identifies.
            return .uri(String(data: type, encoding: .utf8) ?? type.hexString)
        case .external:
            return .external(type: String(data: type, encoding: .utf8) ?? type.hexString, data: payload)
        case .unknown, .unchanged, .reserved:
            break
        }

        return .unknown(data: payload)
    }

    public var displayType: String {
        switch parsedPayload {
        case .empty:
            "Empty"
        case .text:
            "Text"
        case .uri:
            "URI"
        case let .mime(type, _):
            "MIME: \(type)"
        case .smartPoster:
            "Smart Poster"
        case let .external(type, _):
            "External: \(type)"
        case .unknown:
            type.isEmpty ? "Unknown" : "Type \(String(data: type, encoding: .utf8) ?? type.hexString)"
        }
    }

    public var displayValue: String {
        switch parsedPayload {
        case .empty:
            return "No payload"
        case let .text(languageCode, text):
            return "[\(languageCode)] \(text)"
        case let .uri(uri):
            return uri
        case let .mime(type, data):
            return "\(type) (\(data.count) bytes)"
        case let .smartPoster(uri, title):
            let resolvedTitle = title ?? "Untitled"
            return [resolvedTitle, uri].compactMap(\.self).joined(separator: " · ")
        case let .external(_, data):
            return "\(data.count) bytes"
        case let .unknown(data):
            return "\(data.count) bytes"
        }
    }

    /// Well-known Text record (RTD-Text 1.0), UTF-8 encoded. The status byte has six bits
    /// for the language-code length, so codes longer than 63 bytes are truncated.
    public static func text(_ text: String, languageCode: String = "en") -> NDEFRecord {
        let language = Data(Data(languageCode.utf8).prefix(0x3F))
        let encodedText = Data(text.utf8)
        let status = UInt8(language.count & 0x3F)
        return NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Data([0x54]),
            payload: Data([status]) + language + encodedText
        )
    }

    public static func uri(_ uri: String) -> NDEFRecord {
        let (prefixCode, suffix) = abbreviateURI(uri)
        return NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Data([0x55]),
            payload: Data([prefixCode]) + Data(suffix.utf8)
        )
    }

    public static func mime(type: String, data: Data) -> NDEFRecord {
        NDEFRecord(typeNameFormat: .mimeMedia, type: Data(type.utf8), payload: data)
    }

    public static func external(type: String, data: Data) -> NDEFRecord {
        NDEFRecord(typeNameFormat: .external, type: Data(type.utf8), payload: data)
    }

    public static func smartPoster(uri: String, title: String? = nil) -> NDEFRecord {
        var embeddedRecords = [NDEFRecord.uri(uri)]
        if let title {
            embeddedRecords.append(.text(title))
        }
        return NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Data([0x53, 0x70]),
            payload: serializeMessage(embeddedRecords)
        )
    }

    /// NDEF 1.0 §3.2.6 field constraints for one record, or `nil` when the record
    /// honours them: TNF 00h (Empty) has no type, ID or payload; TNF 05h (Unknown)
    /// and 06h (Unchanged) have no type; the reserved TNF 07h is held to the Unknown rule.
    static func tnfViolation(
        _ tnf: NDEFTypeNameFormat,
        typeLength: Int,
        identifierLength: Int,
        payloadLength: Int
    ) -> String? {
        switch tnf {
        case .empty:
            guard typeLength == 0, identifierLength == 0, payloadLength == 0 else {
                return "An NDEF record with TNF Empty (00h) must have no type, ID or payload"
            }
        case .unknown, .unchanged, .reserved:
            // NDEF 1.0 §3.2.6: a parser SHOULD treat the reserved TNF 07h as Unknown (05h).
            guard typeLength == 0 else {
                let name = switch tnf {
                case .unknown: "Unknown (05h)"
                case .unchanged: "Unchanged (06h)"
                default: "reserved 07h (treated as Unknown)"
                }
                return "An NDEF record with TNF \(name) must have no type"
            }
        case .wellKnown, .mimeMedia, .absoluteURI, .external:
            break
        }
        return nil
    }

    /// Parse an NDEF message (NDEF 1.0 §3). Chunked payloads (§2.3.3) are reassembled
    /// into one record carrying the initial chunk's TNF, type and ID.
    ///
    /// The parse is strict: records that break the per-TNF field rules of §3.2.6
    /// (see ``NDEFMessage/validatedData()``; the reserved TNF 07h is read as Unknown) and any byte after
    /// the record carrying ME are rejected with ``NFCError/invalidResponse(_:)``, as
    /// Android's `NdefMessage` parser does.
    public static func parseMessage(_ data: Data) throws -> [NDEFRecord] {
        let data = Data(data) // Rebase so integer offsets index from zero.
        var records: [NDEFRecord] = []
        var offset = 0
        var sawMessageBegin = false
        var sawMessageEnd = false
        var pendingChunk: NDEFRecord?

        while offset < data.count {
            let header = data[offset]
            offset += 1

            let messageBegin = (header & 0x80) != 0
            let messageEnd = (header & 0x40) != 0
            let chunkFlag = (header & 0x20) != 0
            let shortRecord = (header & 0x10) != 0
            let idLengthPresent = (header & 0x08) != 0
            let tnfValue = header & 0x07

            guard let tnf = NDEFTypeNameFormat(rawValue: tnfValue) else {
                throw NFCError.invalidResponse(Data([tnfValue]))
            }
            guard offset < data.count else {
                throw NFCError.invalidResponse(data)
            }

            let typeLength = Int(data[offset])
            offset += 1

            let payloadLength: Int
            if shortRecord {
                guard offset < data.count else {
                    throw NFCError.invalidResponse(data)
                }
                payloadLength = Int(data[offset])
                offset += 1
            } else {
                guard offset + 4 <= data.count else {
                    throw NFCError.invalidResponse(data)
                }
                payloadLength = Int(Data(data[offset ..< offset + 4]).uint32BE)
                offset += 4
            }

            let identifierLength: Int
            if idLengthPresent {
                guard offset < data.count else {
                    throw NFCError.invalidResponse(data)
                }
                identifierLength = Int(data[offset])
                offset += 1
            } else {
                identifierLength = 0
            }

            guard typeLength + identifierLength + payloadLength <= data.count - offset else {
                throw NFCError.invalidResponse(data)
            }

            guard tnfViolation(
                tnf,
                typeLength: typeLength,
                identifierLength: identifierLength,
                payloadLength: payloadLength
            ) == nil else {
                throw NFCError.invalidResponse(data)
            }

            let type = Data(data[offset ..< offset + typeLength])
            offset += typeLength
            let identifier = Data(data[offset ..< offset + identifierLength])
            offset += identifierLength
            let payload = Data(data[offset ..< offset + payloadLength])
            offset += payloadLength

            sawMessageBegin = sawMessageBegin || messageBegin
            sawMessageEnd = sawMessageEnd || messageEnd

            // A non-terminating chunk must not end the message (§2.3.3).
            guard !(chunkFlag && messageEnd) else {
                throw NFCError.invalidResponse(data)
            }

            if let initial = pendingChunk {
                // Middle or terminating chunk: TNF "unchanged", no type, no ID (§2.3.3).
                guard tnf == .unchanged, typeLength == 0, !idLengthPresent, !messageBegin else {
                    throw NFCError.invalidResponse(data)
                }
                let combined = NDEFRecord(
                    typeNameFormat: initial.typeNameFormat,
                    type: initial.type,
                    identifier: initial.identifier,
                    payload: initial.payload + payload
                )
                if chunkFlag {
                    pendingChunk = combined
                } else {
                    pendingChunk = nil
                    records.append(combined)
                }
            } else {
                // TNF "unchanged" is only valid inside a chunk sequence (§3.2.6).
                guard tnf != .unchanged else {
                    throw NFCError.invalidResponse(data)
                }
                let record = NDEFRecord(
                    typeNameFormat: tnf,
                    type: type,
                    identifier: identifier,
                    payload: payload
                )
                if chunkFlag {
                    pendingChunk = record
                } else {
                    records.append(record)
                }
            }

            if messageEnd {
                break
            }
        }

        // ME marks the last record of the message (NDEF 1.0 §3.2.2), so nothing may follow
        // it (Android CTS NdefTest.java:94-100 rejects such messages as too long).
        guard offset == data.count,
              pendingChunk == nil, sawMessageBegin, sawMessageEnd, !records.isEmpty
        else {
            throw NFCError.invalidResponse(data)
        }

        return records
    }

    /// Serialize records into one NDEF message, setting MB on the first and ME on the last record.
    public static func serializeMessage(_ records: [NDEFRecord]) -> Data {
        records.enumerated().reduce(into: Data()) { result, pair in
            let (index, record) = pair
            let messageBegin = index == 0
            let messageEnd = index == records.count - 1
            // Field widths are fixed; longer values cannot be encoded (see `validatedData()`).
            let type = record.type.prefix(0xFF)
            let identifier = record.identifier.prefix(0xFF)
            let payload = record.payload.prefix(Int(UInt32.max))
            let shortRecord = payload.count < 256
            let hasIdentifier = !identifier.isEmpty

            var header = record.typeNameFormat.rawValue
            if messageBegin { header |= 0x80 }
            if messageEnd { header |= 0x40 }
            if shortRecord { header |= 0x10 }
            if hasIdentifier { header |= 0x08 }

            result.append(header)
            result.append(UInt8(type.count))
            if shortRecord {
                result.append(UInt8(payload.count))
            } else {
                let length = UInt32(payload.count)
                result.append(contentsOf: [
                    UInt8((length >> 24) & 0xFF),
                    UInt8((length >> 16) & 0xFF),
                    UInt8((length >> 8) & 0xFF),
                    UInt8(length & 0xFF),
                ])
            }
            if hasIdentifier {
                result.append(UInt8(identifier.count))
            }
            result.append(type)
            if hasIdentifier {
                result.append(identifier)
            }
            result.append(payload)
        }
    }

    public static func parseTextPayload(_ payload: Data) -> Payload {
        guard let status = payload.first else {
            return .unknown(data: payload)
        }
        let usesUTF16 = (status & 0x80) != 0
        let languageLength = Int(status & 0x3F)
        guard payload.count >= 1 + languageLength else {
            return .unknown(data: payload)
        }

        let languageData = Data(payload.dropFirst().prefix(languageLength))
        let textData = Data(payload.dropFirst(1 + languageLength))
        let languageCode = String(data: languageData, encoding: .utf8) ?? "und"
        let text = (usesUTF16 ? decodeUTF16Text(textData) : String(data: textData, encoding: .utf8))
            ?? textData.hexString
        return .text(languageCode: languageCode, text: text)
    }

    /// RTD-Text 1.0 §3.4: UTF-16 text may start with a BOM; without one it is big-endian.
    public static func decodeUTF16Text(_ textData: Data) -> String? {
        if textData.starts(with: [0xFE, 0xFF]) {
            return String(data: textData.dropFirst(2), encoding: .utf16BigEndian)
        }
        if textData.starts(with: [0xFF, 0xFE]) {
            return String(data: textData.dropFirst(2), encoding: .utf16LittleEndian)
        }
        return String(data: textData, encoding: .utf16BigEndian)
    }

    public static func parseURIPayload(_ payload: Data) -> Payload {
        guard let prefixCode = payload.first else {
            return .unknown(data: payload)
        }
        let suffix = String(data: payload.dropFirst(), encoding: .utf8) ?? payload.dropFirst().hexString
        // URI RTD 1.0 §3.2.2: codes 0x24–0xFF are RFU and are treated as 0x00 (no prefix).
        let index = Int(prefixCode)
        let prefix = index < uriPrefixMap.count ? uriPrefixMap[index] : ""
        return .uri(prefix + suffix)
    }

    /// Smart Poster RTD 1.0 §3: the payload is an NDEF message whose URI record is
    /// mandatory and whose Text records carry titles. Only direct URI ("U"), Text
    /// ("T") and absolute-URI (TNF 03h) children are decoded; a URI record wins over an
    /// absolute-URI record, which is used only when no URI record is present (as
    /// Android's `NdefRecord.toUri()` accepts both). Nested records (including nested
    /// Smart Posters) are not parsed, so a deeply nested payload costs linear time
    /// instead of 2^depth.
    public static func parseSmartPoster(_ payload: Data) -> Payload {
        guard let nestedRecords = try? parseMessage(payload) else {
            return .unknown(data: payload)
        }
        var uri: String?
        var absoluteURI: String?
        var title: String?
        for record in nestedRecords {
            switch record.typeNameFormat {
            case .wellKnown:
                if uri == nil, record.type == Data([0x55]), case let .uri(value) = parseURIPayload(record.payload) {
                    uri = value
                } else if title == nil, record.type == Data([0x54]),
                          case let .text(_, value) = parseTextPayload(record.payload)
                {
                    title = value
                }
            case .absoluteURI:
                if absoluteURI == nil, case let .uri(value) = record.parsedPayload {
                    absoluteURI = value
                }
            default:
                break
            }
        }
        return .smartPoster(uri: uri ?? absoluteURI, title: title)
    }

    /// URI RTD 1.0 Table 3: choose the code with the longest matching prefix, so
    /// "http://www." wins over "http://" and "urn:epc:id:" over "urn:".
    public static func abbreviateURI(_ uri: String) -> (UInt8, String) {
        var best: (code: Int, length: Int) = (0, 0)
        for (index, prefix) in uriPrefixMap.enumerated()
            where prefix.count > best.length && uri.hasPrefix(prefix)
        {
            best = (index, prefix.count)
        }
        return (UInt8(best.code), String(uri.dropFirst(best.length)))
    }

    public static let uriPrefixMap: [String] = [
        "",
        "http://www.",
        "https://www.",
        "http://",
        "https://",
        "tel:",
        "mailto:",
        "ftp://anonymous:anonymous@",
        "ftp://ftp.",
        "ftps://",
        "sftp://",
        "smb://",
        "nfs://",
        "ftp://",
        "dav://",
        "news:",
        "telnet://",
        "imap:",
        "rtsp://",
        "urn:",
        "pop:",
        "sip:",
        "sips:",
        "tftp:",
        "btspp://",
        "btl2cap://",
        "btgoep://",
        "tcpobex://",
        "irdaobex://",
        "file://",
        "urn:epc:id:",
        "urn:epc:tag:",
        "urn:epc:pat:",
        "urn:epc:raw:",
        "urn:epc:",
        "urn:nfc:",
    ]
}
