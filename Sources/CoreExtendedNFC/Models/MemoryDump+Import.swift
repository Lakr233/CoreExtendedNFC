import Foundation

extension MemoryDump {
    /// Import a Flipper Zero `.nfc` page dump.
    public static func importFlipperNFC(_ text: String) throws -> MemoryDump {
        let parsed = try FlipperNFCFile(text: text)
        return MemoryDump(
            cardInfo: CardInfo(
                type: parsed.cardType,
                uid: parsed.uid,
                atqa: parsed.atqa,
                sak: parsed.sak
            ),
            pages: try parsed.pages.map { try $0.validatedPage() },
            facts: [
                .init(key: "Imported From", value: "Flipper Zero .nfc"),
                .init(key: "Pages Total", value: "\(parsed.totalPages)"),
            ],
            capabilities: [.readable]
        )
    }

    /// Import a Proxmark3 MFU dump.
    ///
    /// Supports both the documented 56-byte header format and plain 4-byte-page binaries.
    public static func importProxmark3MFU(_ data: Data) throws -> MemoryDump {
        let parsed = try Proxmark3MFUDump(data: data)
        return MemoryDump(
            cardInfo: CardInfo(
                type: parsed.cardType,
                uid: parsed.uid,
                // ATQA 0x0044 (Type 2), stored most-significant byte first like CardIdentifier expects.
                atqa: parsed.cardType.family == .ntag || parsed.cardType.family == .mifareUltralight ? Data([0x00, 0x44]) : nil,
                sak: parsed.cardType.family == .ntag || parsed.cardType.family == .mifareUltralight ? 0x00 : nil
            ),
            pages: try parsed.pages.map { try $0.validatedPage() },
            facts: [
                .init(key: "Imported From", value: "Proxmark3 MFU"),
                .init(key: "Pages Total", value: "\(parsed.pages.count)"),
            ],
            capabilities: [.readable]
        )
    }

    /// A page parsed from an imported file, before its number is range-checked.
    private struct ImportedPageRecord {
        let number: Int
        let data: Data

        func validatedPage() throws -> Page {
            guard let pageNumber = UInt8(exactly: number) else {
                throw NFCError.malformedDump("Page \(number) is outside the Type 2 page range 0-255")
            }
            return Page(number: pageNumber, data: data)
        }
    }

    private struct FlipperNFCFile {
        typealias PageRecord = ImportedPageRecord

        let uid: Data
        let atqa: Data?
        let sak: UInt8?
        let totalPages: Int
        let pages: [PageRecord]
        private let version: Data?
        private let typeName: String?

        init(text: String) throws {
            var fields: [String: String] = [:]
            var pageRecords: [PageRecord] = []

            for rawLine in text.split(whereSeparator: \.isNewline) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !line.isEmpty else { continue }
                guard let separator = line.firstIndex(of: ":") else { continue }

                let key = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)

                if key.hasPrefix("Page "), let pageNumber = Int(key.dropFirst(5)) {
                    guard let pageData = Data(hexString: value), pageData.count == 4 else {
                        throw NFCError.malformedDump("Page \(pageNumber) is not 4 bytes of hex")
                    }
                    // Type 2 page addresses are one byte (0...255), and each page appears once.
                    guard UInt8(exactly: pageNumber) != nil,
                          !pageRecords.contains(where: { $0.number == pageNumber })
                    else {
                        throw NFCError.malformedDump("Page \(pageNumber) is out of range or repeated")
                    }
                    pageRecords.append(.init(number: pageNumber, data: pageData))
                } else {
                    fields[key] = value
                }
            }

            guard fields["Filetype"] == "Flipper NFC device",
                  fields["Device type"] == "NTAG/Ultralight",
                  let uidValue = fields["UID"],
                  let uid = Data(hexString: uidValue),
                  let totalPagesValue = fields["Pages total"],
                  let totalPages = Int(totalPagesValue),
                  totalPages > 0
            else {
                throw NFCError.malformedDump("Unsupported Flipper NFC file format")
            }

            self.uid = uid
            atqa = fields["ATQA"].flatMap(Data.init(hexString:))
            sak = fields["SAK"].flatMap { UInt8($0, radix: 16) }
            version = fields["Mifare version"].flatMap(Data.init(hexString:))
            typeName = fields["NTAG/Ultralight type"]
            self.totalPages = totalPages
            pages = pageRecords.sorted(by: { $0.number < $1.number })
        }

        var cardType: CardType {
            // An all-zero version means GET_VERSION was not available (Ultralight, Ultralight C).
            if let version, version != Data(repeating: 0x00, count: version.count),
               let parsedVersion = try? UltralightVersionResponse(data: version)
            {
                return parsedVersion.cardType
            }
            if let typeName, let type = MemoryDump.cardType(forFlipperTypeName: typeName) {
                return type
            }

            return switch totalPages {
            case 20: .mifareUltralightEV1_MF0UL11
            case 41: .mifareUltralightEV1_MF0UL21
            case 45: .ntag213
            case 48: .mifareUltralightC
            case 135: .ntag215
            case 231: .ntag216
            default: .mifareUltralight
            }
        }
    }

    private struct Proxmark3MFUDump {
        typealias PageRecord = ImportedPageRecord

        /// Size of the Proxmark3 `mfu_dump_t` header that precedes page data:
        /// version[8], tbo[2], tbo1[1], pages[1], signature[32], counter_tearing[3][4].
        static let headerLength = 56
        /// Offset of `pages` in the header: the index of the last page in the dump.
        static let lastPageIndexOffset = 11

        /// Page totals of the known Type 2 memory maps (Ultralight, MF0UL11, MF0UL21,
        /// NTAG213, Ultralight C, NTAG215, NTAG216).
        static let knownPageTotals: Set<Int> = [16, 20, 41, 45, 48, 135, 231]

        /// Whether `data` is a headered Proxmark3 dump: the header's last-page index must
        /// agree with the number of 4-byte pages that follow it.
        ///
        /// When the file length is also exactly a known plain page dump (for example 64
        /// bytes = 16 Ultralight pages, which could also read as a header plus 2 pages),
        /// the plain reading wins unless the header is plausible on its own: the version
        /// field is a GET_VERSION response or all zero, and the first page after the header
        /// carries a consistent BCC0 (ISO/IEC 14443-3: `0x88 ^ UID0 ^ UID1 ^ UID2`).
        static func hasHeader(_ data: Data) -> Bool {
            guard data.count >= headerLength + 4,
                  (data.count - headerLength).isMultiple(of: 4)
            else { return false }
            let lastPageIndex = Int(data[data.startIndex + lastPageIndexOffset])
            guard lastPageIndex + 1 == (data.count - headerLength) / 4 else { return false }

            let isAmbiguousWithPlainDump = data.count.isMultiple(of: 4)
                && knownPageTotals.contains(data.count / 4)
            guard isAmbiguousWithPlainDump else { return true }
            return hasPlausibleVersion(data) && hasConsistentBCC0(afterHeaderIn: data)
        }

        private static func hasPlausibleVersion(_ data: Data) -> Bool {
            let version = data.prefix(8)
            return version.allSatisfy { $0 == 0x00 } || looksLikeHeader(data)
        }

        private static func hasConsistentBCC0(afterHeaderIn data: Data) -> Bool {
            let page0 = data.startIndex + headerLength
            return data[page0 + 3] == 0x88 ^ data[page0] ^ data[page0 + 1] ^ data[page0 + 2]
        }

        /// Whether `data` starts like a Proxmark3 header: a GET_VERSION response
        /// (fixed header 00h, NXP vendor 04h, ISO/IEC 14443-3 protocol type 03h;
        /// NTAG21x / MF0ULx1 datasheets). A plain page dump starts with UID0, which is
        /// 04h for NXP tags, so it does not match.
        static func looksLikeHeader(_ data: Data) -> Bool {
            guard data.count >= headerLength + 4 else { return false }
            let start = data.startIndex
            return data[start] == 0x00 && data[start + 1] == 0x04 && data[start + 7] == 0x03
        }

        let cardType: CardType
        let uid: Data
        let pages: [PageRecord]

        init(data: Data) throws {
            let version: Data?
            let payload: Data

            if Self.hasHeader(data) {
                version = Data(data.prefix(8))
                payload = Data(data.dropFirst(Self.headerLength))
            } else if Self.looksLikeHeader(data) {
                // A header whose page count disagrees with the file (truncated or
                // concatenated dump): importing it as plain pages would shift every page.
                throw NFCError.malformedDump("Proxmark3 header page count does not match the file length")
            } else if data.count.isMultiple(of: 4) {
                version = nil
                payload = data
            } else {
                throw NFCError.malformedDump("Dump length \(data.count) is not a multiple of 4 bytes")
            }

            let pageCount = payload.count / 4
            // Type 2 page addresses are one byte, so at most 256 pages.
            guard pageCount > 0, pageCount <= 256 else {
                throw NFCError.malformedDump("Dump holds \(pageCount) pages; Type 2 tags have 1-256")
            }

            pages = stride(from: 0, to: pageCount, by: 1).map { pageNumber in
                let start = pageNumber * 4
                return PageRecord(
                    number: pageNumber,
                    data: Data(payload[start ..< start + 4])
                )
            }

            if let version, version != Data(repeating: 0x00, count: 8),
               let parsedVersion = try? UltralightVersionResponse(data: version)
            {
                cardType = parsedVersion.cardType
            } else {
                cardType = switch pageCount {
                case 20: .mifareUltralightEV1_MF0UL11
                case 41: .mifareUltralightEV1_MF0UL21
                case 45: .ntag213
                case 48: .mifareUltralightC
                case 135: .ntag215
                case 231: .ntag216
                default: .mifareUltralight
                }
            }

            if let page0 = pages.first?.data, pages.count > 1 {
                var combinedUID = Data(page0.prefix(3))
                combinedUID.append(pages[1].data)
                uid = combinedUID
            } else {
                uid = Data()
            }
        }
    }
}
