import Foundation

/// Generic card memory dump container.
public struct MemoryDump: Sendable, Codable, Equatable {
    /// Card info for the dumped card.
    public let cardInfo: CardInfo

    /// Pages (4 bytes each) — for Type 2 tags (Ultralight/NTAG).
    public let pages: [Page]

    /// Blocks — for ISO 15693 or FeliCa.
    public let blocks: [Block]

    /// Files — for Type 4 (DESFire).
    public let files: [FileData]

    /// Raw NDEF payload when the dump flow identified an NDEF-capable card.
    public let ndefMessage: Data?

    /// Family-specific facts that help the UI render a truthful summary.
    public let facts: [Fact]

    /// Normalized high-level capability flags for this dump result.
    public let capabilities: [CardCapability]

    /// A single page (4 bytes, used by Type 2 tags).
    public struct Page: Sendable, Codable, Equatable {
        public let number: UInt8
        public let data: Data

        public init(number: UInt8, data: Data) {
            self.number = number
            self.data = data
        }
    }

    /// A single block (variable size).
    public struct Block: Sendable, Codable, Equatable {
        public let number: Int
        public let data: Data
        public let locked: Bool

        public init(number: Int, data: Data, locked: Bool = false) {
            self.number = number
            self.data = data
            self.locked = locked
        }
    }

    /// A file read from a DESFire application.
    public struct FileData: Sendable, Codable, Equatable {
        public let identifier: Data
        public let data: Data
        public let name: String?

        public init(fileID: UInt8, data: Data, name: String? = nil) {
            identifier = Data([fileID])
            self.data = data
            self.name = name
        }

        public init(identifier: Data, data: Data, name: String? = nil) {
            self.identifier = identifier
            self.data = data
            self.name = name
        }

        public var fileID: UInt8? {
            identifier.count == 1 ? identifier.first : nil
        }

        public var displayIdentifier: String {
            identifier.hexString
        }
    }

    /// A concise piece of family-specific summary metadata.
    public struct Fact: Sendable, Equatable, Codable {
        public let key: String
        public let value: String
        public let monospaced: Bool

        public init(key: String, value: String, monospaced: Bool = false) {
            self.key = key
            self.value = value
            self.monospaced = monospaced
        }
    }

    /// Structured comparison between two dump results.
    public struct DiffSummary: Sendable, Equatable, Codable {
        public let sameCardFamily: Bool
        public let sameUID: Bool
        public let byteDelta: Int
        public let pageChanges: Int
        public let blockChanges: Int
        public let fileChanges: Int
        public let ndefChanged: Bool
        public let factChanges: Int

        public var hasDifferences: Bool {
            byteDelta != 0 || pageChanges != 0 || blockChanges != 0 || fileChanges != 0 || ndefChanged || factChanges != 0
        }
    }

    /// A named export artifact suitable for sharing or saving to disk.
    public struct ExportArtifact: Sendable, Equatable, Codable {
        public let suggestedFilename: String
        public let contentType: String
        public let data: Data

        public init(suggestedFilename: String, contentType: String, data: Data) {
            self.suggestedFilename = suggestedFilename
            self.contentType = contentType
            self.data = data
        }
    }

    public init(
        cardInfo: CardInfo,
        pages: [Page] = [],
        blocks: [Block] = [],
        files: [FileData] = [],
        ndefMessage: Data? = nil,
        facts: [Fact] = [],
        capabilities: [CardCapability] = []
    ) {
        self.cardInfo = cardInfo
        self.pages = pages
        self.blocks = blocks
        self.files = files
        self.ndefMessage = ndefMessage
        self.facts = facts
        self.capabilities = capabilities
    }

    /// Parsed NDEF message when the dump contains NDEF payload bytes.
    public var parsedNDEFMessage: NDEFMessage? {
        guard let ndefMessage else { return nil }
        return try? NDEFMessage(data: ndefMessage)
    }

    /// Shared user-facing and technical summaries for the dump.
    public var summary: DumpSummary {
        let storageSummary = if !pages.isEmpty {
            "\(pages.count) pages"
        } else if !blocks.isEmpty {
            "\(blocks.count) blocks"
        } else if !files.isEmpty {
            "\(files.count) files"
        } else if let ndefMessage {
            "\(ndefMessage.count) NDEF bytes"
        } else {
            "identification only"
        }

        let userSummary = switch cardInfo.type.family {
        case .ntag, .mifareUltralight:
            "Read a Type 2 style memory map with \(storageSummary)."
        case .type4:
            "Read an NFC Forum Type 4 file layout with \(storageSummary)."
        case .felica:
            "Read FeliCa Type 3 blocks with \(storageSummary)."
        case .iso15693:
            "Read ISO 15693 vicinity memory with \(storageSummary)."
        case .mifareDesfire:
            "Enumerated DESFire applications and captured \(storageSummary)."
        case .passport:
            "Passport chips use the dedicated eMRTD workflow instead of generic dump reads."
        default:
            "Captured \(storageSummary) from \(cardInfo.type.description)."
        }

        let technicalSummary = [
            storageSummary,
            "export \(exportBinary().count) bytes",
            parsedNDEFMessage.map { "\($0.records.count) NDEF records" },
        ]
        .compactMap(\.self)
        .joined(separator: " · ")

        let normalizedCapabilities = capabilities.isEmpty ? inferredCapabilities() : capabilities
        return DumpSummary(
            userSummary: userSummary,
            technicalSummary: technicalSummary,
            capabilities: normalizedCapabilities,
            facts: facts
        )
    }

    /// Export as hex string dump.
    public func exportHex() -> String {
        var lines: [String] = []
        lines.append("Card: \(cardInfo.type.description)")
        lines.append("UID: \(cardInfo.uid.hexString)")
        lines.append("Summary: \(summary.technicalSummary)")
        if !summary.capabilities.isEmpty {
            lines.append("Capabilities: \(summary.capabilities.map(\.rawValue).joined(separator: ", "))")
        }
        lines.append("")

        if !pages.isEmpty {
            for page in pages {
                lines.append(String(format: "Page %3d: %@", page.number, page.data.hexDump))
            }
        }
        if !blocks.isEmpty {
            for block in blocks {
                let lock = block.locked ? " [LOCKED]" : ""
                lines.append(String(format: "Block %3d: %@%@", block.number, block.data.hexDump, lock))
            }
        }
        if !files.isEmpty {
            for file in files {
                let label = file.name ?? "File"
                lines.append("\(label) \(file.displayIdentifier) (\(file.data.count) bytes):")
                lines.append(file.data.hexDumpFormatted)
            }
        }
        if let ndefMessage, !ndefMessage.isEmpty {
            lines.append("")
            lines.append("NDEF (\(ndefMessage.count) bytes):")
            lines.append(ndefMessage.hexDumpFormatted)
            if let parsedNDEFMessage {
                lines.append("")
                lines.append("Parsed NDEF:")
                for (index, record) in parsedNDEFMessage.records.enumerated() {
                    lines.append("  [\(index)] \(record.displayType): \(record.displayValue)")
                }
            }
        }

        return lines.joined(separator: "\n")
    }

    /// Export all data as contiguous binary.
    public func exportBinary() -> Data {
        if !pages.isEmpty {
            return pages.sorted(by: { $0.number < $1.number })
                .reduce(into: Data()) { $0.append($1.data) }
        }
        if !blocks.isEmpty {
            return blocks.sorted(by: { $0.number < $1.number })
                .reduce(into: Data()) { $0.append($1.data) }
        }
        if !files.isEmpty {
            return files.sorted(by: { $0.identifier.lexicographicallyPrecedes($1.identifier) })
                .reduce(into: Data()) { $0.append($1.data) }
        }
        if let ndefMessage {
            return ndefMessage
        }
        return Data()
    }

    /// Export a libnfc-style `.mfd` payload for page-based Type 2 dumps.
    public func exportLibNFCMFD() throws -> Data {
        guard !pages.isEmpty else {
            throw NFCError.unsupportedOperation(
                "libnfc MFD export is currently available only for page-based Type 2 style dumps."
            )
        }
        return pages.sorted(by: { $0.number < $1.number })
            .reduce(into: Data()) { $0.append($1.data) }
    }

    /// Export a Flipper Zero `.nfc` snapshot for page-based Type 2 dumps.
    public func exportFlipperNFC() throws -> String {
        let orderedPages = try requirePageBasedDump(
            message: "Flipper Zero export is currently available only for page-based Type 2 style dumps."
        )
        let totalPages = inferredPageTotal(for: orderedPages)
        let pageMap = Self.pageMap(orderedPages)

        let pagesRead = min(orderedPages.last.map { Int($0.number) + 1 } ?? 0, totalPages)

        // Flipper firmware (`iso14443_3a_load`, `mf_ultralight_load`) reads these keys in
        // this order and rejects the file when any of them is missing.
        var lines = [
            "Filetype: Flipper NFC device",
            "Version: 4",
            "Device type: NTAG/Ultralight",
            "UID: \(cardInfo.uid.hexDump)",
            // ISO/IEC 14443-3A: ATQA most-significant byte first (file version > 2); a
            // Type 2 tag answers ATQA 00 44, SAK 00.
            "ATQA: \((cardInfo.atqa.flatMap { $0.count == 2 ? $0 : nil } ?? Data([0x00, 0x44])).hexDump)",
            String(format: "SAK: %02X", cardInfo.sak ?? 0x00),
            "Data format version: 2",
            "NTAG/Ultralight type: \(Self.flipperTypeName(for: cardInfo.type))",
            // READ_SIG is not captured by the dump.
            "Signature: \(Data(repeating: 0x00, count: 32).hexDump)",
            "Mifare version: \((mifareVersionBytes(for: cardInfo.type) ?? Data(repeating: 0x00, count: 8)).hexDump)",
        ]
        for counter in 0 ..< 3 {
            lines.append("Counter \(counter): 0")
            lines.append("Tearing \(counter): 00")
        }
        lines.append("Pages total: \(totalPages)")
        lines.append("Pages read: \(pagesRead)")

        for pageNumber in 0 ..< totalPages {
            let pageData = pageMap[pageNumber] ?? Data(repeating: 0x00, count: 4)
            lines.append("Page \(pageNumber): \(pageData.hexDump)")
        }

        return lines.joined(separator: "\n")
    }

    /// Export a Proxmark3 MFU binary dump for page-based Type 2 dumps.
    public func exportProxmark3MFU() throws -> Data {
        let orderedPages = try requirePageBasedDump(
            message: "Proxmark3 MFU export is currently available only for page-based Type 2 style dumps."
        )
        let totalPages = inferredPageTotal(for: orderedPages)
        let pageMap = Self.pageMap(orderedPages)

        var result = Data(repeating: 0x00, count: 56 + totalPages * 4)

        if let version = mifareVersionBytes(for: cardInfo.type) {
            result.replaceSubrange(0 ..< 8, with: version)
        }
        result[11] = UInt8(truncatingIfNeeded: totalPages - 1)

        for pageNumber in 0 ..< totalPages {
            let pageData = pageMap[pageNumber] ?? Data(repeating: 0x00, count: 4)
            let offset = 56 + pageNumber * 4
            result.replaceSubrange(offset ..< offset + 4, with: pageData)
        }

        return result
    }

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

    /// Export a structured JSON snapshot that is easier to diff or consume outside the app.
    public func exportStructuredJSON(prettyPrinted: Bool = true) throws -> String {
        let encoder = JSONEncoder()
        if prettyPrinted {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        } else {
            encoder.outputFormatting = [.sortedKeys]
        }

        let snapshot = ExportSnapshot(
            cardType: cardInfo.type.description,
            cardFamily: cardInfo.type.family.description,
            uid: cardInfo.uid.hexString,
            userSummary: summary.userSummary,
            technicalSummary: summary.technicalSummary,
            capabilities: summary.capabilities.map(\.rawValue),
            facts: facts.map { .init(key: $0.key, value: $0.value, monospaced: $0.monospaced) },
            pages: pages.map { .init(number: Int($0.number), data: $0.data.hexString) },
            blocks: blocks.map { .init(number: $0.number, data: $0.data.hexString, locked: $0.locked) },
            files: files.map { .init(identifier: $0.displayIdentifier, name: $0.name, data: $0.data.hexString) },
            ndefHex: ndefMessage?.hexString,
            parsedNDEF: parsedNDEFMessage?.records.map {
                .init(type: $0.displayType, value: $0.displayValue)
            }
        )

        let data = try encoder.encode(snapshot)
        guard let string = String(data: data, encoding: .utf8) else {
            throw NFCError.invalidResponse(data)
        }
        return string
    }

    /// Export a stable set of shareable artifacts for external tools or diff workflows.
    public func exportArtifacts() throws -> [ExportArtifact] {
        let baseName = suggestedExportBasename
        var artifacts: [ExportArtifact] = try [
            .init(
                suggestedFilename: "\(baseName).txt",
                contentType: "text/plain",
                data: Data(exportHex().utf8)
            ),
            .init(
                suggestedFilename: "\(baseName).json",
                contentType: "application/json",
                data: Data(exportStructuredJSON().utf8)
            ),
            .init(
                suggestedFilename: "\(baseName).bin",
                contentType: "application/octet-stream",
                data: exportBinary()
            ),
        ]

        if let mfd = try? exportLibNFCMFD() {
            artifacts.append(
                .init(
                    suggestedFilename: "\(baseName).mfd",
                    contentType: "application/octet-stream",
                    data: mfd
                )
            )
        }

        if let flipper = try? exportFlipperNFC() {
            artifacts.append(
                .init(
                    suggestedFilename: "\(baseName).nfc",
                    contentType: "text/plain",
                    data: Data(flipper.utf8)
                )
            )
        }

        if let proxmark = try? exportProxmark3MFU() {
            artifacts.append(
                .init(
                    suggestedFilename: "\(baseName)-proxmark3.bin",
                    contentType: "application/octet-stream",
                    data: proxmark
                )
            )
        }

        return artifacts
    }

    /// Produce a stable diff summary against another dump.
    ///
    /// Entries are matched by key (page number, block number, file identifier, fact key).
    /// Repeated keys never trap: the n-th occurrence of a key is compared with the
    /// n-th occurrence in the other dump.
    public func diffSummary(against other: MemoryDump) -> DiffSummary {
        DiffSummary(
            sameCardFamily: cardInfo.type.family == other.cardInfo.type.family,
            sameUID: cardInfo.uid == other.cardInfo.uid,
            byteDelta: exportBinary().count - other.exportBinary().count,
            pageChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(pages.map { (Int($0.number), $0.data) }),
                rhs: Self.keyedByOccurrence(other.pages.map { (Int($0.number), $0.data) })
            ),
            blockChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(blocks.map { ($0.number, $0.data) }),
                rhs: Self.keyedByOccurrence(other.blocks.map { ($0.number, $0.data) })
            ),
            fileChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(files.map { ($0.identifier, $0.data) }),
                rhs: Self.keyedByOccurrence(other.files.map { ($0.identifier, $0.data) })
            ),
            ndefChanged: ndefMessage != other.ndefMessage,
            factChanges: keyedDifferenceCount(
                lhs: Self.keyedByOccurrence(facts.map { ($0.key, $0.value) }),
                rhs: Self.keyedByOccurrence(other.facts.map { ($0.key, $0.value) })
            )
        )
    }

    private struct OccurrenceKey<Key: Hashable>: Hashable {
        let key: Key
        let occurrence: Int
    }

    private static func keyedByOccurrence<Key: Hashable, Value>(
        _ pairs: [(Key, Value)]
    ) -> [OccurrenceKey<Key>: Value] {
        var seen: [Key: Int] = [:]
        var result: [OccurrenceKey<Key>: Value] = [:]
        for (key, value) in pairs {
            let occurrence = seen[key, default: 0]
            seen[key] = occurrence + 1
            result[OccurrenceKey(key: key, occurrence: occurrence)] = value
        }
        return result
    }

    /// Page number to data. A repeated page number keeps the last occurrence instead of trapping.
    private static func pageMap(_ pages: [Page]) -> [Int: Data] {
        Dictionary(pages.map { (Int($0.number), $0.data) }, uniquingKeysWith: { _, last in last })
    }

    private func keyedDifferenceCount<Key: Hashable, Value: Equatable>(
        lhs: [Key: Value],
        rhs: [Key: Value]
    ) -> Int {
        let keys = Set(lhs.keys).union(rhs.keys)
        return keys.reduce(into: 0) { count, key in
            if lhs[key] != rhs[key] {
                count += 1
            }
        }
    }

    private struct ExportSnapshot: Encodable {
        struct ExportFact: Encodable {
            let key: String
            let value: String
            let monospaced: Bool
        }

        struct ExportPage: Encodable {
            let number: Int
            let data: String
        }

        struct ExportBlock: Encodable {
            let number: Int
            let data: String
            let locked: Bool
        }

        struct ExportFile: Encodable {
            let identifier: String
            let name: String?
            let data: String
        }

        struct ExportNDEFRecord: Encodable {
            let type: String
            let value: String
        }

        let cardType: String
        let cardFamily: String
        let uid: String
        let userSummary: String
        let technicalSummary: String
        let capabilities: [String]
        let facts: [ExportFact]
        let pages: [ExportPage]
        let blocks: [ExportBlock]
        let files: [ExportFile]
        let ndefHex: String?
        let parsedNDEF: [ExportNDEFRecord]?
    }

    private var suggestedExportBasename: String {
        let rawPrefix = cardInfo.type.family.description.lowercased()
        let sanitizedPrefix = rawPrefix.map { character -> Character in
            switch character {
            case "a" ... "z", "0" ... "9":
                character
            default:
                "-"
            }
        }
        .reduce(into: "") { result, character in
            if character == "-", result.last == "-" {
                return
            }
            result.append(character)
        }
        .trimmingCharacters(in: CharacterSet(charactersIn: "-"))

        return "\(sanitizedPrefix)-\(cardInfo.uid.hexString.lowercased())"
    }

    private func requirePageBasedDump(message: String) throws -> [Page] {
        guard !pages.isEmpty else {
            throw NFCError.unsupportedOperation(message)
        }
        return pages.sorted(by: { $0.number < $1.number })
    }

    /// Number of pages to export: the memory map size for known Type 2 layouts, but never
    /// fewer than the pages actually present, so no captured page is dropped.
    private func inferredPageTotal(for orderedPages: [Page]) -> Int {
        let pagesPresent = orderedPages.last.map { Int($0.number) + 1 } ?? 0
        switch cardInfo.type.family {
        case .ntag, .mifareUltralight:
            return max(Int(UltralightMemoryMap.forType(cardInfo.type).totalPages), pagesPresent)
        default:
            return max(pagesPresent, 1)
        }
    }

    /// Flipper's `NTAG/Ultralight type` names (`mf_ultralight_features[].device_name`).
    /// Flipper has no NTAG210/212 entry and files them, by GET_VERSION storage size,
    /// as Ultralight 11 / 21, which share their page counts.
    static func flipperTypeName(for type: CardType) -> String {
        switch type {
        case .mifareUltralightC: "Mifare Ultralight C"
        case .mifareUltralightEV1_MF0UL11, .ntag210: "Mifare Ultralight 11"
        case .mifareUltralightEV1_MF0UL21, .ntag212: "Mifare Ultralight 21"
        case .ntag213: "NTAG213"
        case .ntag215: "NTAG215"
        case .ntag216: "NTAG216"
        default: "Mifare Ultralight"
        }
    }

    /// Inverse of ``flipperTypeName(for:)`` for the names this library can model.
    static func cardType(forFlipperTypeName name: String) -> CardType? {
        switch name {
        case "Mifare Ultralight": .mifareUltralight
        case "Mifare Ultralight C": .mifareUltralightC
        case "Mifare Ultralight 11": .mifareUltralightEV1_MF0UL11
        case "Mifare Ultralight 21": .mifareUltralightEV1_MF0UL21
        case "NTAG213": .ntag213
        case "NTAG215": .ntag215
        case "NTAG216": .ntag216
        default: nil
        }
    }

    /// GET_VERSION responses from the NXP datasheets (NTAG210/212 §10.1, NTAG213/215/216
    /// §10.1, MF0ULx1 §8.1): fixed header, vendor, type, subtype, major, minor, storage
    /// size, protocol type.
    private func mifareVersionBytes(for type: CardType) -> Data? {
        switch type {
        case .ntag210:
            Data([0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0B, 0x03])
        case .ntag212:
            Data([0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0E, 0x03])
        case .ntag213:
            Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03])
        case .ntag215:
            Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03])
        case .ntag216:
            Data([0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03])
        case .mifareUltralightEV1_MF0UL11:
            Data([0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03])
        case .mifareUltralightEV1_MF0UL21:
            Data([0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03])
        default:
            nil
        }
    }

    /// A page parsed from an imported file, before its number is range-checked.
    private struct ImportedPageRecord {
        let number: Int
        let data: Data

        func validatedPage() throws -> Page {
            guard let pageNumber = UInt8(exactly: number) else {
                throw NFCError.invalidResponse(Data("Page \(number)".utf8))
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
                        throw NFCError.invalidResponse(Data(value.utf8))
                    }
                    // Type 2 page addresses are one byte (0...255), and each page appears once.
                    guard UInt8(exactly: pageNumber) != nil,
                          !pageRecords.contains(where: { $0.number == pageNumber })
                    else {
                        throw NFCError.invalidResponse(Data(line.utf8))
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
                throw NFCError.unsupportedOperation("Unsupported Flipper NFC file format")
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

        /// Whether `data` is a headered Proxmark3 dump: the header's last-page index must
        /// agree with the number of 4-byte pages that follow it.
        static func hasHeader(_ data: Data) -> Bool {
            guard data.count >= headerLength + 4,
                  (data.count - headerLength).isMultiple(of: 4)
            else { return false }
            let lastPageIndex = Int(data[data.startIndex + lastPageIndexOffset])
            return lastPageIndex + 1 == (data.count - headerLength) / 4
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
                throw NFCError.invalidResponse(Data(data.prefix(Self.headerLength)))
            } else if data.count.isMultiple(of: 4) {
                version = nil
                payload = data
            } else {
                throw NFCError.invalidResponse(data)
            }

            let pageCount = payload.count / 4
            // Type 2 page addresses are one byte, so at most 256 pages.
            guard pageCount > 0, pageCount <= 256 else {
                throw NFCError.invalidResponse(data)
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

    private func inferredCapabilities() -> [CardCapability] {
        switch cardInfo.type.family {
        case .mifareClassic, .mifarePlus, .jewelTopaz:
            return [.identificationOnly]
        case .mifareDesfire:
            return files.isEmpty ? [.authenticationRequired, .partiallyReadable] : [.partiallyReadable]
        case .type4:
            if let writeAccess = facts.first(where: { $0.key == "Write Access" })?.value,
               writeAccess == "Writable"
            {
                return [.readable, .writable]
            }
            return [.readable]
        case .felica:
            if let readWrite = facts.first(where: { $0.key == "Read / Write" })?.value,
               readWrite == "Read-write"
            {
                return [.readable, .writable]
            }
            return [.readable]
        default:
            return cardInfo.type.isOperableOnIOS ? [.readable] : [.identificationOnly]
        }
    }
}
