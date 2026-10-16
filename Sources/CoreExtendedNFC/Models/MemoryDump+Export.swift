import Foundation

extension MemoryDump {
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
        let orderedPages = try requirePageBasedDump(
            message: "libnfc MFD export is currently available only for page-based Type 2 style dumps."
        )
        return orderedPages.reduce(into: Data()) { $0.append($1.data) }
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
            throw NFCError.malformedDump("JSON export is not valid UTF-8")
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

    /// Page number to data. A repeated page number keeps the last occurrence instead of trapping.
    public static func pageMap(_ pages: [Page]) -> [Int: Data] {
        Dictionary(pages.map { (Int($0.number), $0.data) }, uniquingKeysWith: { _, last in last })
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

    /// File basename used by ``exportArtifacts()``: `<family>-<uid hex>`.
    public var suggestedExportBasename: String {
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

    /// Pages sorted by number, for the page-based export formats.
    ///
    /// `Page` is `Codable`, so a decoded or hand-built dump can carry pages of any length.
    /// The libnfc, Flipper and Proxmark3 formats all store exactly 4 bytes per Type 2 page;
    /// a page of another length would shift every later page or drop bytes, so it is
    /// rejected instead of silently padded or truncated.
    public func requirePageBasedDump(message: String) throws -> [Page] {
        guard !pages.isEmpty else {
            throw NFCError.unsupportedOperation(message)
        }
        if let malformed = pages.first(where: { $0.data.count != 4 }) {
            throw NFCError.malformedDump("Page \(malformed.number) has \(malformed.data.count) bytes; Type 2 pages have 4")
        }
        return pages.sorted(by: { $0.number < $1.number })
    }

    /// Number of pages to export: the memory map size for known Type 2 layouts, but never
    /// fewer than the pages actually present, so no captured page is dropped.
    public func inferredPageTotal(for orderedPages: [Page]) -> Int {
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
    public static func flipperTypeName(for type: CardType) -> String {
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
    public static func cardType(forFlipperTypeName name: String) -> CardType? {
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
    public func mifareVersionBytes(for type: CardType) -> Data? {
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
}
