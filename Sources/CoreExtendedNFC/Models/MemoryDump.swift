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
