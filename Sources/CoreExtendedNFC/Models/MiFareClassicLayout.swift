import Foundation

/// Data model for MIFARE Classic sector/block layout.
/// This is for understanding and parsing dumps only — iOS cannot authenticate Classic cards.
public enum MiFareClassicLayout: Sendable {
    /// Layout specification for a Classic card variant.
    public struct LayoutSpec: Sendable {
        /// Total number of sectors.
        public let sectorCount: Int
        /// Number of blocks in a given sector.
        public let blocksPerSector: @Sendable (Int) -> Int

        public init(sectorCount: Int, blocksPerSector: @escaping @Sendable (Int) -> Int) {
            self.sectorCount = sectorCount
            self.blocksPerSector = blocksPerSector
        }

        /// Total number of blocks.
        public var totalBlocks: Int {
            (0 ..< sectorCount).reduce(0) { $0 + blocksPerSector($1) }
        }
    }

    /// Classic 1K: 16 sectors, 4 blocks each = 64 blocks.
    public static let classic1K = LayoutSpec(sectorCount: 16) { _ in 4 }

    /// Classic 4K: 32 sectors × 4 blocks + 8 sectors × 16 blocks = 256 blocks.
    public static let classic4K = LayoutSpec(sectorCount: 40) { sector in
        sector < 32 ? 4 : 16
    }

    /// Classic Mini: 5 sectors, 4 blocks each = 20 blocks.
    public static let mini = LayoutSpec(sectorCount: 5) { _ in 4 }

    /// Block size in bytes.
    public static let blockSize = 16

    /// A single 16-byte block.
    public struct Block: Sendable {
        public let data: Data

        public init(data: Data) {
            self.data = data
        }
    }

    /// A sector trailer (last block in each sector).
    public struct Trailer: Sendable {
        /// Key A (6 bytes).
        public let keyA: Data
        /// Access bits (4 bytes: 3 access bytes + 1 user byte).
        public let accessBits: Data
        /// Key B (6 bytes).
        public let keyB: Data

        /// Parse a 16-byte trailer block.
        public init?(block: Data) {
            guard block.count == 16 else { return nil }
            keyA = Data(block[block.startIndex ..< block.startIndex + 6])
            accessBits = Data(block[block.startIndex + 6 ..< block.startIndex + 10])
            keyB = Data(block[block.startIndex + 10 ..< block.startIndex + 16])
        }
    }

    /// Default MIFARE key (all 0xFF).
    public static let defaultKey = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    /// Get the first block number for a given sector.
    public static func firstBlockOfSector(_ sector: Int, layout: LayoutSpec) -> Int {
        (0 ..< sector).reduce(0) { $0 + layout.blocksPerSector($1) }
    }

    /// Get the trailer block number for a given sector.
    public static func trailerBlockOfSector(_ sector: Int, layout: LayoutSpec) -> Int {
        firstBlockOfSector(sector, layout: layout) + layout.blocksPerSector(sector) - 1
    }
}
