import Foundation

/// ISO 15693 memory model.
public enum ISO15693Memory {
    /// Common block sizes for ISO 15693 tags.
    public static let blockSize4 = 4 // ICODE SLIX
    public static let blockSize8 = 8 // Some ISO 15693 variants use 8-byte blocks

    /// Common tag configurations using datasheet block counts.
    public struct TagConfig: Sendable {
        public let blockSize: Int
        public let blockCount: Int

        public init(blockSize: Int, blockCount: Int) {
            self.blockSize = blockSize
            self.blockCount = blockCount
        }

        public var totalBytes: Int {
            blockSize * blockCount
        }
    }

    /// ICODE SLIX: 32 blocks × 4 bytes = 128 bytes.
    public static let icodeSLIX = TagConfig(blockSize: 4, blockCount: 32)
    /// ICODE SLIX2: 80 blocks × 4 bytes = 320 bytes.
    public static let icodeSLIX2 = TagConfig(blockSize: 4, blockCount: 80)
    /// ST25TV512: 16 blocks × 4 bytes = 64 bytes.
    public static let st25tv512 = TagConfig(blockSize: 4, blockCount: 16)
    /// ST25TV02K: 64 blocks × 4 bytes = 256 bytes.
    public static let st25tv02K = TagConfig(blockSize: 4, blockCount: 64)
}
