import Foundation

/// Block security status bytes returned by ISO/IEC 15693-3 GET MULTIPLE BLOCK
/// SECURITY STATUS (2Ch) and its extended form (3Ch).
public enum ISO15693BlockSecurityStatus {
    /// Lock_flag: bit b1 of each block security status byte.
    public static let lockFlagMask: UInt8 = 0x01

    /// Whether one block security status byte marks its block as locked.
    ///
    /// Only Lock_flag (b1) is read. ISO/IEC 15693-3 defines b2-b8 as RFU, and some
    /// tags use them for vendor features (ST tags flag password protection there),
    /// which do not mean the block is locked.
    public static func isLocked(_ status: UInt8) -> Bool {
        status & lockFlagMask != 0
    }

    /// Lock flags for a sequence of block security status bytes, in order.
    public static func lockFlags(from statuses: [UInt8]) -> [Bool] {
        statuses.map(isLocked)
    }
}
