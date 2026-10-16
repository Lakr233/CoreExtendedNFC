import Foundation

public extension Data {
    /// Read first 2 bytes as big-endian UInt16.
    var uint16BE: UInt16 {
        guard count >= 2 else { return 0 }
        return UInt16(self[startIndex]) << 8 | UInt16(self[startIndex + 1])
    }

    /// Read first 2 bytes as little-endian UInt16.
    var uint16LE: UInt16 {
        guard count >= 2 else { return 0 }
        return UInt16(self[startIndex + 1]) << 8 | UInt16(self[startIndex])
    }

    /// Read first 4 bytes as big-endian UInt32.
    var uint32BE: UInt32 {
        guard count >= 4 else { return 0 }
        return UInt32(self[startIndex]) << 24
            | UInt32(self[startIndex + 1]) << 16
            | UInt32(self[startIndex + 2]) << 8
            | UInt32(self[startIndex + 3])
    }

    /// Read first 4 bytes as little-endian UInt32.
    var uint32LE: UInt32 {
        guard count >= 4 else { return 0 }
        return UInt32(self[startIndex + 3]) << 24
            | UInt32(self[startIndex + 2]) << 16
            | UInt32(self[startIndex + 1]) << 8
            | UInt32(self[startIndex])
    }
}
