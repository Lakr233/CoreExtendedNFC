import Foundation

/// FeliCa frame assembly utilities.
/// FeliCa frames: [Length, Command, IDm(8), Payload...]
public enum FeliCaFrame {
    /// FeliCa command codes (JIS X 6319-4).
    public static let POLLING: UInt8 = 0x00
    public static let REQUEST_SERVICE: UInt8 = 0x02
    public static let REQUEST_RESPONSE: UInt8 = 0x04
    public static let CHECK: UInt8 = 0x06 // Read Without Encryption
    public static let UPDATE: UInt8 = 0x08 // Write Without Encryption

    /// Build a block list element for FeliCa CHECK/UPDATE.
    /// - 2-byte element: `[0x80, blockNumber]` for block numbers below 0x100.
    /// - 3-byte element: `[serviceIndex, blockNumber low, blockNumber high]`.
    ///   The block number is little-endian, like every multi-byte FeliCa field
    ///   (Sony FeliCa Card User's Manual, "Block List Element").
    public static func blockListElement(blockNumber: UInt16, serviceIndex: UInt8 = 0) -> Data {
        let encodedServiceIndex = serviceIndex & 0x0F
        if blockNumber <= 0xFF {
            // 2-byte format
            return Data([0x80 | encodedServiceIndex, UInt8(blockNumber & 0xFF)])
        } else {
            // 3-byte format
            return Data([
                encodedServiceIndex,
                UInt8(blockNumber & 0xFF),
                UInt8((blockNumber >> 8) & 0xFF),
            ])
        }
    }
}
