import Foundation

/// FeliCa memory model: services and blocks.
public enum FeliCaMemory {
    /// FeliCa block size is always 16 bytes.
    public static let blockSize = 16

    /// Service types.
    public enum ServiceType: Sendable {
        case randomReadOnly
        case randomReadWrite
        case cyclicReadOnly
        case cyclicReadWrite
        case purseDirectAccess
        case purseCashback

        /// 6-bit service attribute (low bits of the service code) for the
        /// key-less variant of each service type.
        ///
        /// Sony FeliCa Card User's Manual, service attribute table
        /// (bit 0 = 1 means no key required):
        /// random R/W 08h/09h, random RO 0Ah/0Bh, cyclic R/W 0Ch/0Dh,
        /// cyclic RO 0Eh/0Fh, purse direct 10h/11h, purse cashback/decrement 12h/13h,
        /// purse decrement 14h/15h, purse read-only 16h/17h. Only the first two
        /// purse types are modelled here.
        public var accessBits: UInt8 {
            switch self {
            case .randomReadOnly: 0x0B
            case .randomReadWrite: 0x09
            case .cyclicReadOnly: 0x0F
            case .cyclicReadWrite: 0x0D
            case .purseDirectAccess: 0x11
            case .purseCashback: 0x13
            }
        }
    }
}
