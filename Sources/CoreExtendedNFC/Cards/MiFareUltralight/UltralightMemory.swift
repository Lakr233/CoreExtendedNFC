import Foundation

/// Memory map for Ultralight/NTAG variants.
public struct UltralightMemoryMap: Sendable, Equatable {
    /// Total number of pages on the tag.
    public let totalPages: UInt8
    /// First user data page (usually 4).
    public let userDataStart: UInt8
    /// Last user data page (inclusive).
    public let userDataEnd: UInt8
    /// First configuration page (EV1/NTAG only).
    public let configStart: UInt8?
    /// First dynamic lock byte page (if applicable).
    public let dynamicLockStart: UInt8?

    /// Whether `page` lies in the user data area. Every other page is a
    /// manufacturer, lock, OTP, configuration, password or key page.
    public func isUserDataPage(_ page: UInt8) -> Bool {
        (userDataStart ... userDataEnd).contains(page)
    }

    /// Number of user data bytes (4 bytes per page, inclusive range).
    var userDataByteCount: Int {
        Int(userDataEnd - userDataStart + 1) * 4
    }

    /// Build memory map for a specific card type.
    public static func forType(_ type: CardType) -> UltralightMemoryMap {
        switch type {
        case .mifareUltralight:
            UltralightMemoryMap(
                totalPages: 16, userDataStart: 4, userDataEnd: 15,
                configStart: nil, dynamicLockStart: nil
            )
        case .mifareUltralightC:
            UltralightMemoryMap(
                totalPages: 48, userDataStart: 4, userDataEnd: 39,
                configStart: 42, dynamicLockStart: 40
            )
        case .mifareUltralightEV1_MF0UL11:
            UltralightMemoryMap(
                totalPages: 20, userDataStart: 4, userDataEnd: 15,
                configStart: 16, dynamicLockStart: nil
            )
        case .mifareUltralightEV1_MF0UL21:
            UltralightMemoryMap(
                totalPages: 41, userDataStart: 4, userDataEnd: 35,
                configStart: 37, dynamicLockStart: 36
            )
        case .ntag210:
            // NTAG210: user 04h-0Fh, CFG0 10h, CFG1 11h, PWD 12h, PACK 13h.
            UltralightMemoryMap(
                totalPages: 20, userDataStart: 4, userDataEnd: 15,
                configStart: 16, dynamicLockStart: nil
            )
        case .ntag212:
            // NTAG212: user 04h-23h, dynamic lock 24h, CFG0 25h, CFG1 26h, PWD 27h, PACK 28h.
            UltralightMemoryMap(
                totalPages: 41, userDataStart: 4, userDataEnd: 35,
                configStart: 37, dynamicLockStart: 36
            )
        case .ntag213:
            UltralightMemoryMap(
                totalPages: 45, userDataStart: 4, userDataEnd: 39,
                configStart: 41, dynamicLockStart: 40
            )
        case .ntag215:
            UltralightMemoryMap(
                totalPages: 135, userDataStart: 4, userDataEnd: 129,
                configStart: 131, dynamicLockStart: 130
            )
        case .ntag216:
            UltralightMemoryMap(
                totalPages: 231, userDataStart: 4, userDataEnd: 225,
                configStart: 227, dynamicLockStart: 226
            )
        default:
            UltralightMemoryMap(
                totalPages: 16, userDataStart: 4, userDataEnd: 15,
                configStart: nil, dynamicLockStart: nil
            )
        }
    }
}
