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

    /// Describe a Type 2 memory layout. Use ``forType(_:)`` for the NXP products
    /// this library knows; this initializer is for other layouts and tests.
    public init(
        totalPages: UInt8,
        userDataStart: UInt8,
        userDataEnd: UInt8,
        configStart: UInt8?,
        dynamicLockStart: UInt8?
    ) {
        self.totalPages = totalPages
        self.userDataStart = userDataStart
        self.userDataEnd = userDataEnd
        self.configStart = configStart
        self.dynamicLockStart = dynamicLockStart
    }

    /// Whether `page` lies in the user data area. Every other page is a
    /// manufacturer, lock, OTP, configuration, password or key page.
    ///
    /// Returns `false` for every page when the map's user data range is empty
    /// (`userDataStart > userDataEnd`).
    public func isUserDataPage(_ page: UInt8) -> Bool {
        userDataStart <= userDataEnd && page >= userDataStart && page <= userDataEnd
    }

    /// Number of user data bytes (4 bytes per page, inclusive range).
    ///
    /// Computed in `Int`, so a full 0...255 range gives 1024; an empty range
    /// (`userDataStart > userDataEnd`) gives 0.
    public var userDataByteCount: Int {
        guard userDataStart <= userDataEnd else { return 0 }
        return (Int(userDataEnd) - Int(userDataStart) + 1) * 4
    }

    /// Whether the map describes a usable Type 2 layout: the user data area
    /// starts at or after page 4 (after the UID, lock and OTP pages), is not
    /// empty, and ends inside the tag; the configuration and dynamic lock
    /// pages, when present, are inside the tag too.
    public var isValid: Bool {
        guard userDataStart >= 4, userDataStart <= userDataEnd, userDataEnd < totalPages else {
            return false
        }
        if let configStart, configStart >= totalPages { return false }
        if let dynamicLockStart, dynamicLockStart >= totalPages { return false }
        return true
    }

    /// Throw ``NFCError/invalidParameter(_:)`` unless ``isValid``.
    ///
    /// Write and restore paths call this before using a caller-supplied map,
    /// so a malformed map is refused instead of misclassifying pages.
    public func validate() throws {
        guard isValid else {
            throw NFCError.invalidParameter(
                "Invalid Ultralight memory map: user data \(userDataStart)...\(userDataEnd), "
                    + "\(totalPages) pages, config \(configStart.map(String.init) ?? "none"), "
                    + "dynamic lock \(dynamicLockStart.map(String.init) ?? "none")"
            )
        }
    }

    /// Build memory map for a specific card type.
    public static func forType(_ type: CardType) -> UltralightMemoryMap {
        switch type {
        case .mifareUltralight:
            UltralightMemoryMap(
                totalPages: 16,
                userDataStart: 4,
                userDataEnd: 15,
                configStart: nil,
                dynamicLockStart: nil
            )
        case .mifareUltralightC:
            UltralightMemoryMap(
                totalPages: 48,
                userDataStart: 4,
                userDataEnd: 39,
                configStart: 42,
                dynamicLockStart: 40
            )
        case .mifareUltralightEV1_MF0UL11:
            UltralightMemoryMap(
                totalPages: 20,
                userDataStart: 4,
                userDataEnd: 15,
                configStart: 16,
                dynamicLockStart: nil
            )
        case .mifareUltralightEV1_MF0UL21:
            UltralightMemoryMap(
                totalPages: 41,
                userDataStart: 4,
                userDataEnd: 35,
                configStart: 37,
                dynamicLockStart: 36
            )
        case .ntag210:
            // NTAG210: user 04h-0Fh, CFG0 10h, CFG1 11h, PWD 12h, PACK 13h.
            UltralightMemoryMap(
                totalPages: 20,
                userDataStart: 4,
                userDataEnd: 15,
                configStart: 16,
                dynamicLockStart: nil
            )
        case .ntag212:
            // NTAG212: user 04h-23h, dynamic lock 24h, CFG0 25h, CFG1 26h, PWD 27h, PACK 28h.
            UltralightMemoryMap(
                totalPages: 41,
                userDataStart: 4,
                userDataEnd: 35,
                configStart: 37,
                dynamicLockStart: 36
            )
        case .ntag213:
            UltralightMemoryMap(
                totalPages: 45,
                userDataStart: 4,
                userDataEnd: 39,
                configStart: 41,
                dynamicLockStart: 40
            )
        case .ntag215:
            UltralightMemoryMap(
                totalPages: 135,
                userDataStart: 4,
                userDataEnd: 129,
                configStart: 131,
                dynamicLockStart: 130
            )
        case .ntag216:
            UltralightMemoryMap(
                totalPages: 231,
                userDataStart: 4,
                userDataEnd: 225,
                configStart: 227,
                dynamicLockStart: 226
            )
        default:
            UltralightMemoryMap(
                totalPages: 16,
                userDataStart: 4,
                userDataEnd: 15,
                configStart: nil,
                dynamicLockStart: nil
            )
        }
    }
}
