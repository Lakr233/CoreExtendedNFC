import Foundation

/// Constants for Hong Kong Octopus FeliCa transit cards.
///
/// References:
/// - TRETJapanNFCReader OctopusCardItemType / OctopusCardData
/// - System code 0x8008, balance service 0x0117
enum OctopusConstants {
    /// Octopus FeliCa system code.
    static let systemCode = Data([0x80, 0x08])

    /// Balance service code 0x0117, encoded little-endian for CoreNFC.
    static let balanceServiceCode = Data([0x17, 0x01])

    /// Current Octopus raw offset used by CardBal and older public writeups.
    static let currentBalanceRawOffset = 350

    /// Historical raw offset for very old Octopus records.
    static let legacyBalanceRawOffset = 35
}
