import Foundation

/// Constants for Hong Kong Octopus FeliCa transit cards.
///
/// References:
/// - TRETJapanNFCReader OctopusCardItemType / OctopusCardData
/// - Metrodroid OctopusData and FareBot OctopusData for raw value layout
/// - CardBal and Y Mobile IDA checks for live FeliCa balance arithmetic
/// - System code 0x8008, balance service 0x0117
enum OctopusConstants {
    /// Octopus FeliCa system code.
    static let systemCode = Data([0x80, 0x08])

    /// Balance service code 0x0117, encoded little-endian for CoreNFC.
    static let balanceServiceCode = Data([0x17, 0x01])

    /// Raw offset used by CardBal and Y Mobile for live service 0x0117 balance reads.
    static let defaultBalanceRawOffset = 350

    /// Compatibility alias for callers that explicitly name the physical-card offset.
    static let legacyBalanceRawOffset = defaultBalanceRawOffset
}
