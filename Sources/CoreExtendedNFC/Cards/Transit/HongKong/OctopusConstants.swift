import Foundation

/// Constants for Hong Kong Octopus FeliCa transit cards.
///
/// References:
/// - TRETJapanNFCReader OctopusCardItemType / OctopusCardData
/// - Metrodroid OctopusData and FareBot OctopusData for raw value layout
/// - CardBal and Y Mobile IDA checks for live FeliCa balance arithmetic
/// - System code 0x8008, balance service 0x0117
public enum OctopusConstants {
    /// Octopus FeliCa system code.
    public static let systemCode = Data([0x80, 0x08])

    /// Balance service code 0x0117, encoded little-endian for CoreNFC.
    public static let balanceServiceCode = Data([0x17, 0x01])

    /// Raw offset used by CardBal and Y Mobile for live service 0x0117 balance reads.
    ///
    /// Sources disagree: Metrodroid and FareBot `OctopusData` use 350 for scans before
    /// 2017-10-01 00:00 HKT and 500 for scans after that date (the negative-balance limit
    /// change), while TRETJapanNFCReader uses 350. This default has not been confirmed
    /// against a current physical card. Pass `balanceOffset` to `OctopusReader` to override it.
    public static let defaultBalanceRawOffset = 350

    /// Compatibility alias for callers that explicitly name the physical-card offset.
    public static let legacyBalanceRawOffset = defaultBalanceRawOffset
}
