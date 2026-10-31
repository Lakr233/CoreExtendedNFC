import Foundation

/// OKICA's public FeliCa services, cross-checked with TRETJapanNFCReader.
public enum OKICAConstants {
    /// Register `8FC1` under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    public static let systemCode = Data([0x8F, 0xC1])

    /// Service 0x028F, little-endian on the wire, newest record first.
    public static let historyServiceCode = Data([0x8F, 0x02])
    public static let maxHistoryBlocks = 20

    /// Bytes 10-11 of a transaction hold the balance after it, little-endian JPY.
    public static let balanceOffset = 10

    public static let yuiRailTrip: UInt32 = 0x1601_0002
    public static let yuiRailTopup: UInt32 = 0x0802_0000
    public static let pointTopups: Set<UInt32> = [0x0848_0000, 0x0848_0400]
    public static let busTopup: UInt32 = 0x051F_0000
    public static let busTrip: UInt32 = 0x050F_000F
    public static let newIssue: UInt32 = 0x0807_0000
    public static let machineTopup: UInt32 = 0x1F1F_0000
}
