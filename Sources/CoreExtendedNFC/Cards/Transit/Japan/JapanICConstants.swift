import Foundation

/// Constants for Japan FeliCa IC transit cards (Suica, PASMO, ICOCA, etc.).
///
/// ## References
/// - CJRC (Cybernetics Japan Railway Common): system code 0x0003
/// - TRETJapanNFCReader: https://github.com/treastrain/TRETJapanNFCReader
/// - Service code layout: little-endian 2 bytes
enum JapanICConstants {
    /// CJRC system code. Must be registered in the app's Info.plist
    /// under `com.apple.developer.nfc.readersession.felicasystemcodes`.
    static let systemCode = Data([0x00, 0x03])

    // MARK: - Service Codes (little-endian)

    /// Balance service (random read-only, 1 block).
    static let balanceServiceCode = Data([0x8B, 0x00]) // 0x008B

    /// Transaction history service (cyclic read-only, up to 20 blocks).
    static let historyServiceCode = Data([0x0F, 0x09]) // 0x090F

    /// Maximum history blocks to read per session (safe limit).
    static let maxHistoryBlocks = 10

    // MARK: - Balance Block Layout (16 bytes)

    /// Byte offset of the 2-byte LE balance within a balance block.
    static let balanceOffset = 0x0A

    // MARK: - History Block Layout (16 bytes)

    /// Byte 0: terminal/machine type.
    static let historyMachineType = 0
    /// Byte 1: usage type (ride, charge, purchase, etc.).
    static let historyUsageType = 1
    /// Byte 2: payment method.
    static let historyPaymentType = 2
    /// Byte 3: entry/exit flag.
    static let historyEntryExit = 3
    /// Bytes 4-5: date as packed bits — year(7) month(4) day(5), base year 2000.
    static let historyDateOffset = 4
    /// Bytes 6-7: entry station code.
    static let historyStationEntry = 6
    /// Bytes 8-9: exit station code.
    static let historyStationExit = 8
    /// Bytes 0x0A-0x0B: balance after transaction (2 bytes LE).
    static let historyBalanceOffset = 0x0A
    /// Byte 0x0F: region code.
    static let historyRegionCode = 0x0F

    // MARK: - Usage Type Classification

    /// Usage types that represent top-up / charge operations.
    static let topupUsageTypes: Set<UInt8> = [0x02, 0x3F]

    /// Usage types that represent product purchases (vending, store).
    static let purchaseUsageTypes: Set<UInt8> = [0x46, 0x49, 0xC6, 0xC7]
}
