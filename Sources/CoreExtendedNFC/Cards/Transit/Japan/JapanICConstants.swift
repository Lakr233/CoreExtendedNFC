import Foundation

/// Constants for Japan FeliCa IC transit cards (Suica, PASMO, ICOCA, etc.).
///
/// ## References
/// - CJRC (Cybernetics Japan Railway Common): system code 0x0003
/// - TRETJapanNFCReader: https://github.com/treastrain/TRETJapanNFCReader
/// - Service code layout: little-endian 2 bytes
public enum JapanICConstants {
    /// CJRC system code. Must be registered in the app's Info.plist
    /// under `com.apple.developer.nfc.readersession.felicasystemcodes`.
    public static let systemCode = Data([0x00, 0x03])

    // MARK: - Service Codes (little-endian)

    /// Balance service (random read-only, 1 block).
    public static let balanceServiceCode = Data([0x8B, 0x00]) // 0x008B

    /// Transaction history service (cyclic read-only, up to 20 blocks).
    public static let historyServiceCode = Data([0x0F, 0x09]) // 0x090F

    /// Maximum transaction history blocks stored by common CJRC cards.
    public static let maxHistoryBlocks = 20

    // MARK: - Balance Block Layout (16 bytes)

    /// Byte offset of the 2-byte LE balance within the 0x008B balance block.
    public static let balanceOffset = 0x0B

    // MARK: - History Block Layout (16 bytes)

    /// Byte 0: terminal/machine type.
    public static let historyMachineType = 0
    /// Byte 1: usage type (ride, charge, purchase, etc.).
    public static let historyUsageType = 1
    /// Byte 2: payment method.
    public static let historyPaymentType = 2
    /// Byte 3: entry/exit flag.
    public static let historyEntryExit = 3
    /// Bytes 4-5: date as packed bits — year(7) month(4) day(5), base year 2000.
    public static let historyDateOffset = 4
    /// Bytes 6-7: entry station code (product sales: purchase time hhhhhmmmmmm; bus terminals: bus line code).
    public static let historyStationEntry = 6
    /// Bytes 8-9: exit station code (bus terminals: bus stop code; ticket machines: unused).
    public static let historyStationExit = 8
    /// Bytes 0x0A-0x0B: balance after transaction (2 bytes LE).
    public static let historyBalanceOffset = 0x0A
    /// Byte 0x0F: region code.
    public static let historyRegionCode = 0x0F

    // MARK: - Console / Process Type Classification (Metrodroid SuicaUtil / SuicaTrip)

    /// Masks off byte 1 bit 7, which flags a variant of the base process rather than a single
    /// meaning: cash for 0xC6/0xCB (merchandise purchase/admission), third-party for 0x84/0x85
    /// (payment/admission) (Metrodroid SuicaUtil.getProcessTypeName).
    public static let processTypeMask: UInt8 = 0x7F

    /// Process types (byte 1 & 0x7F) that add value: charge, auto-charge at entry/exit,
    /// bus deposit, bonus charge, register deposit.
    public static let topupProcessTypes: Set<UInt8> = [0x02, 0x14, 0x15, 0x1F, 0x48, 0x49]

    /// Process type 0x02 (charge): the record carries no station codes.
    public static let chargeProcessType: UInt8 = 0x02

    /// Process types (byte 1 & 0x7F) for merchandise purchase, cancel, and admission.
    public static let purchaseProcessTypes: Set<UInt8> = [0x46, 0x4A, 0x4B]

    /// Console types (byte 0) of product-sale terminals: 0xC7 POS, 0xC8 vending machine.
    /// Their bytes 6-7 hold the purchase time (hour 5 bits, minute 6 bits) instead of stations.
    public static let productSaleConsoleTypes: Set<UInt8> = [0xC7, 0xC8]

    /// Console type (byte 0) of bus terminals. Bytes 6-7 hold the bus line code and bytes 8-9
    /// the bus stop code instead of rail stations (Metrodroid SuicaTrip.parse).
    public static let busConsoleType: UInt8 = 0x05

    /// Console types (byte 0) of ticket machines, fare adjusters, and similar station terminals.
    /// Their records carry only a station (bytes 6-7), with no exit station (Metrodroid SuicaTrip.isTVM).
    public static let ticketMachineConsoleTypes: Set<UInt8> = [0x03, 0x07, 0x08, 0x12, 0x13, 0x14, 0x15]
}
