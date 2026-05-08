import Foundation

/// Unified transit card balance result.
public struct TransitBalance: Sendable, Equatable, Codable {
    /// Card identifier / serial number (hex string).
    public let serialNumber: String
    /// Current balance in the card currency's stored unit, such as yen, won, dollars, cents, or fen.
    public let balanceRaw: Int
    /// ISO 4217 currency code, such as "JPY", "KRW", "CNY", "HKD", "SGD", "NZD", or "TWD".
    public let currencyCode: String
    /// Card type name for display (e.g. "Suica", "T-Money").
    public let cardName: String
    /// Optional validity period start.
    public let validFrom: Date?
    /// Optional validity period end.
    public let validUntil: Date?
    /// Recent transaction history (newest first).
    public let transactions: [TransitTransaction]

    public init(
        serialNumber: String,
        balanceRaw: Int,
        currencyCode: String,
        cardName: String,
        validFrom: Date? = nil,
        validUntil: Date? = nil,
        transactions: [TransitTransaction] = [],
    ) {
        self.serialNumber = serialNumber
        self.balanceRaw = balanceRaw
        self.currencyCode = currencyCode
        self.cardName = cardName
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.transactions = transactions
    }

    /// Human-readable formatted balance.
    public var formattedBalance: String {
        switch currencyCode {
        case "JPY":
            return "¥\(balanceRaw)"
        case "KRW":
            return "₩\(balanceRaw)"
        case "CNY":
            let yuan = Double(balanceRaw) / 100.0
            return String(format: "¥%.2f", yuan)
        case "TWD":
            return "NT$\(balanceRaw)"
        case "HKD":
            let dollars = Double(balanceRaw) / 100.0
            return String(format: "HK$%.2f", dollars)
        case "SGD":
            let dollars = Double(balanceRaw) / 100.0
            return String(format: "S$%.2f", dollars)
        case "NZD":
            let dollars = Double(balanceRaw) / 100.0
            return String(format: "NZ$%.2f", dollars)
        default:
            return "\(balanceRaw) \(currencyCode)"
        }
    }
}

/// A single transit card transaction record.
public struct TransitTransaction: Sendable, Equatable, Codable {
    /// Transaction type.
    public let type: TransactionType
    /// Amount in smallest currency unit.
    public let amount: Int
    /// Balance after this transaction.
    public let balanceAfter: Int
    /// Transaction date/time, if available.
    public let date: Date?
    /// Entry station code (hex string), if available.
    public let entryStation: String?
    /// Exit station code (hex string), if available.
    public let exitStation: String?
    /// Source record number, if the card exposes cyclic record slots.
    public let recordNumber: Int?
    /// Raw record payload, if retained by the reader.
    public let rawData: Data?
    /// Reader-specific decoded fields.
    public let metadata: [String: String]

    public init(
        type: TransactionType,
        amount: Int,
        balanceAfter: Int,
        date: Date? = nil,
        entryStation: String? = nil,
        exitStation: String? = nil,
        recordNumber: Int? = nil,
        rawData: Data? = nil,
        metadata: [String: String] = [:],
    ) {
        self.type = type
        self.amount = amount
        self.balanceAfter = balanceAfter
        self.date = date
        self.entryStation = entryStation
        self.exitStation = exitStation
        self.recordNumber = recordNumber
        self.rawData = rawData
        self.metadata = metadata
    }
}

/// Transit transaction type.
public enum TransactionType: String, Sendable, Codable {
    case trip
    case topup
    case purchase
    case unknown
}
