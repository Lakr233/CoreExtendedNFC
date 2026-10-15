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
    /// Reader-specific decoded fields.
    public let metadata: [String: String]

    public init(
        serialNumber: String,
        balanceRaw: Int,
        currencyCode: String,
        cardName: String,
        validFrom: Date? = nil,
        validUntil: Date? = nil,
        transactions: [TransitTransaction] = [],
        metadata: [String: String] = [:]
    ) {
        self.serialNumber = serialNumber
        self.balanceRaw = balanceRaw
        self.currencyCode = currencyCode
        self.cardName = cardName
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.transactions = transactions
        self.metadata = metadata
    }

    /// Human-readable formatted balance.
    public var formattedBalance: String {
        let major = Double(balanceRaw) / 100.0
        switch currencyCode {
        case "JPY":
            return "¥\(balanceRaw)"
        case "KRW":
            return "₩\(balanceRaw)"
        case "CNY":
            return String(format: "¥%.2f", major)
        case "TWD":
            return "NT$\(balanceRaw)"
        case "HKD":
            return String(format: "HK$%.2f", major)
        case "SGD":
            return String(format: "S$%.2f", major)
        case "NZD":
            return String(format: "NZ$%.2f", major)
        default:
            return "\(balanceRaw) \(currencyCode)"
        }
    }
}

/// A single transit card transaction record.
public struct TransitTransaction: Sendable, Equatable, Codable {
    /// Transaction type.
    public let type: TransactionType
    /// Unsigned magnitude of the transaction in the card currency's stored unit, or nil when no
    /// monetary amount is exposed or understood.
    ///
    /// Every reader reports a non-negative value; the direction comes from ``type``
    /// (`.topup` adds to the balance, `.trip` and `.purchase` deduct from it).
    public let amount: Int?
    /// Balance after this transaction, or nil when the source record does not expose it.
    public let balanceAfter: Int?
    /// Transaction date/time, if available.
    public let date: Date?
    /// Entry station code, if available. Encoding depends on the reader.
    public let entryStation: String?
    /// Exit station code, if available. Encoding depends on the reader.
    public let exitStation: String?
    /// Source record number, if the card exposes cyclic record slots.
    public let recordNumber: Int?
    /// Raw record payload, if retained by the reader.
    public let rawData: Data?
    /// Reader-specific decoded fields.
    public let metadata: [String: String]

    public init(
        type: TransactionType,
        amount: Int? = nil,
        balanceAfter: Int? = nil,
        date: Date? = nil,
        entryStation: String? = nil,
        exitStation: String? = nil,
        recordNumber: Int? = nil,
        rawData: Data? = nil,
        metadata: [String: String] = [:]
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
