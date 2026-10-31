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
    /// Recent journey tap records (newest first), kept apart from ``transactions``.
    ///
    /// A tap record tells where, when and how the card was used, through ``TransitTransaction/event``,
    /// ``TransitTransaction/mode`` and the station fields. Fares and balance changes stay in
    /// ``transactions``, so tap records must not be added to them.
    public let tapEvents: [TransitTransaction]
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
        tapEvents: [TransitTransaction] = [],
        metadata: [String: String] = [:]
    ) {
        self.serialNumber = serialNumber
        self.balanceRaw = balanceRaw
        self.currencyCode = currencyCode
        self.cardName = cardName
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.transactions = transactions
        self.tapEvents = tapEvents
        self.metadata = metadata
    }

    /// Decodes values encoded before ``tapEvents`` existed as having no tap records.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serialNumber = try container.decode(String.self, forKey: .serialNumber)
        balanceRaw = try container.decode(Int.self, forKey: .balanceRaw)
        currencyCode = try container.decode(String.self, forKey: .currencyCode)
        cardName = try container.decode(String.self, forKey: .cardName)
        validFrom = try container.decodeIfPresent(Date.self, forKey: .validFrom)
        validUntil = try container.decodeIfPresent(Date.self, forKey: .validUntil)
        transactions = try container.decode([TransitTransaction].self, forKey: .transactions)
        tapEvents = try container.decodeIfPresent([TransitTransaction].self, forKey: .tapEvents) ?? []
        metadata = try container.decode([String: String].self, forKey: .metadata)
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
    /// Means of transport, if the record identifies it.
    public let mode: TransitMode?
    /// Whether a tap record marks the start or the end of a journey, if the record says so.
    public let event: TransitTapEvent?
    /// Distance travelled in metres, if the record stores it.
    public let distanceMeters: Int?
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
        mode: TransitMode? = nil,
        event: TransitTapEvent? = nil,
        distanceMeters: Int? = nil,
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
        self.mode = mode
        self.event = event
        self.distanceMeters = distanceMeters
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

/// Means of transport of a transit record.
public enum TransitMode: String, Sendable, Codable, CaseIterable {
    case bus
    /// Any rail service: metro, light rail, monorail, commuter and intercity trains.
    case rail
    case tram
    case ferry
    case taxi
}

/// The end of a journey that a tap record marks.
public enum TransitTapEvent: String, Sendable, Codable, CaseIterable {
    /// Boarding, or entering through a gate.
    case tapOn
    /// Alighting, or leaving through a gate.
    case tapOff
}
