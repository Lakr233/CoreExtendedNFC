import Foundation

/// Reads balance and transaction history from Rakuten Edy prepaid e-money cards.
///
/// ## Requirements
/// The consumer app must register system code `0xFE00` in its Info.plist
/// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
///
/// ## References
/// - FeliCa common area system code 0xFE00
/// - Edy ID and issue date: service 0x110B, block 0
/// - Balance: service 0x1317, 1 block, bytes 0-3 LE (JPY)
/// - History: service 0x170F, 6 blocks (cyclic, newest first)
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class EdyReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read balance and card information.
    open func readBalance() async throws -> TransitBalance {
        NFCLog.info("Edy balance read start idm=\(NFCLog.payload(transport.identifier))", source: "Edy")
        try await validateCard()
        let balance = try await readRawBalance()
        let cardInformation = try await readCardInformation()
        NFCLog.info("Edy balance read complete balance=\(NFCLog.cardValue(balance)) JPY", source: "Edy")
        return Self.makeBalance(balance: balance, cardInformation: cardInformation, idm: transport.identifier)
    }

    /// Read balance, card information, and transaction history.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("Edy balance/history read start idm=\(NFCLog.payload(transport.identifier))", source: "Edy")
        try await validateCard()
        let balance = try await readRawBalance()
        let cardInformation = try await readCardInformation()
        let transactions = try await readHistory()
        NFCLog.info("Edy balance/history read complete balance=\(NFCLog.cardValue(balance)) JPY transactions=\(transactions.count)", source: "Edy")
        return Self.makeBalance(balance: balance, cardInformation: cardInformation, idm: transport.identifier, transactions: transactions)
    }

    // MARK: - Steps

    /// Throw `tagNotSupported` unless this is a common area tag with the Edy purse service.
    open func validateCard() async throws {
        try await transport.requireCommonAreaService(EdyConstants.balanceServiceCode, source: "Edy")
    }

    open func readRawBalance() async throws -> Int {
        let block = try await transport.readCommonAreaBlock(serviceCode: EdyConstants.balanceServiceCode, source: "Edy")
        let balance = Int(Data(block.dropFirst(EdyConstants.balanceOffset)).uint32LE)
        NFCLog.debug("Edy balance value=\(NFCLog.cardValue(balance))", source: "Edy")
        return balance
    }

    /// Read the card information block. Returns nil when the card refuses it; session loss and
    /// cancellation propagate.
    open func readCardInformation() async throws -> Data? {
        try await transport.readOptionalCommonAreaBlock(serviceCode: EdyConstants.idServiceCode, source: "Edy")
    }

    /// Read history blocks one at a time. A block-level read failure ends the history;
    /// session loss and cancellation propagate to the caller.
    open func readHistory() async throws -> [TransitTransaction] {
        let blocks = try await transport.readCommonAreaBlocks(
            serviceCode: EdyConstants.historyServiceCode,
            maxBlocks: EdyConstants.maxHistoryBlocks,
            source: "Edy"
        )
        let transactions = blocks.compactMap { Self.parseHistoryBlock($0) }
        NFCLog.debug("Edy history read complete blocks=\(blocks.count) transactions=\(transactions.count)", source: "Edy")
        return transactions
    }

    // MARK: - Parsing

    /// Build the result from the balance and the card information block (service 0x110B). The
    /// serial number is the Edy ID printed on the card, or the IDm when the block is unavailable;
    /// the issue date becomes `validFrom`.
    open class func makeBalance(
        balance: Int,
        cardInformation: Data?,
        idm: Data,
        transactions: [TransitTransaction] = []
    ) -> TransitBalance {
        var metadata = ["idm": idm.hexString]
        var serialNumber = idm.hexString
        var issueDate: Date?
        if let cardInformation, cardInformation.count >= EdyConstants.issueDateOffset + 4 {
            let edyID = Data(cardInformation.dropFirst(EdyConstants.idOffset).prefix(EdyConstants.idLength)).hexString
            serialNumber = edyID
            metadata["edyID"] = edyID
            issueDate = parseDateTime(Data(cardInformation.dropFirst(EdyConstants.issueDateOffset).prefix(4)).uint32BE)
        }
        return TransitBalance(
            serialNumber: serialNumber,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "Rakuten Edy",
            validFrom: issueDate,
            transactions: transactions,
            metadata: metadata
        )
    }

    /// Parse a 16-byte history block. Empty (all-zero) slots return nil.
    ///
    /// Process types follow Metrodroid EdyTrip: 0x20 payment, 0x02 charge, 0x04 gift. Other
    /// types are `.unknown` and carry no amount.
    open class func parseHistoryBlock(_ block: Data) -> TransitTransaction? {
        let block = Data(block)
        guard block.count == 16, !block.allSatisfy({ $0 == 0 }) else { return nil }

        let processType = block[EdyConstants.historyTypeOffset]
        let type: TransactionType =
            switch processType {
            case EdyConstants.paymentType: .purchase
            case EdyConstants.chargeType, EdyConstants.giftType: .topup
            default: .unknown
            }
        let amount = Int(Data(block[EdyConstants.historyAmountOffset ..< EdyConstants.historyAmountOffset + 4]).uint32BE)
        let balanceAfter = Int(Data(block[EdyConstants.historyBalanceOffset ..< EdyConstants.historyBalanceOffset + 4]).uint32BE)
        let sequence = Int(Data(block[EdyConstants.historySequenceOffset ..< EdyConstants.historySequenceOffset + 2]).uint16BE)
        let rawDate = Data(block[EdyConstants.historyDateOffset ..< EdyConstants.historyDateOffset + 4]).uint32BE

        return TransitTransaction(
            type: type,
            amount: type == .unknown ? nil : amount,
            balanceAfter: balanceAfter,
            date: parseDateTime(rawDate),
            rawData: block,
            metadata: [
                "processType": String(format: "%02X", processType),
                "sequenceNumber": String(sequence),
            ]
        )
    }

    /// Decode a 32-bit Edy timestamp: days since 2000-01-01 in the upper 15 bits and seconds
    /// since midnight in the lower 17 bits, Japan Standard Time. Zero means no date.
    open class func parseDateTime(_ raw: UInt32) -> Date? {
        guard raw != 0 else { return nil }
        let days = Int(raw >> 17)
        let seconds = Int(raw & 0x1FFFF)
        guard seconds < 86400,
            let epoch = FeliCaCommonAreaConstants.jstDate(year: 2000, month: 1, day: 1)
        else { return nil }
        // JST has no daylight saving time, so days are a fixed 86 400 seconds.
        return epoch.addingTimeInterval(TimeInterval(days * 86400 + seconds))
    }
}
