import Foundation

/// Reads balance and transaction history from Seven & i nanaco prepaid e-money cards.
///
/// ## Requirements
/// The consumer app must register system code `0xFE00` in its Info.plist
/// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
///
/// ## References
/// - FeliCa common area system code 0xFE00
/// - Balance: service 0x5597, 1 block, bytes 0-3 LE (JPY)
/// - nanaco number: service 0x558B; card dates: service 0x55CB; points: service 0x560B block 1
/// - History: service 0x564F, 5 blocks (cyclic, newest first)
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class NanacoReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read balance, nanaco number, card dates, and points.
    open func readBalance() async throws -> TransitBalance {
        NFCLog.info("nanaco balance read start idm=\(NFCLog.payload(transport.identifier))", source: "nanaco")
        try await validateCard()
        let balance = try await readRawBalance()
        let blocks = try await readCardBlocks()
        NFCLog.info("nanaco balance read complete balance=\(NFCLog.cardValue(balance)) JPY", source: "nanaco")
        return Self.makeBalance(balance: balance, numberBlock: blocks.number, infoBlock: blocks.info, pointsBlock: blocks.points, idm: transport.identifier)
    }

    /// Read balance, nanaco number, card dates, points, and transaction history.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("nanaco balance/history read start idm=\(NFCLog.payload(transport.identifier))", source: "nanaco")
        try await validateCard()
        let balance = try await readRawBalance()
        let blocks = try await readCardBlocks()
        let transactions = try await readHistory()
        NFCLog.info("nanaco balance/history read complete balance=\(NFCLog.cardValue(balance)) JPY transactions=\(transactions.count)", source: "nanaco")
        return Self.makeBalance(
            balance: balance,
            numberBlock: blocks.number,
            infoBlock: blocks.info,
            pointsBlock: blocks.points,
            idm: transport.identifier,
            transactions: transactions
        )
    }

    // MARK: - Steps

    /// Throw `tagNotSupported` unless this is a common area tag with the nanaco purse service.
    open func validateCard() async throws {
        try await transport.requireCommonAreaService(NanacoConstants.balanceServiceCode, source: "nanaco")
    }

    open func readRawBalance() async throws -> Int {
        let block = try await transport.readCommonAreaBlock(serviceCode: NanacoConstants.balanceServiceCode, source: "nanaco")
        let balance = Int(Data(block.dropFirst(NanacoConstants.balanceOffset)).uint32LE)
        NFCLog.debug("nanaco balance value=\(NFCLog.cardValue(balance))", source: "nanaco")
        return balance
    }

    /// Read the number, card information, and points blocks. A block the card refuses is nil;
    /// session loss and cancellation propagate.
    open func readCardBlocks() async throws -> (number: Data?, info: Data?, points: Data?) {
        let number = try await transport.readOptionalCommonAreaBlock(serviceCode: NanacoConstants.numberServiceCode, source: "nanaco")
        let info = try await transport.readOptionalCommonAreaBlock(serviceCode: NanacoConstants.infoServiceCode, source: "nanaco")
        let points = try await transport.readOptionalCommonAreaBlock(
            serviceCode: NanacoConstants.pointsServiceCode,
            blockNumber: NanacoConstants.pointsBlockNumber,
            source: "nanaco"
        )
        return (number, info, points)
    }

    /// Read history blocks one at a time. A block-level read failure ends the history;
    /// session loss and cancellation propagate to the caller.
    open func readHistory() async throws -> [TransitTransaction] {
        let blocks = try await transport.readCommonAreaBlocks(
            serviceCode: NanacoConstants.historyServiceCode,
            maxBlocks: NanacoConstants.maxHistoryBlocks,
            source: "nanaco"
        )
        let transactions = blocks.compactMap { Self.parseHistoryBlock($0) }
        NFCLog.debug("nanaco history read complete blocks=\(blocks.count) transactions=\(transactions.count)", source: "nanaco")
        return transactions
    }

    // MARK: - Parsing

    /// Build the result. The serial number is the nanaco number printed on the card, or the IDm
    /// when the number block is unavailable. The issue date becomes `validFrom`; the last-use
    /// date and the summed point buckets go to `metadata["lastUseDate"]` and `metadata["points"]`.
    open class func makeBalance(
        balance: Int,
        numberBlock: Data?,
        infoBlock: Data?,
        pointsBlock: Data?,
        idm: Data,
        transactions: [TransitTransaction] = []
    ) -> TransitBalance {
        var metadata = ["idm": idm.hexString]
        var serialNumber = idm.hexString
        var issueDate: Date?
        if let numberBlock, numberBlock.count >= 8 {
            serialNumber = Data(numberBlock.prefix(8)).hexString
            metadata["nanacoNumber"] = serialNumber
        }
        if let infoBlock, infoBlock.count >= NanacoConstants.issueDateOffset + 2 {
            let lastUse = Data(infoBlock.dropFirst(NanacoConstants.lastUseDateOffset).prefix(2))
            let issue = Data(infoBlock.dropFirst(NanacoConstants.issueDateOffset).prefix(2))
            metadata["lastUseDate"] = FeliCaCommonAreaConstants.packedDateString(lastUse)
            issueDate = FeliCaCommonAreaConstants.packedDate(issue)
        }
        if let pointsBlock, pointsBlock.count >= 8 {
            let points = NanacoConstants.pointsOffsets.reduce(0) { total, offset in
                total + Data(pointsBlock.dropFirst(offset).prefix(3)).reduce(0) { $0 << 8 | Int($1) }
            }
            metadata["points"] = String(points)
        }
        return TransitBalance(
            serialNumber: serialNumber,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "nanaco",
            validFrom: issueDate,
            transactions: transactions,
            metadata: metadata
        )
    }

    /// Parse a 16-byte history block. Empty (all-zero) slots return nil.
    ///
    /// Usage types follow TRETJapanNFCReader: 0x47 payment, 0x5C / 0x6F / 0x70 charge, 0x83
    /// points exchanged for e-money (a top-up), 0x35 transfer. Transfers and other types are
    /// `.unknown` and carry no amount; transfers set `metadata["event"]` to `transfer`.
    open class func parseHistoryBlock(_ block: Data) -> TransitTransaction? {
        let block = Data(block)
        guard block.count == 16, !block.allSatisfy({ $0 == 0 }) else { return nil }

        let usageType = block[NanacoConstants.historyTypeOffset]
        var metadata = ["usageType": String(format: "%02X", usageType)]
        let type: TransactionType
        switch usageType {
        case NanacoConstants.paymentType:
            type = .purchase
        case _ where NanacoConstants.chargeTypes.contains(usageType):
            type = .topup
        case NanacoConstants.pointExchangeType:
            type = .topup
            metadata["event"] = "pointExchange"
        case NanacoConstants.transferType:
            type = .unknown
            metadata["event"] = "transfer"
        default:
            type = .unknown
        }
        let amount = Int(Data(block[NanacoConstants.historyAmountOffset ..< NanacoConstants.historyAmountOffset + 4]).uint32BE)
        let balanceAfter = Int(Data(block[NanacoConstants.historyBalanceOffset ..< NanacoConstants.historyBalanceOffset + 4]).uint32BE)
        let sequence = Int(Data(block[NanacoConstants.historySequenceOffset ..< NanacoConstants.historySequenceOffset + 2]).uint16BE)
        metadata["sequenceNumber"] = String(sequence)

        let rawDate = Data(block[NanacoConstants.historyDateOffset ..< NanacoConstants.historyDateOffset + 4]).uint32BE
        let date = FeliCaCommonAreaConstants.jstDate(
            year: 2000 + Int(rawDate >> 21 & 0x7FF),
            month: Int(rawDate >> 17 & 0x0F),
            day: Int(rawDate >> 12 & 0x1F),
            hour: Int(rawDate >> 6 & 0x3F),
            minute: Int(rawDate & 0x3F)
        )

        return TransitTransaction(
            type: type,
            amount: type == .unknown ? nil : amount,
            balanceAfter: balanceAfter,
            date: date,
            rawData: block,
            metadata: metadata
        )
    }
}
