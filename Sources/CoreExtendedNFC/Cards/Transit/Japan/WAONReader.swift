import Foundation

/// Reads balance and transaction history from AEON WAON prepaid e-money cards.
///
/// ## Requirements
/// The consumer app must register system code `0xFE00` in its Info.plist
/// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
///
/// ## References
/// - FeliCa common area system code 0xFE00
/// - Balance: service 0x6817, 1 block, bytes 0-1 LE (JPY)
/// - WAON number: service 0x684F; points: service 0x684B
/// - History: service 0x680B, three 32-byte records in blocks 0-5
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class WAONReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read balance, WAON number, and points.
    open func readBalance() async throws -> TransitBalance {
        NFCLog.info("WAON balance read start idm=\(NFCLog.payload(transport.identifier))", source: "WAON")
        try await validateCard()
        let balance = try await readRawBalance()
        let blocks = try await readCardBlocks()
        NFCLog.info("WAON balance read complete balance=\(NFCLog.cardValue(balance)) JPY", source: "WAON")
        return Self.makeBalance(balance: balance, numberBlock: blocks.number, pointsBlock: blocks.points, idm: transport.identifier)
    }

    /// Read balance, WAON number, points, and transaction history.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("WAON balance/history read start idm=\(NFCLog.payload(transport.identifier))", source: "WAON")
        try await validateCard()
        let balance = try await readRawBalance()
        let blocks = try await readCardBlocks()
        let transactions = try await readHistory()
        NFCLog.info("WAON balance/history read complete balance=\(NFCLog.cardValue(balance)) JPY transactions=\(transactions.count)", source: "WAON")
        return Self.makeBalance(balance: balance, numberBlock: blocks.number, pointsBlock: blocks.points, idm: transport.identifier, transactions: transactions)
    }

    // MARK: - Steps

    /// Throw `tagNotSupported` unless this is a common area tag with the WAON purse service.
    open func validateCard() async throws {
        try await transport.requireCommonAreaService(WAONConstants.balanceServiceCode, source: "WAON")
    }

    open func readRawBalance() async throws -> Int {
        let block = try await transport.readCommonAreaBlock(serviceCode: WAONConstants.balanceServiceCode, source: "WAON")
        let balance = Int(Data(block.dropFirst(WAONConstants.balanceOffset)).uint16LE)
        NFCLog.debug("WAON balance value=\(NFCLog.cardValue(balance))", source: "WAON")
        return balance
    }

    /// Read the WAON number and points blocks. A block the card refuses is nil; session loss and
    /// cancellation propagate.
    open func readCardBlocks() async throws -> (number: Data?, points: Data?) {
        let number = try await transport.readOptionalCommonAreaBlock(serviceCode: WAONConstants.numberServiceCode, source: "WAON")
        let points = try await transport.readOptionalCommonAreaBlock(serviceCode: WAONConstants.pointsServiceCode, source: "WAON")
        return (number, points)
    }

    /// Read history blocks one at a time and pair them into records, newest first. A
    /// block-level read failure ends the history; session loss and cancellation propagate.
    open func readHistory() async throws -> [TransitTransaction] {
        let blocks = try await transport.readCommonAreaBlocks(
            serviceCode: WAONConstants.historyServiceCode,
            maxBlocks: WAONConstants.maxHistoryRecords * 2,
            source: "WAON"
        )
        let records = stride(from: 0, to: blocks.count - 1, by: 2).map { blocks[$0] + blocks[$0 + 1] }
        let transactions = Self.sortedNewestFirst(records.compactMap { Self.parseHistoryRecord($0) })
        NFCLog.debug("WAON history read complete blocks=\(blocks.count) transactions=\(transactions.count)", source: "WAON")
        return transactions
    }

    // MARK: - Parsing

    /// Build the result. The serial number is the WAON number printed on the card, or the IDm
    /// when the number block is unavailable; the point balance goes to `metadata["points"]`.
    open class func makeBalance(
        balance: Int,
        numberBlock: Data?,
        pointsBlock: Data?,
        idm: Data,
        transactions: [TransitTransaction] = []
    ) -> TransitBalance {
        var metadata = ["idm": idm.hexString]
        var serialNumber = idm.hexString
        if let numberBlock, numberBlock.count >= 8 {
            serialNumber = Data(numberBlock.prefix(8)).hexString
            metadata["waonNumber"] = serialNumber
        }
        if let pointsBlock, pointsBlock.count >= 3 {
            metadata["points"] = String(pointsBlock.prefix(3).reduce(0) { $0 << 8 | Int($1) })
        }
        return TransitBalance(
            serialNumber: serialNumber,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "WAON",
            transactions: transactions,
            metadata: metadata
        )
    }

    /// Parse a 32-byte history record (two blocks). Empty (all-zero) records return nil.
    ///
    /// Payments report the usage amount and charges the charge amount. Other usage types are
    /// `.unknown` with no amount; both raw amounts stay in `metadata["usageAmount"]` and
    /// `metadata["chargeAmount"]`.
    open class func parseHistoryRecord(_ record: Data) -> TransitTransaction? {
        let record = Data(record)
        guard record.count == 32, !record.allSatisfy({ $0 == 0 }) else { return nil }

        let usageType = record[WAONConstants.historyTypeOffset]
        let packed = Data(record.dropFirst(WAONConstants.historyPackedOffset))
        let year = 2005 + packedBits(packed, offset: 0, length: 5)
        let month = packedBits(packed, offset: 5, length: 4)
        let day = packedBits(packed, offset: 9, length: 5)
        let hour = packedBits(packed, offset: 14, length: 5)
        let minute = packedBits(packed, offset: 19, length: 6)
        let balanceAfter = packedBits(packed, offset: 25, length: 18)
        let usageAmount = packedBits(packed, offset: 43, length: 18)
        let chargeAmount = packedBits(packed, offset: 61, length: 17)

        var metadata = [
            "usageType": String(format: "%02X", usageType),
            "terminalNumber": Data(record[WAONConstants.historyTerminalRange]).hexString,
            "cardSequence": Data(record[WAONConstants.historySequenceRange]).hexString,
            "usageAmount": String(usageAmount),
            "chargeAmount": String(chargeAmount),
        ]
        let type: TransactionType
        let amount: Int?
        if usageType == WAONConstants.paymentType {
            type = .purchase
            amount = usageAmount
        } else if WAONConstants.chargeTypes.contains(usageType) {
            type = .topup
            amount = chargeAmount
        } else {
            type = .unknown
            amount = nil
            metadata["event"] = WAONConstants.otherTypeNames[usageType]
        }

        return TransitTransaction(
            type: type,
            amount: amount,
            balanceAfter: balanceAfter,
            date: FeliCaCommonAreaConstants.jstDate(year: year, month: month, day: day, hour: hour, minute: minute),
            rawData: record,
            metadata: metadata
        )
    }

    /// Order records newest first. The card rotates records through fixed slots, so slot order
    /// is not chronological (TRETJapanNFCReader also sorts by date). Undated records go last.
    open class func sortedNewestFirst(_ transactions: [TransitTransaction]) -> [TransitTransaction] {
        transactions.enumerated().sorted { lhs, rhs in
            switch (lhs.element.date, rhs.element.date) {
            case (let l?, let r?) where l != r: l > r
            case (_?, nil): true
            case (nil, _?): false
            default: lhs.offset < rhs.offset
            }
        }.map(\.element)
    }

    /// Read `length` bits starting at bit `offset`, most significant bit first.
    private static func packedBits(_ data: Data, offset: Int, length: Int) -> Int {
        (offset ..< offset + length).reduce(0) { value, bit in
            value << 1 | Int(data[data.startIndex + bit / 8] >> (7 - bit % 8) & 0x01)
        }
    }
}
