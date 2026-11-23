import Foundation

/// Reads Okinawa OKICA balance and history from service 0x028F.
///
/// The latest history record also holds the current balance. Operation codes,
/// packed JST dates and locations follow TRETJapanNFCReader's OKICA format.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class OKICAReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    open func validateSystemCode() throws {
        guard transport.systemCode == OKICAConstants.systemCode else {
            throw NFCError.tagNotSupported
        }
    }

    /// Read just the latest record for a fast balance lookup.
    open func readBalance() async throws -> TransitBalance {
        try validateSystemCode()
        try await requireHistoryService()
        let block = try await readBlock(0)
        guard let balance = Self.parseBalance(block) else {
            throw NFCError.invalidResponse(block)
        }
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "OKICA"
        )
    }

    /// Keep the latest record mandatory; a refused later block ends the history.
    /// Session loss and cancellation always propagate.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("OKICA balance/history read start idm=\(NFCLog.payload(transport.identifier))", source: "OKICA")
        try validateSystemCode()
        try await requireHistoryService()
        let first = try await readBlock(0)
        guard let balance = Self.parseBalance(first) else {
            throw NFCError.invalidResponse(first)
        }
        var blocks = [first]
        for index in 1 ..< OKICAConstants.maxHistoryBlocks {
            try Task.checkCancellation()
            do {
                blocks.append(try await readBlock(UInt16(index)))
            } catch  where !isSessionTerminating(error) {
                NFCLog.debug("OKICA history stopped at block #\(index): \(error.localizedDescription)", source: "OKICA")
                break
            }
        }

        let transactions = blocks.enumerated().compactMap { index, block in
            Self.parseHistoryBlock(block, previousBlock: index + 1 < blocks.count ? blocks[index + 1] : nil)
        }
        NFCLog.info("OKICA read complete balance=\(NFCLog.cardValue(balance)) JPY transactions=\(transactions.count)", source: "OKICA")
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "OKICA",
            transactions: transactions
        )
    }

    open func requireHistoryService() async throws {
        let versions = try await transport.requestService(nodeCodeList: [OKICAConstants.historyServiceCode])
        guard let version = versions.first, version != Data([0xFF, 0xFF]) else {
            throw NFCError.tagNotSupported
        }
    }

    open func readBlock(_ index: UInt16) async throws -> Data {
        let blocks = try await transport.readWithoutEncryption(
            serviceCode: OKICAConstants.historyServiceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: index)]
        )
        guard let block = blocks.first, block.count == 16 else {
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }
        NFCLog.debug("OKICA history block #\(index)=\(NFCLog.payload(block))", source: "OKICA")
        return block
    }

    /// An unused slot has no date field and must not become a zero balance or an amount.
    open class func parseBalance(_ block: Data) -> Int? {
        let bytes = [UInt8](block)
        guard bytes.count == 16, JapanICReader.hasDateField(block) else { return nil }
        return Int(bytes[OKICAConstants.balanceOffset]) | Int(bytes[OKICAConstants.balanceOffset + 1]) << 8
    }

    /// `previousBlock` is the immediately older slot. An amount is the balance delta
    /// between adjacent populated slots, only when it moves in the expected direction.
    open class func parseHistoryBlock(_ block: Data, previousBlock: Data? = nil) -> TransitTransaction? {
        guard let balance = parseBalance(block) else { return nil }
        let bytes = [UInt8](block)
        let usage = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        let recordNumber = Int(bytes[13]) << 8 | Int(bytes[14])
        let type: TransactionType
        let operation: String
        switch usage {
        case OKICAConstants.yuiRailTrip:
            type = .trip
            operation = "Yui Rail"
        case OKICAConstants.busTrip:
            type = .trip
            operation = "Bus"
        case OKICAConstants.yuiRailTopup, OKICAConstants.busTopup, OKICAConstants.machineTopup:
            type = .topup
            operation = "Top-up"
        case let code where OKICAConstants.pointTopups.contains(code):
            type = .topup
            operation = "Point exchange"
        case OKICAConstants.newIssue:
            type = .topup
            operation = "New issue"
        default:
            type = .unknown
            operation = "Unknown"
        }

        var amount: Int?
        if let previousBlock, let previousBalance = parseBalance(previousBlock) {
            if type == .trip, balance <= previousBalance {
                amount = previousBalance - balance
            } else if type == .topup, balance >= previousBalance {
                amount = balance - previousBalance
            }
        }

        var metadata = ["usageCode": String(format: "%08X", usage), "operation": operation]
        var entryStation: String?
        var exitStation: String?
        let entryCode = Data(bytes[6 ... 7]).hexString
        let exitCode = Data(bytes[8 ... 9]).hexString
        if usage == OKICAConstants.yuiRailTrip {
            metadata["mode"] = "monorail"
            metadata["entryRegion"] = "3"
            metadata["exitRegion"] = "3"
            entryStation = entryCode
            exitStation = exitCode
        } else if usage == OKICAConstants.busTrip {
            metadata["mode"] = "bus"
            metadata["entryLocationCode"] = entryCode
            metadata["exitLocationCode"] = exitCode
        }
        return TransitTransaction(
            type: type,
            amount: amount,
            balanceAfter: balance,
            date: JapanICReader.parseDate(block),
            entryStation: entryStation,
            exitStation: exitStation,
            recordNumber: recordNumber,
            rawData: block,
            metadata: metadata
        )
    }
}
