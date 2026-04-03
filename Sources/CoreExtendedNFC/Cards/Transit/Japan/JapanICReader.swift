import Foundation

/// Reads balance and transaction history from Japan FeliCa IC transit cards
/// (Suica, PASMO, ICOCA, Kitaca, TOICA, manaca, SUGOCA, nimoca, Hayakaken, etc.).
///
/// ## Requirements
/// The consumer app must register system code `0x0003` in its Info.plist
/// under `com.apple.developer.nfc.readersession.felicasystemcodes`.
///
/// ## References
/// - CJRC system code 0x0003
/// - Balance: service 0x008B, 1 block, bytes 0x0A-0x0B LE (JPY)
/// - History: service 0x090F, up to 20 blocks (cyclic)
public struct JapanICReader: Sendable {
    let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read balance only (fast — single block read).
    public func readBalance() async throws -> TransitBalance {
        try validateSystemCode()
        let balance = try await readRawBalance()
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "Japan IC"
        )
    }

    /// Read balance + transaction history.
    public func readBalanceAndHistory() async throws -> TransitBalance {
        try validateSystemCode()
        let balance = try await readRawBalance()
        let transactions = await readHistory()
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "Japan IC",
            transactions: transactions
        )
    }

    // MARK: - Private

    private func validateSystemCode() throws {
        guard transport.systemCode == JapanICConstants.systemCode else {
            throw NFCError.unsupportedOperation(
                "Expected FeliCa system code 0x0003 (CJRC), got \(transport.systemCode.hexString)"
            )
        }
    }

    private func readRawBalance() async throws -> Int {
        // Verify balance service exists
        let versions = try await transport.requestService(
            nodeCodeList: [JapanICConstants.balanceServiceCode]
        )
        guard let version = versions.first,
              version != Data([0xFF, 0xFF])
        else {
            throw NFCError.unsupportedOperation("Balance service 0x008B not available on this card")
        }

        // Read single balance block
        let blocks = try await transport.readWithoutEncryption(
            serviceCode: JapanICConstants.balanceServiceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: 0)]
        )
        guard let block = blocks.first, block.count >= 12 else {
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }

        return Int(Data(block[JapanICConstants.balanceOffset ..< JapanICConstants.balanceOffset + 2]).uint16LE)
    }

    private func readHistory() async -> [TransitTransaction] {
        var transactions: [TransitTransaction] = []

        // Read history blocks one at a time; stop on first failure
        for i in 0 ..< JapanICConstants.maxHistoryBlocks {
            do {
                let blocks = try await transport.readWithoutEncryption(
                    serviceCode: JapanICConstants.historyServiceCode,
                    blockList: [FeliCaFrame.blockListElement(blockNumber: UInt16(i))]
                )
                guard let block = blocks.first, block.count == 16 else { break }

                // Skip empty blocks (all zeros)
                if block.allSatisfy({ $0 == 0 }) { continue }

                if let tx = parseHistoryBlock(block) {
                    transactions.append(tx)
                }
            } catch {
                break
            }
        }

        return transactions
    }

    /// Parse a 16-byte history block into a `TransitTransaction`.
    static func parseHistoryBlock(_ block: Data) -> TransitTransaction? {
        guard block.count == 16 else { return nil }

        let usageType = block[JapanICConstants.historyUsageType]

        // Classify transaction type
        let txType: TransactionType
        if JapanICConstants.topupUsageTypes.contains(usageType) {
            txType = .topup
        } else if JapanICConstants.purchaseUsageTypes.contains(usageType) {
            txType = .purchase
        } else {
            txType = .trip
        }

        // Parse date: 2 bytes at offset 4, packed as year(7) month(4) day(5)
        let date = parseDate(block)

        // Station codes as hex strings
        let entryStation = Data(block[JapanICConstants.historyStationEntry ..< JapanICConstants.historyStationEntry + 2]).hexString
        let exitStation = Data(block[JapanICConstants.historyStationExit ..< JapanICConstants.historyStationExit + 2]).hexString

        // Balance after transaction
        let balanceAfter = Int(Data(block[JapanICConstants.historyBalanceOffset ..< JapanICConstants.historyBalanceOffset + 2]).uint16LE)

        return TransitTransaction(
            type: txType,
            amount: 0, // Individual trip fare not stored in standard history
            balanceAfter: balanceAfter,
            date: date,
            entryStation: entryStation,
            exitStation: exitStation
        )
    }

    /// Parse the packed date field from a history block.
    /// Format: 2 bytes BE → year(7 bits) month(4 bits) day(5 bits), base year 2000.
    static func parseDate(_ block: Data) -> Date? {
        guard block.count > JapanICConstants.historyDateOffset + 1 else { return nil }

        let raw = Data(block[JapanICConstants.historyDateOffset ..< JapanICConstants.historyDateOffset + 2]).uint16BE
        let year = Int((raw >> 9) & 0x7F) + 2000
        let month = Int((raw >> 5) & 0x0F)
        let day = Int(raw & 0x1F)

        guard month >= 1, month <= 12, day >= 1, day <= 31 else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return Calendar(identifier: .gregorian).date(from: components)
    }

    private func parseHistoryBlock(_ block: Data) -> TransitTransaction? {
        Self.parseHistoryBlock(block)
    }
}
