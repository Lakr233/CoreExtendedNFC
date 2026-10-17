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
/// - Balance: service 0x008B, 1 block, bytes 0x0B-0x0C LE (JPY)
/// - History: service 0x090F, up to 20 blocks (cyclic)
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class JapanICReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    /// Read balance only (fast — single block read).
    open func readBalance() async throws -> TransitBalance {
        NFCLog.info("Japan IC balance read start idm=\(NFCLog.payload(transport.identifier))", source: "JapanIC")
        try validateSystemCode()
        let balance = try await readRawBalance()
        NFCLog.info("Japan IC balance read complete balance=\(NFCLog.cardValue(balance)) JPY", source: "JapanIC")
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "Japan IC"
        )
    }

    /// Read balance + transaction history.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("Japan IC balance/history read start idm=\(NFCLog.payload(transport.identifier))", source: "JapanIC")
        try validateSystemCode()
        let balance = try await readRawBalance()
        let transactions = try await readHistory()
        NFCLog.info("Japan IC balance/history read complete balance=\(NFCLog.cardValue(balance)) JPY transactions=\(transactions.count)", source: "JapanIC")
        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balance,
            currencyCode: "JPY",
            cardName: "Japan IC",
            transactions: transactions
        )
    }

    // MARK: - Steps

    open func validateSystemCode() throws {
        NFCLog.debug("Japan IC system code=\(transport.systemCode.hexString) expected=\(JapanICConstants.systemCode.hexString)", source: "JapanIC")
        guard transport.systemCode == JapanICConstants.systemCode else {
            // Not a CJRC (0x0003) card.
            throw NFCError.tagNotSupported
        }
    }

    open func readRawBalance() async throws -> Int {
        // Verify balance service exists
        NFCLog.debug("Japan IC request service balance=\(JapanICConstants.balanceServiceCode.hexString)", source: "JapanIC")
        let versions = try await transport.requestService(
            nodeCodeList: [JapanICConstants.balanceServiceCode]
        )
        NFCLog.debug("Japan IC balance service versions=\(versions.map(\.hexString).joined(separator: ","))", source: "JapanIC")
        guard let version = versions.first,
            version != Data([0xFF, 0xFF])
        else {
            // Balance service 0x008B is missing.
            throw NFCError.tagNotSupported
        }

        // Read single balance block
        let blocks = try await transport.readWithoutEncryption(
            serviceCode: JapanICConstants.balanceServiceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: 0)]
        )
        guard let block = blocks.first,
            block.count >= JapanICConstants.balanceOffset + 2
        else {
            NFCLog.error("Japan IC invalid balance block=\(NFCLog.payload(blocks.first ?? Data()))", source: "JapanIC")
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }

        let balanceBytes = Data(block.dropFirst(JapanICConstants.balanceOffset).prefix(2))
        let balance = Int(balanceBytes.uint16LE)
        NFCLog.debug(
            "Japan IC balance block=\(NFCLog.payload(block)) offset=\(JapanICConstants.balanceOffset) bytes=\(NFCLog.payload(balanceBytes)) value=\(NFCLog.cardValue(balance))",
            source: "JapanIC"
        )
        return balance
    }

    /// Read history blocks one at a time. A block-level read failure ends the history;
    /// session loss and cancellation propagate to the caller.
    open func readHistory() async throws -> [TransitTransaction] {
        var transactions: [TransitTransaction] = []
        NFCLog.debug("Japan IC history read start service=\(JapanICConstants.historyServiceCode.hexString) maxBlocks=\(JapanICConstants.maxHistoryBlocks)", source: "JapanIC")

        for i in 0 ..< JapanICConstants.maxHistoryBlocks {
            try Task.checkCancellation()
            do {
                let blocks = try await transport.readWithoutEncryption(
                    serviceCode: JapanICConstants.historyServiceCode,
                    blockList: [FeliCaFrame.blockListElement(blockNumber: UInt16(i))]
                )
                guard let block = blocks.first, block.count == 16 else {
                    NFCLog.debug("Japan IC history block #\(i) invalid=\(NFCLog.payload(blocks.first ?? Data()))", source: "JapanIC")
                    break
                }
                NFCLog.debug("Japan IC history block #\(i)=\(NFCLog.payload(block))", source: "JapanIC")

                // Skip empty blocks (all zeros)
                if block.allSatisfy({ $0 == 0 }) {
                    NFCLog.debug("Japan IC history block #\(i) empty", source: "JapanIC")
                    continue
                }

                // Unused slots are not always all zeros (e.g. `00 00 00 80 00…` on PASMO).
                // Like Metrodroid (SuicaUtil.extractDate returns null only for a raw date of 0,
                // and SuicaTransitData skips only those), drop slots whose date field is 0 and
                // keep records whose date fields are out of range, with a nil date.
                if Self.hasDateField(block), let tx = Self.parseHistoryBlock(block) {
                    NFCLog.debug(
                        "Japan IC history block #\(i) parsed type=\(tx.type.rawValue) balanceAfter=\(tx.balanceAfter.map { NFCLog.cardValue($0) } ?? "unavailable") entry=\(NFCLog.cardValue(tx.entryStation ?? "")) exit=\(NFCLog.cardValue(tx.exitStation ?? ""))",
                        source: "JapanIC")
                    transactions.append(tx)
                } else {
                    NFCLog.debug("Japan IC history block #\(i) skipped by parser", source: "JapanIC")
                }
            } catch where !isSessionTerminating(error) {
                NFCLog.debug("Japan IC history block #\(i) read stopped: \(error.localizedDescription)", source: "JapanIC")
                break
            }
        }
        NFCLog.debug("Japan IC history read complete transactions=\(transactions.count)", source: "JapanIC")

        return transactions
    }

    /// Parse a 16-byte history block into a `TransitTransaction`.
    open class func parseHistoryBlock(_ block: Data) -> TransitTransaction? {
        let bytes = [UInt8](block)
        guard bytes.count == 16 else { return nil }

        let consoleType = bytes[JapanICConstants.historyMachineType]
        let processType = bytes[JapanICConstants.historyUsageType] & JapanICConstants.processTypeMask
        let isProductSale = JapanICConstants.productSaleConsoleTypes.contains(consoleType)

        // Classification follows Metrodroid SuicaUtil console/process tables.
        let txType: TransactionType =
            if JapanICConstants.topupProcessTypes.contains(processType) {
                .topup
            } else if isProductSale || JapanICConstants.purchaseProcessTypes.contains(processType) {
                .purchase
            } else {
                .trip
            }

        // Product sales store the purchase time in bytes 6-7 (Metrodroid SuicaUtil.extractDate).
        let date = parseDate(block, includeTime: isProductSale)

        // Station codes as hex strings, following Metrodroid SuicaTrip.parse: unused blocks, product
        // sales, and charges carry none; bus records carry a line and stop instead of stations;
        // ticket machines record a single station and no exit.
        var metadata = [
            "consoleType": String(format: "%02X", consoleType),
            "processType": String(format: "%02X", bytes[JapanICConstants.historyUsageType]),
        ]
        let entryCode = Data(bytes[JapanICConstants.historyStationEntry ..< JapanICConstants.historyStationEntry + 2]).hexString
        let exitCode = Data(bytes[JapanICConstants.historyStationExit ..< JapanICConstants.historyStationExit + 2]).hexString
        var entryStation: String?
        var exitStation: String?
        let regionByte = bytes[JapanICConstants.historyRegionCode]
        if hasDateField(block), !isProductSale, processType != JapanICConstants.chargeProcessType {
            if consoleType == JapanICConstants.busConsoleType {
                metadata["busLineCode"] = entryCode
                metadata["busStopCode"] = exitCode
            } else if JapanICConstants.ticketMachineConsoleTypes.contains(consoleType) {
                entryStation = entryCode
                metadata["entryRegion"] = String(regionByte >> 6 & 0x03)
            } else {
                entryStation = entryCode
                exitStation = exitCode
                metadata["entryRegion"] = String(regionByte >> 6 & 0x03)
                metadata["exitRegion"] = String(regionByte >> 4 & 0x03)
            }
        }

        // Balance after transaction (little-endian)
        let balanceAfter = Int(bytes[JapanICConstants.historyBalanceOffset])
            | Int(bytes[JapanICConstants.historyBalanceOffset + 1]) << 8

        return TransitTransaction(
            type: txType,
            amount: nil, // Individual trip fare not stored in standard history
            balanceAfter: balanceAfter,
            date: date,
            entryStation: entryStation,
            exitStation: exitStation,
            metadata: metadata
        )
    }

    /// Whether the history block's 2-byte date field is non-zero. Metrodroid
    /// (SuicaUtil.extractDate) treats a zero date as an unused slot.
    open class func hasDateField(_ block: Data) -> Bool {
        let offset = JapanICConstants.historyDateOffset
        let bytes = [UInt8](block)
        guard bytes.count > offset + 1 else { return false }
        return bytes[offset] != 0 || bytes[offset + 1] != 0
    }

    /// Parse the packed date field from a history block.
    /// Format: 2 bytes BE → year(7 bits) month(4 bits) day(5 bits), base year 2000.
    /// With `includeTime`, bytes 6-7 BE add hour(5 bits) minute(6 bits), as on product sales.
    open class func parseDate(_ block: Data, includeTime: Bool = false) -> Date? {
        let bytes = [UInt8](block)
        let offset = JapanICConstants.historyDateOffset
        guard bytes.count > offset + 1 else { return nil }

        let raw = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        let year = ((raw >> 9) & 0x7F) + 2000
        let month = (raw >> 5) & 0x0F
        let day = raw & 0x1F

        guard month >= 1, month <= 12, day >= 1, day <= 31 else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        if includeTime {
            let timeOffset = JapanICConstants.historyStationEntry
            guard bytes.count > timeOffset + 1 else { return nil }
            let time = Int(bytes[timeOffset]) << 8 | Int(bytes[timeOffset + 1])
            let hour = time >> 11
            let minute = (time >> 5) & 0x3F
            guard hour <= 23, minute <= 59 else { return nil }
            components.hour = hour
            components.minute = minute
        }
        components.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return Calendar(identifier: .gregorian).date(from: components)
    }
}
