import Foundation

/// Reads balance and transaction history from South Korea KS X 6924 transit cards
/// (T-Money, Cashbee, MOIBA, K-Cash) and Wellington Snapper cards, which share the
/// T-Money AID.
///
/// ## Protocol Overview
/// 1. SELECT one of the known AIDs (try each until success)
/// 2. Parse FCI for purse info (tag 0xB0) containing serial number and dates
/// 3. GET BALANCE: CLA=0x90 INS=0x4C → 4 bytes big-endian
/// 4. READ RECORD from SFI 4 (`00 B2 n 24 00`, n = 1...) → transaction records
///
/// Cards selected through the T-Money AID whose SFI 4 records all carry Snapper's
/// 0xFF filler (Metrodroid `SnapperTransitData.check`) are reported as Snapper in NZD cents.
/// Snapper trips use a different record layout and are not decoded.
///
/// ## References
/// - KS X 6924 specification
/// - Metrodroid KSX6924Application, TMoneyTrip, SnapperTransitData
public struct KSX6924Reader: Sendable {
    let transport: any ISO7816TagTransporting

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    /// Try all known KS X 6924 AIDs and read the balance from the first match.
    ///
    /// For the shared T-Money / Snapper AID the transaction file is also read, because it is
    /// the only way to tell the two systems (and their currencies) apart.
    public func readBalance() async throws -> TransitBalance {
        try await read(includeTransactions: false)
    }

    /// Read balance + transaction records.
    public func readBalanceAndHistory() async throws -> TransitBalance {
        try await read(includeTransactions: true)
    }

    // MARK: - Private

    private func read(includeTransactions: Bool) async throws -> TransitBalance {
        NFCLog.info("KSX6924 read start history=\(includeTransactions)", source: "KSX6924")
        let (aidName, aid, fciData) = try await selectCard()
        let purseInfo = parsePurseInfo(fciData)
        let balance = try await readRawBalance()

        let sharesSnapperAID = aid == KSX6924Constants.tMoneyAID
        let records = includeTransactions || sharesSnapperAID ? try await readRecords() : []
        let isSnapper = sharesSnapperAID && Self.isSnapper(records: records)

        let cardName: String
        let currencyCode: String
        let transactions: [TransitTransaction]
        if isSnapper {
            cardName = "Snapper"
            currencyCode = "NZD"
            transactions = []
        } else {
            cardName = sharesSnapperAID ? "T-Money" : aidName
            currencyCode = "KRW"
            transactions = includeTransactions
                ? records.enumerated().compactMap { Self.parseRecord($0.element, recordNumber: $0.offset + 1) }
                : []
        }
        NFCLog.info(
            "KSX6924 read complete card=\(cardName) balance=\(NFCLog.cardValue(balance)) \(currencyCode) transactions=\(transactions.count)",
            source: "KSX6924"
        )

        return TransitBalance(
            serialNumber: purseInfo.serial,
            balanceRaw: balance,
            currencyCode: currencyCode,
            cardName: cardName,
            validFrom: purseInfo.issueDate,
            validUntil: purseInfo.expiryDate,
            transactions: transactions
        )
    }

    /// Try each known AID until one succeeds. Returns (name, aid, fciResponseData).
    private func selectCard() async throws -> (String, Data, Data) {
        for (name, aid) in KSX6924Constants.allAIDs {
            NFCLog.debug("KSX6924 SELECT AID \(aid.hexString) (\(name))", source: "KSX6924")
            do {
                let response = try await transport.sendAPDUWithChaining(CommandAPDU.select(aid: aid))
                if response.isSuccess {
                    NFCLog.debug("KSX6924 SELECT AID success card=\(name) data=\(NFCLog.payload(response.data))", source: "KSX6924")
                    return (name, aid, response.data)
                }
                NFCLog.debug("KSX6924 SELECT AID rejected card=\(name) sw=\(String(format: "%02X%02X", response.sw1, response.sw2))", source: "KSX6924")
            } catch let NFCError.unexpectedStatusWord(sw1, sw2) {
                NFCLog.debug("KSX6924 SELECT AID threw status card=\(name) sw=\(String(format: "%02X%02X", sw1, sw2))", source: "KSX6924")
            } catch let NFCError.unsupportedOperation(message) {
                NFCLog.debug("KSX6924 SELECT AID unsupported card=\(name): \(message)", source: "KSX6924")
            }
        }
        // None of the KS X 6924 AIDs was selectable; report the primary (T-Money) AID.
        throw NFCError.applicationNotFound(aid: KSX6924Constants.tMoneyAID)
    }

    private func readRawBalance() async throws -> Int {
        let apdu = CommandAPDU(
            cla: KSX6924Constants.CLA,
            ins: KSX6924Constants.INS_GET_BALANCE,
            p1: 0x00,
            p2: 0x00,
            le: KSX6924Constants.BALANCE_RESP_LEN
        )
        let response = try await transport.sendAPDUWithChaining(apdu)
        NFCLog.debug("KSX6924 GET BALANCE sw=\(String(format: "%02X%02X", response.sw1, response.sw2)) data=\(NFCLog.payload(response.data))", source: "KSX6924")
        guard response.isSuccess else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
        guard response.data.count >= 4 else {
            throw NFCError.invalidResponse(response.data)
        }
        return Int(Data(response.data.prefix(4)).uint32BE)
    }

    /// READ RECORD `00 B2 n 24 00`: record `n` of SFI 4, Le = 256.
    static func readRecordAPDU(recordNumber: UInt8) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xB2,
            p1: recordNumber,
            p2: (KSX6924Constants.transactionSFI << 3) | 0x04,
            le: 0x00
        )
    }

    /// Read SFI 4 records until the card reports no further record. Session loss and
    /// cancellation propagate; any other per-record failure ends the record list.
    private func readRecords() async throws -> [Data] {
        var records: [Data] = []
        for recordNumber in 1 ... KSX6924Constants.maxRecords {
            try Task.checkCancellation()
            let response: ResponseAPDU
            do {
                response = try await transport.sendAPDUWithChaining(
                    Self.readRecordAPDU(recordNumber: UInt8(recordNumber))
                )
            } catch where !isSessionTerminating(error) {
                NFCLog.debug("KSX6924 READ RECORD #\(recordNumber) stopped: \(error.localizedDescription)", source: "KSX6924")
                break
            }
            guard response.isSuccess else {
                NFCLog.debug("KSX6924 READ RECORD #\(recordNumber) end sw=\(String(format: "%04X", response.statusWord))", source: "KSX6924")
                break
            }
            NFCLog.debug("KSX6924 record #\(recordNumber)=\(NFCLog.payload(response.data))", source: "KSX6924")
            records.append(Data(response.data))
        }
        return records
    }

    /// Metrodroid `SnapperTransitData.check`: every SFI 4 record is 46 bytes with bytes 26..<46
    /// set to 0xFF. An empty record file is not treated as Snapper.
    ///
    /// A T-Money record keeps its BCD date-time at 26..<33 (``KSX6924Constants/recordDateTime``),
    /// so any record with real T-Money trip data already fails the filler test. The type byte
    /// is deliberately not used: Snapper's SFI 4 records also carry type 1 / 2 at byte 0
    /// (Metrodroid `SnapperTransaction.parseTransaction`, 2 = top-up), so rejecting those
    /// values would misreport real Snapper cards as T-Money.
    static func isSnapper(records: [Data]) -> Bool {
        guard !records.isEmpty else { return false }
        return records.allSatisfy { record in
            let bytes = [UInt8](record)
            return bytes.count == KSX6924Constants.snapperRecordLength
                && bytes[KSX6924Constants.snapperFillerRange].allSatisfy { $0 == 0xFF }
        }
    }

    // MARK: - Parsing

    struct PurseInfo {
        let serial: String
        let issueDate: Date?
        let expiryDate: Date?
    }

    func parsePurseInfo(_ fciData: Data) -> PurseInfo {
        guard !fciData.isEmpty,
              let nodes = try? ASN1Parser.parseTLV(fciData),
              let purseNode = ASN1Parser.findTag(KSX6924Constants.PURSE_TAG, in: nodes),
              purseNode.value.count >= 25
        else {
            return PurseInfo(serial: "", issueDate: nil, expiryDate: nil)
        }

        let purse = [UInt8](purseNode.value)

        // Serial: 8 bytes BCD at offset 4
        let serialData = Data(purse[KSX6924Constants.purseCSN ..< KSX6924Constants.purseCSN + KSX6924Constants.purseCSNLength])
        let serial = serialData.hexString

        // Issue date: 4 bytes BCD YYYYMMDD at offset 17
        let issueData = Data(purse[KSX6924Constants.purseIssueDate ..< KSX6924Constants.purseIssueDate + 4])
        let issueDate = Self.parseBCDDate(issueData)

        // Expiry date: 4 bytes BCD YYYYMMDD at offset 21
        let expiryData = Data(purse[KSX6924Constants.purseExpiryDate ..< KSX6924Constants.purseExpiryDate + 4])
        let expiryDate = Self.parseBCDDate(expiryData)

        return PurseInfo(serial: serial, issueDate: issueDate, expiryDate: expiryDate)
    }

    /// Parse a 4-byte BCD date (YYYYMMDD) into a Date.
    static func parseBCDDate(_ data: Data) -> Date? {
        guard data.count >= 4 else { return nil }

        let hex = data.hexString // e.g. "20251231"
        guard hex.count == 8 else { return nil }

        let yearStr = String(hex.prefix(4))
        let monthStr = String(hex.dropFirst(4).prefix(2))
        let dayStr = String(hex.dropFirst(6).prefix(2))

        guard let year = Int(yearStr), let month = Int(monthStr), let day = Int(dayStr),
              month >= 1, month <= 12, day >= 1, day <= 31
        else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.timeZone = TimeZone(identifier: "Asia/Seoul")
        return Calendar(identifier: .gregorian).date(from: components)
    }

    /// Parse a 7-byte BCD date-time (YYYYMMDDhhmmss) in Korea Standard Time.
    static func parseBCDDateTime(_ data: Data) -> Date? {
        let bytes = [UInt8](data)
        guard bytes.count == 7,
              bytes.allSatisfy({ $0 >> 4 <= 9 && $0 & 0x0F <= 9 })
        else { return nil }
        let values = bytes.map { Int($0 >> 4) * 10 + Int($0 & 0x0F) }
        let year = values[0] * 100 + values[1]
        guard year > 0, (1 ... 12).contains(values[2]), (1 ... 31).contains(values[3]),
              values[4] <= 23, values[5] <= 59, values[6] <= 59
        else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = values[2]
        components.day = values[3]
        components.hour = values[4]
        components.minute = values[5]
        components.second = values[6]
        components.timeZone = TimeZone(identifier: "Asia/Seoul")
        return Calendar(identifier: .gregorian).date(from: components)
    }

    /// Parse one SFI 4 transaction record (Metrodroid `TMoneyTrip.parseTrip`).
    ///
    /// Layout: byte 0 type, bytes 2..<6 balance after (BE), 6..<10 counter,
    /// 10..<14 cost (BE, unsigned), 26..<33 BCD date-time (KST).
    /// Returns nil for unused slots (zero cost and no valid timestamp).
    static func parseRecord(_ data: Data, recordNumber: Int? = nil) -> TransitTransaction? {
        let bytes = [UInt8](data)
        guard bytes.count >= KSX6924Constants.recordMinimumLength else { return nil }

        func uint32(at offset: Int) -> Int {
            bytes[offset ..< offset + 4].reduce(0) { $0 << 8 | Int($1) }
        }

        let recordType = bytes[KSX6924Constants.recordType]
        let balance = uint32(at: KSX6924Constants.recordBalance)
        let cost = uint32(at: KSX6924Constants.recordCost)
        let dateRange = KSX6924Constants.recordDateTime ..< KSX6924Constants.recordDateTime + KSX6924Constants.recordDateTimeLength
        let date = parseBCDDateTime(Data(bytes[dateRange]))
        if cost == 0, date == nil { return nil }

        let txType: TransactionType = switch recordType {
        case 0x01: .trip
        case 0x02: .topup
        default: .unknown
        }

        return TransitTransaction(
            type: txType,
            amount: cost,
            balanceAfter: balance,
            date: date,
            recordNumber: recordNumber,
            rawData: Data(bytes),
            metadata: [
                "source": "KSX6924 SFI 4",
                "recordType": String(format: "%02X", recordType),
                "counter": String(uint32(at: KSX6924Constants.recordCounter)),
            ]
        )
    }
}
