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
/// 5. READ RECORD from SFI 3 (`00 B2 n 1C 00`) → boarding / alighting records (history reads only)
///
/// Cards selected through the T-Money AID whose SFI 4 records all carry Snapper's
/// 0xFF filler (Metrodroid `SnapperTransitData.check`) are reported as Snapper in NZD cents.
/// Snapper trips use a different record layout and are not decoded. Korean SFI 3 records
/// become ``TransitBalance/tapEvents`` with the KOTRIS transport mode.
///
/// ## References
/// - KS X 6924 specification
/// - Metrodroid KSX6924Application, TMoneyTrip, SnapperTransitData
/// - KORAIL KOTRIS public-transport code table: https://www.data.go.kr/data/15121099/fileData.do
/// - K-Transit (SFI 3 layout): https://github.com/quyen2867/K-Transit
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class KSX6924Reader: @unchecked Sendable {
    public let transport: any ISO7816TagTransporting

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    /// Try all known KS X 6924 AIDs and read the balance from the first match.
    ///
    /// For the shared T-Money / Snapper AID the transaction file is also read, because it is
    /// the only way to tell the two systems (and their currencies) apart.
    open func readBalance() async throws -> TransitBalance {
        try await read(includeTransactions: false)
    }

    /// Read balance + transaction records.
    open func readBalanceAndHistory() async throws -> TransitBalance {
        try await read(includeTransactions: true)
    }

    // MARK: - Steps

    open func read(includeTransactions: Bool) async throws -> TransitBalance {
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
        let tapEvents: [TransitTransaction]
        if isSnapper {
            cardName = "Snapper"
            currencyCode = "NZD"
            transactions = []
            tapEvents = []
        } else {
            cardName = sharesSnapperAID ? "T-Money" : aidName
            currencyCode = "KRW"
            transactions = includeTransactions
                ? records.enumerated().compactMap { Self.parseRecord($0.element, recordNumber: $0.offset + 1) }
                : []
            tapEvents = includeTransactions ? try await readTapEvents() : []
        }
        NFCLog.info(
            "KSX6924 read complete card=\(cardName) balance=\(NFCLog.cardValue(balance)) \(currencyCode) transactions=\(transactions.count) tapEvents=\(tapEvents.count)",
            source: "KSX6924"
        )

        return TransitBalance(
            serialNumber: purseInfo.serial,
            balanceRaw: balance,
            currencyCode: currencyCode,
            cardName: cardName,
            validFrom: purseInfo.issueDate,
            validUntil: purseInfo.expiryDate,
            transactions: transactions,
            tapEvents: tapEvents
        )
    }

    /// Try each known AID until one succeeds. Follow a Hyundai configuration DF's
    /// advertised purse AID before reading. Returns (name, aid, fciResponseData).
    open func selectCard() async throws -> (String, Data, Data) {
        for (name, aid) in KSX6924Constants.allAIDs {
            NFCLog.debug("KSX6924 SELECT AID \(aid.hexString) (\(name))", source: "KSX6924")
            do {
                let response = try await transport.sendAPDUWithChaining(CommandAPDU.select(aid: aid))
                if response.isSuccess {
                    if aid == KSX6924Constants.hyundaiAID,
                        let applicationAID = Self.configuredApplicationAID(response.data),
                        let application = KSX6924Constants.allAIDs.first(where: { $0.aid == applicationAID })
                    {
                        NFCLog.debug("KSX6924 configuration DF selects purse AID \(applicationAID.hexString)", source: "KSX6924")
                        let purseResponse = try await transport.sendAPDUWithChaining(CommandAPDU.select(aid: applicationAID))
                        if purseResponse.isSuccess {
                            return (application.name, applicationAID, purseResponse.data)
                        }
                        continue
                    }
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

    /// A Hyundai configuration DF advertises its purse application in tag `4F`.
    /// Only known purse AIDs are followed, once; an FCI with purse info is already selected.
    open class func configuredApplicationAID(_ fciData: Data) -> Data? {
        guard let nodes = try? ASN1Parser.parseTLV(fciData),
            ASN1Parser.findTag(KSX6924Constants.PURSE_TAG, in: nodes) == nil,
            let aid = ASN1Parser.findTag(0x4F, in: nodes)?.value,
            aid != KSX6924Constants.hyundaiAID,
            KSX6924Constants.allAIDs.contains(where: { $0.aid == aid })
        else { return nil }
        return aid
    }

    open func readRawBalance() async throws -> Int {
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
    open class func readRecordAPDU(recordNumber: UInt8) -> CommandAPDU {
        readRecordAPDU(recordNumber: recordNumber, sfi: KSX6924Constants.transactionSFI)
    }

    /// READ RECORD `00 B2 n (sfi << 3 | 4) 00`: record `n` of `sfi`, Le = 256.
    open class func readRecordAPDU(recordNumber: UInt8, sfi: UInt8) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xB2,
            p1: recordNumber,
            p2: (sfi << 3) | 0x04,
            le: 0x00
        )
    }

    /// Read SFI 4 records until the card reports no further record. Session loss and
    /// cancellation propagate; any other per-record failure ends the record list.
    open func readRecords() async throws -> [Data] {
        try await readRecords(sfi: KSX6924Constants.transactionSFI)
    }

    /// Read the records of `sfi` until the card reports no further record. Session loss and
    /// cancellation propagate; any other per-record failure ends the record list.
    open func readRecords(sfi: UInt8) async throws -> [Data] {
        var records: [Data] = []
        for recordNumber in 1 ... KSX6924Constants.maxRecords {
            try Task.checkCancellation()
            let response: ResponseAPDU
            do {
                response = try await transport.sendAPDUWithChaining(
                    Self.readRecordAPDU(recordNumber: UInt8(recordNumber), sfi: sfi)
                )
            } catch where !isSessionTerminating(error) {
                NFCLog.debug("KSX6924 READ RECORD SFI \(sfi) #\(recordNumber) stopped: \(error.localizedDescription)", source: "KSX6924")
                break
            }
            guard response.isSuccess else {
                NFCLog.debug("KSX6924 READ RECORD SFI \(sfi) #\(recordNumber) end sw=\(String(format: "%04X", response.statusWord))", source: "KSX6924")
                break
            }
            NFCLog.debug("KSX6924 SFI \(sfi) record #\(recordNumber)=\(NFCLog.payload(response.data))", source: "KSX6924")
            records.append(Data(response.data))
        }
        return records
    }

    /// Read SFI 3 and decode its boarding / alighting records. A card without the file
    /// returns no tap events.
    open func readTapEvents() async throws -> [TransitTransaction] {
        try await readRecords(sfi: KSX6924Constants.tapRecordSFI)
            .enumerated()
            .compactMap { Self.parseTapRecord($0.element, recordNumber: $0.offset + 1) }
    }

    /// Metrodroid `SnapperTransitData.check`: every SFI 4 record is 46 bytes with bytes 26..<46
    /// set to 0xFF. An empty record file is not treated as Snapper.
    ///
    /// A T-Money record keeps its BCD date-time at 26..<33 (``KSX6924Constants/recordDateTime``),
    /// so any record with real T-Money trip data already fails the filler test. The type byte
    /// is deliberately not used: Snapper's SFI 4 records also carry type 1 / 2 at byte 0
    /// (Metrodroid `SnapperTransaction.parseTransaction`, 2 = top-up), so rejecting those
    /// values would misreport real Snapper cards as T-Money.
    open class func isSnapper(records: [Data]) -> Bool {
        guard !records.isEmpty else { return false }
        return records.allSatisfy { record in
            let bytes = [UInt8](record)
            return bytes.count == KSX6924Constants.snapperRecordLength
                && bytes[KSX6924Constants.snapperFillerRange].allSatisfy { $0 == 0xFF }
        }
    }

    // MARK: - Parsing

    /// Purse info decoded from the SELECT response FCI (tag 0xB0).
    public struct PurseInfo: Sendable, Equatable {
        public let serial: String
        public let issueDate: Date?
        public let expiryDate: Date?

        public init(serial: String, issueDate: Date?, expiryDate: Date?) {
            self.serial = serial
            self.issueDate = issueDate
            self.expiryDate = expiryDate
        }
    }

    open func parsePurseInfo(_ fciData: Data) -> PurseInfo {
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
    open class func parseBCDDate(_ data: Data) -> Date? {
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
    open class func parseBCDDateTime(_ data: Data) -> Date? {
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
    /// Returns nil for unused slots (all `00` or all `FF`).
    open class func parseRecord(_ data: Data, recordNumber: Int? = nil) -> TransitTransaction? {
        let bytes = [UInt8](data)
        guard bytes.count >= KSX6924Constants.recordMinimumLength,
            !bytes.allSatisfy({ $0 == 0x00 }), !bytes.allSatisfy({ $0 == 0xFF })
        else { return nil }

        func uint32(at offset: Int) -> Int {
            bytes[offset ..< offset + 4].reduce(0) { $0 << 8 | Int($1) }
        }

        let recordType = bytes[KSX6924Constants.recordType]
        let balance = uint32(at: KSX6924Constants.recordBalance)
        let cost = uint32(at: KSX6924Constants.recordCost)
        let dateRange = KSX6924Constants.recordDateTime ..< KSX6924Constants.recordDateTime + KSX6924Constants.recordDateTimeLength
        let date = parseBCDDateTime(Data(bytes[dateRange]))
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

    /// Parse one 52-byte SFI 3 boarding / alighting record.
    ///
    /// Layout (K-Transit and CardBal): byte 2 event (`00` tap on, `01` tap off), bytes 5..<9
    /// station, 9..<11 KOTRIS transport code (BE), 11..<18 date-time (KST), 19..<21 distance
    /// in metres (BE). The fare is in the matching SFI 4 record, so `amount` is nil.
    /// Returns nil for short records and for unused slots (all `00` or all `FF`).
    open class func parseTapRecord(_ data: Data, recordNumber: Int? = nil) -> TransitTransaction? {
        let bytes = [UInt8](data)
        guard bytes.count >= KSX6924Constants.tapRecordLength,
            !bytes.allSatisfy({ $0 == 0x00 }), !bytes.allSatisfy({ $0 == 0xFF })
        else { return nil }

        func uint16(at offset: Int) -> Int {
            Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        }

        let eventCode = bytes[KSX6924Constants.tapEvent]
        let event: TransitTapEvent? =
            switch eventCode {
            case 0x00: .tapOn
            case 0x01: .tapOff
            default: nil
            }
        let modeCode = uint16(at: KSX6924Constants.tapModeCode)
        let stationRange = KSX6924Constants.tapStation ..< KSX6924Constants.tapStation + 4
        let station = Data(bytes[stationRange]).hexString
        let distance = uint16(at: KSX6924Constants.tapDistance)

        return TransitTransaction(
            type: .trip,
            date: parseTapDateTime(data, modeCode: modeCode),
            entryStation: event == .tapOn ? station : nil,
            exitStation: event == .tapOff ? station : nil,
            mode: transitMode(forKOTRISCode: modeCode),
            event: event,
            distanceMeters: event == .tapOff && distance > 0 ? distance : nil,
            recordNumber: recordNumber,
            rawData: Data(bytes),
            metadata: [
                "source": "KSX6924 SFI 3",
                "eventCode": String(format: "%02X", eventCode),
                "station": station,
                "modeCode": String(modeCode),
            ]
        )
    }

    /// Transport mode from KORAIL's table and the supplementary codes documented
    /// in ``KSX6924Constants`` (`R` rail, `B` bus, `T` taxi). Other codes return nil.
    open class func transitMode(forKOTRISCode code: Int) -> TransitMode? {
        if KSX6924Constants.kotrisRailCodes.contains(where: { $0.contains(code) }) { return .rail }
        if KSX6924Constants.kotrisBusCodes.contains(where: { $0.contains(code) }) { return .bus }
        if KSX6924Constants.kotrisTaxiCodes.contains(where: { $0.contains(code) }) { return .taxi }
        return nil
    }

    /// Decode the date-time at bytes 11..<18 of a tap record in Korea Standard Time.
    ///
    /// A strict BCD `YYYYMMDDhhmmss` value (year 20xx) is tried first. Otherwise bytes 11..<15
    /// hold a packed date and time: year since 2000 (7 bits), month (4), day (5), hour (5),
    /// minute (6) and seconds / 2 (5), with the low second bit in bit 7 of byte 15. Codes in
    /// ``KSX6924Constants/bcdOnlyClockModeCodes`` use another clock and get only the BCD form.
    open class func parseTapDateTime(_ record: Data, modeCode: Int) -> Date? {
        let bytes = [UInt8](record)
        let offset = KSX6924Constants.tapDateTime
        guard bytes.count >= offset + 7 else { return nil }

        let bcd = bytes[offset ..< offset + 7]
        if bcd.first == 0x20, bcd.allSatisfy({ $0 >> 4 <= 9 && $0 & 0x0F <= 9 }) {
            let values = bcd.map { Int($0 >> 4) * 10 + Int($0 & 0x0F) }
            if let date = seoulDate(
                year: 2000 + values[1], month: values[2], day: values[3],
                hour: values[4], minute: values[5], second: values[6]
            ) {
                return date
            }
        }
        guard !KSX6924Constants.bcdOnlyClockModeCodes.contains(where: { $0.contains(modeCode) }) else {
            return nil
        }

        let dateWord = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        let timeWord = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
        return seoulDate(
            year: 2000 + (dateWord >> 9),
            month: (dateWord >> 5) & 0x0F,
            day: dateWord & 0x1F,
            hour: timeWord >> 11,
            minute: (timeWord >> 5) & 0x3F,
            second: ((timeWord & 0x1F) << 1) | Int(bytes[offset + 4] >> 7)
        )
    }

    /// A Korea Standard Time date, or nil when a field is out of range or the day does not
    /// exist in that month.
    private static func seoulDate(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int) -> Date? {
        guard (1 ... 12).contains(month), (1 ... 31).contains(day),
            hour <= 23, minute <= 59, second <= 59,
            let timeZone = TimeZone(identifier: "Asia/Seoul")
        else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let components = DateComponents(year: year, month: month, day: day, hour: hour, minute: minute, second: second)
        guard let date = calendar.date(from: components),
            calendar.component(.day, from: date) == day
        else { return nil }
        return date
    }
}
