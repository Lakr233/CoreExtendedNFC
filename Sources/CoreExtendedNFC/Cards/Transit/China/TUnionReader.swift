import Foundation

/// Reads balance from China T-Union (交通联合) transit cards.
///
/// ## Protocol Overview
/// 1. SELECT T-Union AID (A000000632010105)
/// 2. GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02 → 4 bytes
///    Balance = low 31 bits of a big-endian UInt32 in CNY fen, divide by 100 for yuan.
/// 3. SELECT file 0x15 + READ BINARY for serial number and validity dates.
/// 4. READ RECORD from SFI 0x18 and 0x1E for recent transactions/trips.
///
/// ## iOS Scope
/// - T-Union branded cards with the full AID work on iOS.
/// - Beijing Yikatong uses a short AID outside iOS CoreNFC's selectable AID path.
///
/// ## References
/// - Metrodroid ChinaTransitData
/// - NFSee
public struct TUnionReader: Sendable {
    let transport: any ISO7816TagTransporting

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    /// Read T-Union card balance and info.
    public func readBalance() async throws -> TransitBalance {
        NFCLog.info("T-Union balance read start", source: "TUnion")
        // 1. SELECT T-Union AID
        let selectResponse = try await transport.sendAPDUWithChaining(
            CommandAPDU.select(aid: TUnionConstants.tUnionAID),
        )
        guard selectResponse.isSuccess else {
            throw NFCError.unsupportedOperation("T-Union AID not found on this card")
        }
        NFCLog.debug("T-Union SELECT AID ok data=\(selectResponse.data.hexString)", source: "TUnion")

        // 2. GET BALANCE. T-Union exposes two purse registers; the displayed
        // value is the signed delta between the primary and negative purse.
        let balance0 = try await readBalanceSlot(p1: TUnionConstants.GET_BALANCE_P1)
        let balance1 = await readOptionalBalanceSlot(p1: TUnionConstants.GET_NEGATIVE_BALANCE_P1)
        let balanceFen = Self.displayBalance(primary: balance0, negative: balance1)
        NFCLog.info("T-Union balance read complete balance0=\(balance0) balance1=\(balance1) final=\(balanceFen)", source: "TUnion")

        // 3. Read file 0x15 for serial and validity
        let fileInfo = await readFileInfo()
        let transactions = await readTransactions()

        return TransitBalance(
            serialNumber: fileInfo.serial,
            balanceRaw: balanceFen,
            currencyCode: "CNY",
            cardName: "T-Union",
            validFrom: fileInfo.validFrom,
            validUntil: fileInfo.validUntil,
            transactions: transactions,
            metadata: [
                "balanceSource": "TUnion dual purse",
                "primaryPurseFen": "\(balance0)",
                "negativePurseFen": "\(balance1)",
                "fileInfoSource": fileInfo.source,
            ],
        )
    }

    // MARK: - Private

    private struct FileInfo {
        let serial: String
        let validFrom: Date?
        let validUntil: Date?
        let source: String
    }

    private func readBalanceSlot(p1: UInt8) async throws -> Int {
        let response = try await transport.sendAPDUWithChaining(Self.balanceAPDU(p1: p1))
        NFCLog.debug(
            "T-Union GET BALANCE p1=\(String(format: "%02X", p1)) sw=\(String(format: "%02X%02X", response.sw1, response.sw2)) data=\(response.data.hexString)",
            source: "TUnion",
        )
        guard response.isSuccess, response.data.count >= 4 else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }

        return Self.parseBalanceFen(response.data)
    }

    private func readOptionalBalanceSlot(p1: UInt8) async -> Int {
        do {
            return try await readBalanceSlot(p1: p1)
        } catch {
            NFCLog.debug("T-Union optional balance slot p1=\(String(format: "%02X", p1)) skipped: \(error.localizedDescription)", source: "TUnion")
            return 0
        }
    }

    private static func balanceAPDU(p1: UInt8) -> CommandAPDU {
        CommandAPDU(
            cla: TUnionConstants.GET_BALANCE_CLA,
            ins: TUnionConstants.GET_BALANCE_INS,
            p1: p1,
            p2: TUnionConstants.GET_BALANCE_P2,
            le: TUnionConstants.GET_BALANCE_LE,
        )
    }

    static func parseBalanceFen(_ data: Data) -> Int {
        let rawValue = Data(data.prefix(4)).uint32BE
        return Int(rawValue & 0x7FFF_FFFF)
    }

    static func displayBalance(primary: Int, negative: Int) -> Int {
        primary - negative
    }

    private func readFileInfo() async -> FileInfo {
        do {
            // SELECT file 0x15
            let selectFile = try await transport.sendAPDUWithChaining(
                Self.selectFileAPDU(id: TUnionConstants.balanceFileID),
            )
            NFCLog.debug("T-Union SELECT file 0015 sw=\(String(format: "%02X%02X", selectFile.sw1, selectFile.sw2)) data=\(selectFile.data.hexString)", source: "TUnion")
            guard selectFile.isSuccess else {
                return await readFileInfoFromSFI()
            }

            // READ BINARY: need at least 28 bytes (offset 0, covers through validity dates)
            let readResponse = try await transport.sendAPDUWithChaining(
                CommandAPDU.readBinary(offset: 0, length: 30),
            )
            NFCLog.debug("T-Union READ BINARY 0015 sw=\(String(format: "%02X%02X", readResponse.sw1, readResponse.sw2)) data=\(readResponse.data.hexString)", source: "TUnion")
            guard readResponse.isSuccess, readResponse.data.count >= 28 else {
                return await readFileInfoFromSFI()
            }

            return Self.parseFileInfo(readResponse.data, source: "SELECT 0015 + READ BINARY")
        } catch {
            return await readFileInfoFromSFI()
        }
    }

    private static func selectFileAPDU(id: Data) -> CommandAPDU {
        CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x00, p2: 0x00, data: id, le: 0x00)
    }

    private func readFileInfoFromSFI() async -> FileInfo {
        do {
            let response = try await transport.sendAPDUWithChaining(Self.readFile15BySFIAPDU())
            NFCLog.debug("T-Union READ BINARY SFI 15 sw=\(String(format: "%02X%02X", response.sw1, response.sw2)) data=\(response.data.hexString)", source: "TUnion")
            guard response.isSuccess, response.data.count >= 28 else {
                return FileInfo(serial: "", validFrom: nil, validUntil: nil, source: "unavailable")
            }
            return Self.parseFileInfo(response.data, source: "SFI 15 READ BINARY")
        } catch {
            NFCLog.debug("T-Union READ BINARY SFI 15 skipped: \(error.localizedDescription)", source: "TUnion")
            return FileInfo(serial: "", validFrom: nil, validUntil: nil, source: "unavailable")
        }
    }

    private static func readFile15BySFIAPDU() -> CommandAPDU {
        CommandAPDU(cla: 0x00, ins: 0xB0, p1: TUnionConstants.file15SFIReadP1, p2: 0x00, le: 0x00)
    }

    private static func parseFileInfo(_ fileData: Data, source: String) -> FileInfo {
        // Serial: bytes 10-19, skip first nibble (convention from Metrodroid)
        let serialData = Data(fileData[TUnionConstants.serialOffset ..< TUnionConstants.serialOffset + TUnionConstants.serialLength])
        let serialHex = serialData.hexString
        let serial = String(serialHex.dropFirst()) // skip first nibble

        // Validity dates: 4 bytes hex YYYYMMDD
        let validFromData = Data(fileData[TUnionConstants.validFromOffset ..< TUnionConstants.validFromOffset + TUnionConstants.validFromLength])
        let validFrom = Self.parseHexDate(validFromData)

        let validUntilData = Data(fileData[TUnionConstants.validUntilOffset ..< TUnionConstants.validUntilOffset + TUnionConstants.validUntilLength])
        let validUntil = Self.parseHexDate(validUntilData)

        return FileInfo(serial: serial, validFrom: validFrom, validUntil: validUntil, source: source)
    }

    private static func readRecordAPDU(sfi: UInt8, recordNumber: UInt8, length: UInt8) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xB2,
            p1: recordNumber,
            p2: (sfi << 3) | 0x04,
            le: length,
        )
    }

    private func readTransactions() async -> [TransitTransaction] {
        let transactions = await readRecords(
            sfi: TUnionConstants.transactionSFI,
            length: TUnionConstants.transactionRecordLength,
            maxRecords: TUnionConstants.maxTransactionRecords,
            parser: Self.parseTransactionRecord,
        )
        let trips = await readRecords(
            sfi: TUnionConstants.transitActivitySFI,
            length: TUnionConstants.transitActivityRecordLength,
            maxRecords: TUnionConstants.maxTransitActivityRecords,
            parser: Self.parseTransitActivityRecord,
        )
        let merged = (transactions + trips).sorted { lhs, rhs in
            switch (lhs.date, rhs.date) {
            case let (left?, right?):
                left > right
            case (_?, nil):
                true
            case (nil, _?):
                false
            case (nil, nil):
                (lhs.recordNumber ?? 0) < (rhs.recordNumber ?? 0)
            }
        }
        NFCLog.info("T-Union records read complete transactions=\(transactions.count) trips=\(trips.count)", source: "TUnion")
        return merged
    }

    private func readRecords(
        sfi: UInt8,
        length: UInt8,
        maxRecords: Int,
        parser: (Data, Int) -> TransitTransaction?,
    ) async -> [TransitTransaction] {
        var records: [TransitTransaction] = []
        for recordNumber in 1 ... maxRecords {
            do {
                let apdu = Self.readRecordAPDU(sfi: sfi, recordNumber: UInt8(recordNumber), length: length)
                let response = try await transport.sendAPDUWithChaining(apdu)
                NFCLog.debug(
                    "T-Union READ RECORD sfi=\(String(format: "%02X", sfi)) record=\(recordNumber) sw=\(String(format: "%02X%02X", response.sw1, response.sw2)) data=\(response.data.hexString)",
                    source: "TUnion",
                )
                guard response.isSuccess else {
                    if response.statusWord == 0x6A83 || response.statusWord == 0x6A82 {
                        break
                    }
                    continue
                }
                if response.data.allSatisfy({ $0 == 0x00 }) {
                    continue
                }
                if let record = parser(response.data, recordNumber) {
                    records.append(record)
                }
            } catch {
                NFCLog.debug("T-Union record read stopped sfi=\(String(format: "%02X", sfi)) record=\(recordNumber): \(error.localizedDescription)", source: "TUnion")
                break
            }
        }
        return records
    }

    static func parseTransactionRecord(_ data: Data, recordNumber: Int) -> TransitTransaction? {
        guard data.count >= Int(TUnionConstants.transactionRecordLength) else { return nil }
        let amount = Int(Data(data[TUnionConstants.transactionAmountOffset ..< TUnionConstants.transactionAmountOffset + TUnionConstants.transactionAmountLength]).uint32BE)
        let transactionType = data[TUnionConstants.transactionTypeOffset]
        let dateBytes = Data(data[TUnionConstants.transactionDateTimeOffset ..< TUnionConstants.transactionDateTimeOffset + TUnionConstants.transactionDateTimeLength])
        if amount == 0, dateBytes.allSatisfy({ $0 == 0x00 }) {
            return nil
        }

        let isTopUp = transactionType == TUnionConstants.topUpType
        let station = Data(data[TUnionConstants.transactionStationOffset ..< TUnionConstants.transactionStationOffset + TUnionConstants.transactionStationLength]).hexString
        let signedAmount = isTopUp ? amount : -amount
        return TransitTransaction(
            type: isTopUp ? .topup : .purchase,
            amount: signedAmount,
            balanceAfter: 0,
            date: parseBCDDateTime(dateBytes),
            entryStation: station,
            exitStation: nil,
            recordNumber: recordNumber,
            rawData: data,
            metadata: [
                "source": "TUnion SFI 18",
                "transactionType": String(format: "%02X", transactionType),
                "station": station,
            ],
        )
    }

    static func parseTransitActivityRecord(_ data: Data, recordNumber: Int) -> TransitTransaction? {
        guard data.count >= Int(TUnionConstants.transitActivityRecordLength) else { return nil }
        if data.allSatisfy({ $0 == 0x00 }) {
            return nil
        }
        return TransitTransaction(
            type: .trip,
            amount: 0,
            balanceAfter: 0,
            date: nil,
            entryStation: nil,
            exitStation: nil,
            recordNumber: recordNumber,
            rawData: data,
            metadata: [
                "source": "TUnion SFI 1E",
                "raw": data.hexString,
            ],
        )
    }

    /// Parse a 4-byte hex-encoded date (YYYYMMDD) into a Date.
    static func parseHexDate(_ data: Data) -> Date? {
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
        components.timeZone = TimeZone(identifier: "Asia/Shanghai")
        return Calendar(identifier: .gregorian).date(from: components)
    }

    static func parseBCDDateTime(_ data: Data) -> Date? {
        guard data.count >= TUnionConstants.transactionDateTimeLength else { return nil }
        let values = data.prefix(7).map { byte -> Int in
            Int((byte >> 4) & 0x0F) * 10 + Int(byte & 0x0F)
        }
        let year = values[0] * 100 + values[1]
        let month = values[2]
        let day = values[3]
        let hour = values[4]
        let minute = values[5]
        let second = values[6]
        guard year > 0, month >= 1, month <= 12, day >= 1, day <= 31,
              hour <= 23, minute <= 59, second <= 59
        else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        components.timeZone = TimeZone(identifier: "Asia/Shanghai")
        return Calendar(identifier: .gregorian).date(from: components)
    }
}
