import Foundation

/// Reads balance and transaction history from South Korea KS X 6924 transit cards
/// (T-Money, Cashbee, MOIBA, K-Cash).
///
/// ## Protocol Overview
/// 1. SELECT one of the known AIDs (try each until success)
/// 2. Parse FCI for purse info (tag 0xB0) containing serial number and dates
/// 3. GET BALANCE: CLA=0x90 INS=0x4C → 4 bytes big-endian (KRW)
/// 4. GET RECORD: CLA=0x90 INS=0x78 P1=index → 16-byte transaction record
///
/// ## References
/// - KS X 6924 specification
/// - Metrodroid TMoney implementation
public struct KSX6924Reader: Sendable {
    let transport: any ISO7816TagTransporting

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    /// Try all known KS X 6924 AIDs and read balance from the first match.
    public func readBalance() async throws -> TransitBalance {
        let (cardName, fciData) = try await selectCard()
        let purseInfo = parsePurseInfo(fciData)
        let balance = try await readRawBalance()

        return TransitBalance(
            serialNumber: purseInfo.serial,
            balanceRaw: balance,
            currencyCode: "KRW",
            cardName: cardName,
            validFrom: purseInfo.issueDate,
            validUntil: purseInfo.expiryDate
        )
    }

    /// Read balance + transaction records.
    public func readBalanceAndHistory() async throws -> TransitBalance {
        let (cardName, fciData) = try await selectCard()
        let purseInfo = parsePurseInfo(fciData)
        let balance = try await readRawBalance()
        let transactions = await readRecords()

        return TransitBalance(
            serialNumber: purseInfo.serial,
            balanceRaw: balance,
            currencyCode: "KRW",
            cardName: cardName,
            validFrom: purseInfo.issueDate,
            validUntil: purseInfo.expiryDate,
            transactions: transactions
        )
    }

    // MARK: - Private

    /// Try each known AID until one succeeds. Returns (cardName, fciResponseData).
    private func selectCard() async throws -> (String, Data) {
        for (name, aid) in KSX6924Constants.allAIDs {
            let response = try await transport.sendAPDUWithChaining(CommandAPDU.select(aid: aid))
            if response.isSuccess {
                return (name, response.data)
            }
        }
        throw NFCError.unsupportedOperation("No supported KS X 6924 AID found on this card")
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
        guard response.isSuccess, response.data.count >= 4 else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
        return Int(Data(response.data[response.data.startIndex ..< response.data.startIndex + 4]).uint32BE)
    }

    private func readRecords() async -> [TransitTransaction] {
        var transactions: [TransitTransaction] = []

        for i in 0 ..< KSX6924Constants.maxRecords {
            do {
                let apdu = CommandAPDU(
                    cla: KSX6924Constants.CLA,
                    ins: KSX6924Constants.INS_GET_RECORD,
                    p1: UInt8(i),
                    p2: 0x00,
                    le: 0x10
                )
                let response = try await transport.sendAPDUWithChaining(apdu)
                guard response.isSuccess, response.data.count >= 14 else { break }

                if let tx = Self.parseRecord(response.data) {
                    transactions.append(tx)
                }
            } catch {
                break
            }
        }

        return transactions
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

        let purse = purseNode.value

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

    /// Parse a 16-byte transaction record.
    static func parseRecord(_ data: Data) -> TransitTransaction? {
        guard data.count >= 14 else { return nil }

        let recordType = data[data.startIndex + KSX6924Constants.recordType]
        let txType: TransactionType = switch recordType {
        case 2: .topup
        case 1: .trip
        default: .unknown
        }

        let balance = Int(Data(data[data.startIndex + KSX6924Constants.recordBalance ..< data.startIndex + KSX6924Constants.recordBalance + 4]).uint32BE)
        let amount = Int(Data(data[data.startIndex + KSX6924Constants.recordAmount ..< data.startIndex + KSX6924Constants.recordAmount + 4]).uint32BE)

        let dateData = Data(data[data.startIndex + KSX6924Constants.recordDate ..< data.startIndex + KSX6924Constants.recordDate + 4])
        let date = parseBCDDate(dateData)

        return TransitTransaction(
            type: txType,
            amount: amount,
            balanceAfter: balance,
            date: date
        )
    }
}
