import Foundation

/// Reads balance from China T-Union (交通联合) transit cards.
///
/// ## Protocol Overview
/// 1. SELECT T-Union AID (A000000632010105)
/// 2. GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02 → 4 bytes
///    Balance = bits 1-31 as signed integer (CNY fen, divide by 100 for yuan)
/// 3. SELECT file 0x15 + READ BINARY for serial number and validity dates
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
            CommandAPDU.select(aid: TUnionConstants.tUnionAID)
        )
        guard selectResponse.isSuccess else {
            throw NFCError.unsupportedOperation("T-Union AID not found on this card")
        }
        NFCLog.debug("T-Union SELECT AID ok data=\(selectResponse.data.hexString)", source: "TUnion")

        // 2. GET BALANCE. CardBal reads balance slot 0 and slot 1, then uses slot0 - slot1.
        let balance0 = try await readBalanceSlot(p1: TUnionConstants.GET_BALANCE_P1)
        let balance1 = await readOptionalBalanceSlot(p1: TUnionConstants.GET_NEGATIVE_BALANCE_P1)
        let balanceFen = balance0 - balance1
        NFCLog.info("T-Union balance read complete balance0=\(balance0) balance1=\(balance1) final=\(balanceFen)", source: "TUnion")

        // 3. Read file 0x15 for serial and validity
        let fileInfo = await readFileInfo()

        return TransitBalance(
            serialNumber: fileInfo.serial,
            balanceRaw: balanceFen,
            currencyCode: "CNY",
            cardName: "T-Union",
            validFrom: fileInfo.validFrom,
            validUntil: fileInfo.validUntil
        )
    }

    // MARK: - Private

    private struct FileInfo {
        let serial: String
        let validFrom: Date?
        let validUntil: Date?
    }

    private func readBalanceSlot(p1: UInt8) async throws -> Int {
        let response = try await transport.sendAPDUWithChaining(Self.balanceAPDU(p1: p1))
        NFCLog.debug(
            "T-Union GET BALANCE p1=\(String(format: "%02X", p1)) sw=\(String(format: "%02X%02X", response.sw1, response.sw2)) data=\(response.data.hexString)",
            source: "TUnion"
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
            le: TUnionConstants.GET_BALANCE_LE
        )
    }

    static func parseBalanceFen(_ data: Data) -> Int {
        let rawValue = Data(data.prefix(4)).uint32BE
        return Int(rawValue >> 1)
    }

    private func readFileInfo() async -> FileInfo {
        do {
            // SELECT file 0x15
            let selectFile = try await transport.sendAPDUWithChaining(
                CommandAPDU.selectFile(id: TUnionConstants.balanceFileID)
            )
            guard selectFile.isSuccess else {
                return FileInfo(serial: "", validFrom: nil, validUntil: nil)
            }

            // READ BINARY: need at least 28 bytes (offset 0, covers through validity dates)
            let readResponse = try await transport.sendAPDUWithChaining(
                CommandAPDU.readBinary(offset: 0, length: 30)
            )
            guard readResponse.isSuccess, readResponse.data.count >= 28 else {
                return FileInfo(serial: "", validFrom: nil, validUntil: nil)
            }

            let fileData = readResponse.data

            // Serial: bytes 10-19, skip first nibble (convention from Metrodroid)
            let serialData = Data(fileData[TUnionConstants.serialOffset ..< TUnionConstants.serialOffset + TUnionConstants.serialLength])
            let serialHex = serialData.hexString
            let serial = String(serialHex.dropFirst()) // skip first nibble

            // Validity dates: 4 bytes hex YYYYMMDD
            let validFromData = Data(fileData[TUnionConstants.validFromOffset ..< TUnionConstants.validFromOffset + TUnionConstants.validFromLength])
            let validFrom = Self.parseHexDate(validFromData)

            let validUntilData = Data(fileData[TUnionConstants.validUntilOffset ..< TUnionConstants.validUntilOffset + TUnionConstants.validUntilLength])
            let validUntil = Self.parseHexDate(validUntilData)

            return FileInfo(serial: serial, validFrom: validFrom, validUntil: validUntil)
        } catch {
            return FileInfo(serial: "", validFrom: nil, validUntil: nil)
        }
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
}
