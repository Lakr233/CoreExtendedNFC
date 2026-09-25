import Foundation

/// Experimental read-only reader for traditional CEPAS purse 3 and its recent log.
///
/// iOS tag discovery and physical-card compatibility remain unverified. SimplyGo
/// account-based history is not supported. Call before application-refinement probes.
public struct CEPASReader: Sendable {
    private let transport: any ISO7816TagTransporting
    // CEPAS timestamps start at 1995-01-01 00:00 in Singapore (UTC+08:00).
    private static let epoch = Date(timeIntervalSince1970: 788_918_400)

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    public func readBalanceAndHistory() async throws -> TransitBalance {
        NFCLog.info("Experimental CEPAS read start; initial AID=\(transport.initialAID)", source: "CEPAS")
        _ = try await read(
            CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x00, p2: 0x00, data: Data([0x40, 0x00])),
            stage: "SELECT 4000"
        )
        // Some legacy cards require 90 32 03 00 00 00, which Core NFC rejects.
        // This experimental path uses the standard five-byte form; no silent fallback.
        let purse = try await read(CommandAPDU(cla: 0x90, ins: 0x32, p1: 0x03, p2: 0x00, le: 0x00), stage: "GET PURSE")
        guard purse.count >= 63, purse.count >= 63 + Int(purse[41]) else {
            throw NFCError.invalidResponse(purse)
        }
        guard purse[0] == 2 else {
            throw NFCError.unsupportedOperation("Unsupported CEPAS purse version \(purse[0])")
        }

        let serial = Data(purse[8 ..< 16]).hexString
        let cardName: String
        switch serial.prefix(3) {
        case "100": cardName = "EZ-Link"
        case "111": cardName = "NETS FlashPay"
        default: cardName = "CEPAS"
        }
        let count = Int(purse[40])
        var transactions: [TransitTransaction] = []
        while transactions.count < count {
            let offset = transactions.count
            let requestedCount = min(15, count - offset)
            let page = try await read(
                CommandAPDU(cla: 0x90, ins: 0x32, p1: 0x03, p2: 0x00, data: Data([UInt8(offset)]), le: UInt8(requestedCount * 16)),
                stage: "GET HISTORY offset=\(offset) count=\(requestedCount)"
            )
            guard !page.isEmpty, page.count.isMultiple(of: 16), page.count <= requestedCount * 16 else {
                throw NFCError.invalidResponse(page)
            }
            for start in stride(from: 0, to: page.count, by: 16) {
                transactions.append(Self.transaction(Data(page[start ..< start + 16]), recordNumber: transactions.count + 1))
            }
        }
        NFCLog.info("CEPAS read complete; records=\(transactions.count)", source: "CEPAS")
        return TransitBalance(
            serialNumber: serial,
            balanceRaw: Self.signedAmount(Data(purse[2 ..< 5])),
            currencyCode: "SGD",
            cardName: cardName,
            validFrom: Self.epoch.addingTimeInterval(Double(Data(purse[26 ..< 28]).uint16BE) * 86_400),
            validUntil: Self.epoch.addingTimeInterval(Double(Data(purse[24 ..< 26]).uint16BE) * 86_400),
            transactions: transactions,
            metadata: [
                "purseID": "3",
                "purseVersion": String(purse[0]),
                "purseStatus": String(format: "%02X", purse[1]),
                "cardSerialNumber": Data(purse[16 ..< 24]).hexString,
                "recordCount": String(count),
            ]
        )
    }

    private func read(_ command: CommandAPDU, stage: String) async throws -> Data {
        NFCLog.debug(stage, source: "CEPAS")
        let response = try await transport.sendAPDUWithChaining(command)
        guard response.isSuccess else {
            NFCLog.error("\(stage) failed; SW=\(String(format: "%04X", response.statusWord))", source: "CEPAS")
            if response.statusWord == 0x6700 {
                NFCLog.error("Card rejected the APDU length; legacy six-byte GET PURSE encoding is unavailable in Core NFC", source: "CEPAS")
            }
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
        return Data(response.data)
    }

    private static func signedAmount(_ bytes: Data) -> Int {
        let value = bytes.reduce(0) { ($0 << 8) | Int($1) }
        return value & 0x80_0000 == 0 ? value : value - 0x100_0000
    }

    private static func transaction(_ record: Data, recordNumber: Int) -> TransitTransaction {
        let type: TransactionType
        switch record[0] {
        case 0x30, 0x31: type = .trip
        case 0x03, 0x75: type = .topup
        case 0x01: type = .purchase
        default: type = .unknown
        }
        let change = signedAmount(Data(record[1 ..< 4]))
        var metadata = ["transactionType": String(format: "%02X", record[0]), "balanceChange": String(change)]
        var entry: String?
        var exit: String?
        let userData = Data(record[8 ..< 16])
        if userData.allSatisfy({ $0 == 0 || (0x20 ... 0x7E).contains($0) }), let text = String(data: userData, encoding: .ascii) {
            metadata["userData"] = text.trimmingCharacters(in: .whitespaces.union(.controlCharacters))
            let characters = Array(text)
            if record[0] == 0x30, characters[3] == "-" || characters[3] == " " {
                let from = String(characters[0 ..< 3]).trimmingCharacters(in: .whitespaces)
                let to = String(characters[4 ..< 7]).trimmingCharacters(in: .whitespaces)
                entry = from.isEmpty ? nil : from
                exit = to.isEmpty ? nil : to
            } else if record[0] == 0x31, text.hasPrefix("BUS") || text.hasPrefix("SVC") {
                metadata["busRoute"] = String(characters[3 ..< 7]).replacingOccurrences(of: " ", with: "")
            }
        }
        return TransitTransaction(
            type: type,
            amount: abs(change),
            date: epoch.addingTimeInterval(Double(Data(record[4 ..< 8]).uint32BE)),
            entryStation: entry,
            exitStation: exit,
            recordNumber: recordNumber,
            rawData: record,
            metadata: metadata
        )
    }
}
