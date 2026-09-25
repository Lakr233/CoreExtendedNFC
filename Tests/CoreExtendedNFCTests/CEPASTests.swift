import Foundation
import Testing

// Hand-built CEPAS protocol fixtures, not captures from a physical card.
@testable import CoreExtendedNFC

struct CEPASTests {
    @Test
    func `Reads short history pages using received record offsets`() async throws {
        let debit = Data([0x30, 0xFF, 0xFF, 0x06, 0x00, 0x01, 0x51, 0x80] + Array("BFT-CGA ".utf8))
        let topup = Data([0x03, 0x00, 0x07, 0xD0, 0x00, 0x00, 0x00, 0x00] + Array("TOPUP   ".utf8))
        let bus = Data([0x31, 0xFF, 0xFF, 0x9C, 0x00, 0x00, 0x00, 0x01] + Array("BUS  12 ".utf8))
        let purchase = Data([0x01, 0xFF, 0xFF, 0xFB, 0x00, 0x00, 0x00, 0x02] + Array("SHOP    ".utf8))
        let transport = transport(
            purse: purse(recordCount: 18),
            history: [debit + topup, Data(Array(repeating: Array(bus), count: 15).joined()), purchase]
        )

        let result = try await CoreExtendedNFC.readSingaporeTransitBalance(transport: transport)

        #expect(
            transport.sentAPDUs.map(\.bytes) == [
                Data([0x00, 0xA4, 0x00, 0x00, 0x02, 0x40, 0x00]),
                Data([0x90, 0x32, 0x03, 0x00, 0x00]),
                Data([0x90, 0x32, 0x03, 0x00, 0x01, 0x00, 0xF0]),
                Data([0x90, 0x32, 0x03, 0x00, 0x01, 0x02, 0xF0]),
                Data([0x90, 0x32, 0x03, 0x00, 0x01, 0x11, 0x10]),
            ])
        #expect(result.serialNumber == "1000123456789012")
        #expect(result.cardName == "EZ-Link")
        #expect(result.currencyCode == "SGD")
        #expect(result.balanceRaw == 1250)
        #expect(result.validFrom == Date(timeIntervalSince1970: 789_004_800))
        #expect(result.validUntil == Date(timeIntervalSince1970: 789_091_200))
        #expect(result.transactions.count == 18)
        let trip = try #require(result.transactions.first)
        #expect(trip.type == .trip)
        #expect(trip.amount == 250)
        #expect(trip.balanceAfter == nil)
        #expect(trip.metadata["balanceChange"] == "-250")
        #expect(trip.date == Date(timeIntervalSince1970: 789_004_800))
        #expect(trip.entryStation == "BFT")
        #expect(trip.exitStation == "CGA")
        #expect(trip.rawData == debit)
        let recharge = try #require(result.transactions.dropFirst().first)
        #expect(recharge.type == .topup)
        #expect(recharge.amount == 2000)
        #expect(recharge.metadata["balanceChange"] == "2000")
        let busTrip = try #require(result.transactions.dropFirst(2).first)
        #expect(busTrip.type == .trip)
        #expect(busTrip.metadata["busRoute"] == "12")
        #expect(result.transactions.last?.type == .purchase)
    }

    @Test
    func `Negative balance and empty history preserve issuer identity without reading records`() async throws {
        for (prefix, expectedName) in [(UInt8(0x11), "NETS FlashPay"), (UInt8(0x20), "CEPAS")] {
            var data = purse(recordCount: 0)
            data.replaceSubrange(2 ..< 5, with: [0xFF, 0xFF, 0x83]) // -125 cents
            data.replaceSubrange(8 ..< 10, with: [prefix, 0x10])
            let transport = transport(purse: data)

            let result = try await CEPASReader(transport: transport).readBalanceAndHistory()

            #expect(result.balanceRaw == -125)
            #expect(result.cardName == expectedName)
            #expect(result.transactions.isEmpty)
            #expect(transport.sentAPDUs.count == 2)
        }
    }

    @Test
    func `Unknown records preserve opaque bytes and alternate topups retain their type`() async throws {
        let opaque = Data([0xAB, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0x80, 0, 1, 2, 3, 4, 5])
        let topup = Data([0x75, 0x00, 0x00, 0x64, 0, 0, 0, 0] + Array("TOPUP   ".utf8))
        let transport = transport(purse: purse(recordCount: 2), history: [opaque + topup])

        let result = try await CEPASReader(transport: transport).readBalanceAndHistory()

        let unknown = try #require(result.transactions.first)
        #expect(unknown.type == .unknown)
        #expect(unknown.amount == nil)
        #expect(unknown.metadata["balanceChange"] == nil)
        #expect(unknown.metadata["transactionType"] == "AB")
        #expect(unknown.metadata["userData"] == nil)
        #expect(unknown.rawData == opaque)
        #expect(unknown.entryStation == nil)
        #expect(unknown.exitStation == nil)
        let recharge = try #require(result.transactions.last)
        #expect(recharge.type == .topup)
        #expect(recharge.metadata["transactionType"] == "75")
        #expect(recharge.metadata["userData"]?.trimmingCharacters(in: .whitespaces) == "TOPUP")
    }

    @Test
    func `Creation events do not expose amounts while zero-value purchases remain numeric`() async throws {
        let creation = [UInt8(0x05), 0xF0].map { type in
            Data([type, 0x7F, 0xFF, 0xFF, 0, 0, 0, 0] + Array("NEW CARD".utf8))
        }
        let purchase = Data([0x01, 0, 0, 0, 0, 0, 0, 0] + Array("SHOP    ".utf8))
        let transport = transport(purse: purse(recordCount: 3), history: [creation[0] + creation[1] + purchase])

        let result = try await CEPASReader(transport: transport).readBalanceAndHistory()

        for (transaction, raw) in zip(result.transactions.prefix(2), creation) {
            #expect(transaction.type == .unknown)
            #expect(transaction.amount == nil)
            #expect(transaction.metadata["balanceChange"] == nil)
            #expect(transaction.metadata["transactionType"] == String(format: "%02X", raw[0]))
            #expect(transaction.rawData == raw)
        }
        let zeroValuePurchase = try #require(result.transactions.last)
        #expect(zeroValuePurchase.type == .purchase)
        #expect(zeroValuePurchase.amount == 0)
        #expect(zeroValuePurchase.metadata["balanceChange"] == "0")
    }

    @Test
    func `Optional transaction amounts decode old numeric JSON and retain missing values`() throws {
        let oldJSON = Data(#"{"type":"trip","amount":250,"balanceAfter":244,"metadata":{}}"#.utf8)
        let oldTransaction = try JSONDecoder().decode(TransitTransaction.self, from: oldJSON)
        #expect(oldTransaction.amount == 250)
        #expect(oldTransaction.balanceAfter == 244)

        let newJSON = Data(#"{"type":"unknown","metadata":{"transactionType":"05"}}"#.utf8)
        let newTransaction = try JSONDecoder().decode(TransitTransaction.self, from: newJSON)
        #expect(newTransaction.amount == nil)
        #expect(newTransaction.balanceAfter == nil)
        let restored = try JSONDecoder().decode(TransitTransaction.self, from: JSONEncoder().encode(newTransaction))
        #expect(restored == newTransaction)
    }

    @Test
    func `Truncated and unsupported purses fail before history is read`() async {
        var unsupported = purse(recordCount: 1)
        unsupported[0] = 3
        var truncatedIssuerData = purse(recordCount: 1)
        truncatedIssuerData[41] = 3 // Requires 66 bytes, but this fixture has 65.
        for data in [Data(), Data(repeating: 0, count: 62), unsupported, truncatedIssuerData] {
            let transport = transport(purse: data)

            await #expect(throws: NFCError.self) {
                _ = try await CEPASReader(transport: transport).readBalanceAndHistory()
            }
            #expect(transport.sentAPDUs.count == 2)
        }
    }

    @Test
    func `Malformed history never returns previously read records`() async {
        let record = Data([0x01, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0] + Array("SHOP    ".utf8))
        for malformed in [Data(), Data(repeating: 0, count: 15), Data(repeating: 0, count: 17), record + record] {
            let transport = transport(purse: purse(recordCount: 2), history: [record, malformed])

            await #expect(throws: NFCError.self) {
                _ = try await CEPASReader(transport: transport).readBalanceAndHistory()
            }
            #expect(transport.sentAPDUs.count == 4)
        }
    }

    @Test
    func `Status and transport failures propagate at every stage`() async {
        let record = Data([0x01, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0] + Array("SHOP    ".utf8))
        let responses = transport(purse: purse(recordCount: 2), history: [record, record]).apduResponses
        for failedCall in responses.indices {
            for failWithStatus in [false, true] {
                let transport = MockTransport()
                transport.apduResponses = responses
                if failWithStatus {
                    transport.apduResponses[failedCall] = ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82)
                } else {
                    transport.apduFailures[failedCall] = .tagConnectionLost
                }

                await #expect(throws: NFCError.self) {
                    _ = try await CEPASReader(transport: transport).readBalanceAndHistory()
                }
                #expect(transport.sentAPDUs.count == failedCall + 1)
            }
        }
    }

    @Test
    func `Automatic detection reads CEPAS before selecting another application`() async throws {
        let transport = transport(purse: purse(recordCount: 0))
        let info = CardInfo(type: .smartMX, uid: transport.identifier)

        let result = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)

        #expect(result.cardName == "EZ-Link")
        #expect(result.balanceRaw == 1250)
        #expect(
            transport.sentAPDUs.map(\.bytes) == [
                Data([0x00, 0xA4, 0x00, 0x00, 0x02, 0x40, 0x00]),
                Data([0x90, 0x32, 0x03, 0x00, 0x00]),
            ])
    }

    @Test
    func `Automatic detection continues to Korea when the CEPAS file or command is unsupported`() async throws {
        for rejectedCall in 0 ... 1 {
            let statuses: [UInt16] = [0x6A81, 0x6A82, 0x6D00, 0x6E00] + (rejectedCall == 0 ? [0x6A86] : [])
            for status in statuses {
                let transport = MockTransport()
                let success = ResponseAPDU(data: Data(), sw1: 0x90, sw2: 0x00)
                transport.apduResponses =
                    Array(repeating: success, count: rejectedCall) + [
                        ResponseAPDU(data: Data(), sw1: UInt8(status >> 8), sw2: UInt8(status & 0xFF)),
                        success, // KS X 6924 SELECT
                        ResponseAPDU(data: Data([0, 0, 0x13, 0x88]), sw1: 0x90, sw2: 0x00),
                        ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x83), // No history
                    ]
                let info = CardInfo(type: .smartMX, uid: transport.identifier)

                let result = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)

                #expect(result.currencyCode == "KRW")
                #expect(result.balanceRaw == 5000)
                #expect(transport.sentAPDUs[rejectedCall + 1].data == KSX6924Constants.allAIDs[0].aid)
            }
        }
    }

    @Test
    func `Automatic detection propagates CEPAS transport and operational failures`() async {
        let record = Data([0x01, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0] + Array("SHOP    ".utf8))
        let responses = transport(purse: purse(recordCount: 1), history: [record]).apduResponses
        for failedCall in responses.indices {
            let statuses: [UInt16?] = [nil, 0x6700, 0x6982] + (failedCall > 0 ? [0x6A86] : []) + (failedCall == 2 ? [0x6A82] : [])
            for status in statuses {
                let transport = MockTransport()
                transport.apduResponses = responses
                if let status {
                    transport.apduResponses[failedCall] = ResponseAPDU(data: Data(), sw1: UInt8(status >> 8), sw2: UInt8(status & 0xFF))
                } else {
                    transport.apduFailures[failedCall] = .tagConnectionLost
                }
                let info = CardInfo(type: .smartMX, uid: transport.identifier)

                await #expect(throws: NFCError.self) {
                    _ = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
                }
                #expect(transport.sentAPDUs.count == failedCall + 1)
            }
        }
    }

    @Test
    func `Automatic detection does not hide malformed or unsupported CEPAS purses`() async {
        var unsupported = purse(recordCount: 0)
        unsupported[0] = 3
        for data in [Data(), Data(repeating: 0, count: 62), unsupported] {
            let transport = transport(purse: data)
            let info = CardInfo(type: .smartMX, uid: transport.identifier)

            await #expect(throws: NFCError.self) {
                _ = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
            }
            #expect(transport.sentAPDUs.count == 2)
        }
    }

    private func purse(recordCount: UInt8) -> Data {
        var data = Data(repeating: 0, count: 65)
        data[0] = 2
        data[1] = 1
        data.replaceSubrange(2 ..< 5, with: [0x00, 0x04, 0xE2])
        data.replaceSubrange(8 ..< 16, with: [0x10, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12])
        data.replaceSubrange(16 ..< 24, with: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        data.replaceSubrange(24 ..< 28, with: [0x00, 0x02, 0x00, 0x01])
        data[40] = recordCount
        data[41] = 2
        data[42] = 0x12
        data[43] = 0x34
        data[64] = 0xFF
        return data
    }

    private func transport(purse: Data, history: [Data] = []) -> MockTransport {
        let transport = MockTransport()
        transport.apduResponses = ([Data(), purse] + history).map { ResponseAPDU(data: $0, sw1: 0x90, sw2: 0x00) }
        return transport
    }
}
