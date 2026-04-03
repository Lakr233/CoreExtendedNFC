@testable import CoreExtendedNFC
import Foundation

/// Shared mock FeliCa transport for unit testing FeliCa-based card commands.
final class MockFeliCaServiceTransport: FeliCaTagTransporting, @unchecked Sendable {
    let identifier: Data
    let systemCode: Data
    let serviceVersions: [Data: Data]
    let serviceBlocks: [Data: [Data]]
    var readLog: [[String]] = []

    init(
        serviceVersions: [Data: Data],
        serviceBlocks: [Data: [Data]] = [:],
        systemCode: Data = Data([0x12, 0xFC]),
        identifier: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    ) {
        self.serviceVersions = serviceVersions
        self.serviceBlocks = serviceBlocks
        self.systemCode = systemCode
        self.identifier = identifier
    }

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readWithoutEncryption(serviceCodeList: [Data], blockList: [Data]) async throws -> [Data] {
        guard blockList.count == serviceCodeList.count else {
            throw NFCError.invalidResponse(Data())
        }

        let requestLog = try zip(serviceCodeList, blockList).map { serviceCode, element in
            let blockNumber = try parseBlockNumber(element)
            return "\(serviceCode.hexString):\(blockNumber)"
        }
        readLog.append(requestLog)

        return try zip(serviceCodeList, blockList).map { serviceCode, element in
            let blockNumber = try parseBlockNumber(element)
            let serviceIndex = try parseServiceIndex(element)
            guard serviceCodeList[serviceIndex] == serviceCode else {
                throw NFCError.invalidResponse(element)
            }

            let blocks = serviceBlocks[serviceCode] ?? []
            guard blockNumber < blocks.count else {
                throw NFCError.felicaBlockReadFailed(statusFlag: 0xA1)
            }
            return blocks[blockNumber]
        }
    }

    func readWithoutEncryption(serviceCode: Data, blockList: [Data]) async throws -> [Data] {
        try await readWithoutEncryption(
            serviceCodeList: Array(repeating: serviceCode, count: blockList.count),
            blockList: blockList
        )
    }

    func writeWithoutEncryption(serviceCode _: Data, blockList _: [Data], blockData _: [Data]) async throws {}

    func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        nodeCodeList.map { serviceVersions[$0] ?? Data([0xFF, 0xFF]) }
    }

    private func parseBlockNumber(_ element: Data) throws -> Int {
        switch element.count {
        case 2:
            return Int(element[1])
        case 3:
            return Int(element[1]) << 8 | Int(element[2])
        default:
            throw NFCError.invalidResponse(element)
        }
    }

    private func parseServiceIndex(_ element: Data) throws -> Int {
        switch element.count {
        case 2, 3:
            return Int(element[0] & 0x0F)
        default:
            throw NFCError.invalidResponse(element)
        }
    }
}
