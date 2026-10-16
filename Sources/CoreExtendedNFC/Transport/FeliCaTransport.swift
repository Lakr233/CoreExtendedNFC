import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCFeliCaTag`.
public final class FeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    private let tag: NFCFeliCaTag
    /// Set by `NFCSessionManager`: once the user cancels the session, failures are
    /// reported as `NFCError.userCanceled`.
    private let terminationMonitor: SessionTerminationMonitor?

    public var identifier: Data {
        tag.currentIDm
    }

    public var systemCode: Data {
        tag.currentSystemCode
    }

    public init(tag: NFCFeliCaTag) {
        self.tag = tag
        terminationMonitor = nil
    }

    init(tag: NFCFeliCaTag, terminationMonitor: SessionTerminationMonitor?) {
        self.tag = tag
        self.terminationMonitor = terminationMonitor
    }

    public func send(_ data: Data) async throws -> Data {
        NFCLog.rawCommand(data, family: .felica, source: "FeliCa")
        let response: Data = try await withNFCErrorMapping(terminationMonitor) {
            try await withCheckedThrowingContinuation { continuation in
                tag.sendFeliCaCommand(commandPacket: data) { response, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: response)
                    }
                }
            }
        }
        NFCLog.rawResponse(response, command: data, family: .felica, source: "FeliCa")
        return response
    }

    public func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("FeliCa does not use ISO 7816 APDUs")
    }

    /// Read blocks without encryption from one or more services.
    public func readWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data]
    ) async throws -> [Data] {
        NFCLog.debug("→ READ_WO_ENC services=\(serviceCodeList.count) blocks=\(blockList.count)", source: "FeliCa")
        let (statusFlag1, statusFlag2, blocks) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.readWithoutEncryption(
                serviceCodeList: serviceCodeList,
                blockList: blockList
            )
        }
        guard statusFlag1 == 0, statusFlag2 == 0 else {
            NFCLog.error("← READ_WO_ENC failed SF1=\(statusFlag1) SF2=\(statusFlag2)", source: "FeliCa")
            throw NFCError.felicaBlockReadFailed(statusFlag: Int(statusFlag1))
        }
        NFCLog.debug("← READ_WO_ENC \(blocks.count) block(s)", source: "FeliCa")
        return blocks
    }

    /// Read blocks without encryption.
    public func readWithoutEncryption(
        serviceCode: Data,
        blockList: [Data]
    ) async throws -> [Data] {
        try await readWithoutEncryption(
            serviceCodeList: [serviceCode],
            blockList: blockList
        )
    }

    /// Write blocks without encryption to one or more services.
    public func writeWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data],
        blockData: [Data]
    ) async throws {
        NFCLog.debug("→ WRITE_WO_ENC services=\(serviceCodeList.count) blocks=\(blockList.count)", source: "FeliCa")
        let (statusFlag1, statusFlag2) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.writeWithoutEncryption(
                serviceCodeList: serviceCodeList,
                blockList: blockList,
                blockData: blockData
            )
        }
        guard statusFlag1 == 0, statusFlag2 == 0 else {
            NFCLog.error("← WRITE_WO_ENC failed SF1=\(statusFlag1) SF2=\(statusFlag2)", source: "FeliCa")
            throw NFCError.felicaBlockWriteFailed(statusFlag: Int(statusFlag1))
        }
        NFCLog.debug("← WRITE_WO_ENC OK", source: "FeliCa")
    }

    /// Write blocks without encryption.
    public func writeWithoutEncryption(
        serviceCode: Data,
        blockList: [Data],
        blockData: [Data]
    ) async throws {
        try await writeWithoutEncryption(
            serviceCodeList: [serviceCode],
            blockList: blockList,
            blockData: blockData
        )
    }

    /// Check whether the requested service codes exist.
    public func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        NFCLog.debug("→ REQUEST_SERVICE nodes=\(nodeCodeList.count)", source: "FeliCa")
        let result = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.requestService(nodeCodeList: nodeCodeList)
        }
        NFCLog.debug("← REQUEST_SERVICE \(result.count) response(s)", source: "FeliCa")
        return result
    }
}
