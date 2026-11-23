import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCFeliCaTag`.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class FeliCaTransport: FeliCaTagTransporting, @unchecked Sendable {
    public let tag: NFCFeliCaTag
    /// Set by `NFCSessionManager`: once the user cancels the session, failures are
    /// reported as `NFCError.userCanceled`.
    public let terminationMonitor: SessionTerminationMonitor?

    open var identifier: Data {
        tag.currentIDm
    }

    open var systemCode: Data {
        tag.currentSystemCode
    }

    public init(tag: NFCFeliCaTag, terminationMonitor: SessionTerminationMonitor? = nil) {
        self.tag = tag
        self.terminationMonitor = terminationMonitor
    }

    open func send(_ data: Data) async throws -> Data {
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

    open func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("FeliCa does not use ISO 7816 APDUs")
    }

    /// Status flag as two hex digits, as the FeliCa manuals list them.
    static func hex(_ flag: Int) -> String {
        String(format: "%02X", flag)
    }

    /// Read blocks without encryption from one or more services.
    ///
    /// A non-zero status throws ``NFCError/felicaBlockReadFailed(statusFlag:)`` with
    /// Status Flag 1; Status Flag 2 (the error detail) is logged with it.
    open func readWithoutEncryption(
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
            NFCLog.error("← READ_WO_ENC failed SF1=\(Self.hex(statusFlag1)) SF2=\(Self.hex(statusFlag2))", source: "FeliCa")
            throw NFCError.felicaBlockReadFailed(statusFlag: Int(statusFlag1))
        }
        NFCLog.debug("← READ_WO_ENC \(blocks.count) block(s)", source: "FeliCa")
        return blocks
    }

    /// Read blocks without encryption.
    open func readWithoutEncryption(
        serviceCode: Data,
        blockList: [Data]
    ) async throws -> [Data] {
        try await readWithoutEncryption(
            serviceCodeList: [serviceCode],
            blockList: blockList
        )
    }

    /// Write blocks without encryption to one or more services.
    ///
    /// A non-zero status throws ``NFCError/felicaBlockWriteFailed(statusFlag:)`` with
    /// Status Flag 1; Status Flag 2 (the error detail) is logged with it.
    open func writeWithoutEncryption(
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
            NFCLog.error("← WRITE_WO_ENC failed SF1=\(Self.hex(statusFlag1)) SF2=\(Self.hex(statusFlag2))", source: "FeliCa")
            throw NFCError.felicaBlockWriteFailed(statusFlag: Int(statusFlag1))
        }
        NFCLog.debug("← WRITE_WO_ENC OK", source: "FeliCa")
    }

    /// Write blocks without encryption.
    open func writeWithoutEncryption(
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
    open func requestService(nodeCodeList: [Data]) async throws -> [Data] {
        NFCLog.debug("→ REQUEST_SERVICE nodes=\(nodeCodeList.count)", source: "FeliCa")
        let result = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.requestService(nodeCodeList: nodeCodeList)
        }
        NFCLog.debug("← REQUEST_SERVICE \(result.count) response(s)", source: "FeliCa")
        return result
    }

    /// List every advertised system without polling or selecting another system.
    open func requestSystemCode() async throws -> [Data] {
        NFCLog.debug("→ REQUEST_SYSTEM_CODE", source: "FeliCa")
        let result = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.requestSystemCode()
        }
        NFCLog.debug("← REQUEST_SYSTEM_CODE \(result.map(\.hexString).joined(separator: ","))", source: "FeliCa")
        return result
    }
}
