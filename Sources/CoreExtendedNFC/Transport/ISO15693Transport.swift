import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCISO15693Tag`.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class ISO15693Transport: ISO15693TagTransporting, @unchecked Sendable {
    public let tag: NFCISO15693Tag
    /// Set by `NFCSessionManager`: once the user cancels the session, failures are
    /// reported as `NFCError.userCanceled`.
    public let terminationMonitor: SessionTerminationMonitor?

    open var identifier: Data {
        tag.identifier
    }

    open var icManufacturerCode: Int {
        tag.icManufacturerCode
    }

    open var icSerialNumber: Data {
        tag.icSerialNumber
    }

    public init(tag: NFCISO15693Tag, terminationMonitor: SessionTerminationMonitor? = nil) {
        self.tag = tag
        self.terminationMonitor = terminationMonitor
    }

    open func send(_ data: Data) async throws -> Data {
        guard let commandByte = data.first else {
            throw NFCError.unsupportedOperation("ISO 15693 raw send requires at least one byte (command code)")
        }
        NFCLog.rawCommand(data, family: .iso15693, source: "ISO15693")
        let commandCode = Int(commandByte)
        // `dropFirst` is startIndex-relative, so sliced input is safe.
        let parameters: Data? = data.count > 1 ? Data(data.dropFirst()) : nil
        let response: Data = try await withNFCErrorMapping(terminationMonitor) {
            try await withCheckedThrowingContinuation { continuation in
                tag.sendRequest(
                    requestFlags: Int(NFCISO15693RequestFlag.highDataRate.rawValue),
                    commandCode: commandCode,
                    data: parameters
                ) { result in
                    switch result {
                    case let .success((_, responseData)):
                        continuation.resume(returning: responseData ?? Data())
                    case let .failure(error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
        NFCLog.rawResponse(response, command: data, family: .iso15693, source: "ISO15693")
        return response
    }

    open func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("ISO 15693 does not use ISO 7816 APDUs")
    }

    /// Read a single block.
    open func readBlock(_ number: UInt8) async throws -> Data {
        NFCLog.debug("→ READ_BLOCK #\(number)", source: "ISO15693")
        let data = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.readSingleBlock(requestFlags: [.highDataRate], blockNumber: number)
        }
        NFCLog.debug("← BLOCK #\(number) \(NFCLog.payload(data))", source: "ISO15693")
        return data
    }

    /// Write a single block.
    open func writeBlock(_ number: UInt8, data: Data) async throws {
        NFCLog.debug("→ WRITE_BLOCK #\(number) \(NFCLog.payload(data))", source: "ISO15693")
        try await withNFCErrorMapping(terminationMonitor) {
            try await tag.writeSingleBlock(
                requestFlags: [.highDataRate],
                blockNumber: number,
                dataBlock: data
            )
        }
        NFCLog.debug("← WRITE_BLOCK #\(number) OK", source: "ISO15693")
    }

    /// Extended read of a single block addressed with a 2-byte block number (command 0x30).
    open func extendedReadBlock(_ number: UInt16) async throws -> Data {
        NFCLog.debug("→ EXT_READ_BLOCK #\(number)", source: "ISO15693")
        let data = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.extendedReadSingleBlock(requestFlags: [.highDataRate], blockNumber: Int(number))
        }
        NFCLog.debug("← EXT_BLOCK #\(number) \(NFCLog.payload(data))", source: "ISO15693")
        return data
    }

    /// Extended write of a single block addressed with a 2-byte block number (command 0x31).
    open func extendedWriteBlock(_ number: UInt16, data: Data) async throws {
        NFCLog.debug("→ EXT_WRITE_BLOCK #\(number) \(NFCLog.payload(data))", source: "ISO15693")
        try await withNFCErrorMapping(terminationMonitor) {
            try await tag.extendedWriteSingleBlock(
                requestFlags: [.highDataRate],
                blockNumber: Int(number),
                dataBlock: data
            )
        }
        NFCLog.debug("← EXT_WRITE_BLOCK #\(number) OK", source: "ISO15693")
    }

    /// Read multiple contiguous blocks.
    open func readBlocks(range: NSRange) async throws -> [Data] {
        NFCLog.debug("→ READ_BLOCKS \(range.location)..\(range.location + range.length - 1)", source: "ISO15693")
        let blocks = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.readMultipleBlocks(requestFlags: [.highDataRate], blockRange: range)
        }
        NFCLog.debug("← READ_BLOCKS \(blocks.count) block(s)", source: "ISO15693")
        return blocks
    }

    /// Get UID, block size, block count, and related system info.
    open func getSystemInfo() async throws -> ISO15693SystemInfo {
        NFCLog.debug("→ GET_SYSTEM_INFO", source: "ISO15693")
        let systemInfo = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.systemInfo(requestFlags: [.highDataRate])
        }
        let info = Self.makeSystemInfo(
            uid: systemInfo.uniqueIdentifier,
            dsfid: systemInfo.dataStorageFormatIdentifier,
            afi: systemInfo.applicationFamilyIdentifier,
            blockSize: systemInfo.blockSize,
            totalBlocks: systemInfo.totalBlocks,
            icReference: systemInfo.icReference
        )
        NFCLog.debug("← SYSTEM_INFO blocks=\(info.blockCount) size=\(info.blockSize)", source: "ISO15693")
        return info
    }

    /// EXTENDED GET SYSTEM INFORMATION (3Bh), sent with `sendRequest` because CoreNFC
    /// has no dedicated call. The request is not addressed (no UID), like ``send(_:)``;
    /// CoreNFC talks to the one connected tag. A response with the error flag set
    /// throws ``NFCError/iso15693Error(code:)``.
    open func extendedGetSystemInfo(infoFlags: UInt8) async throws -> Data {
        NFCLog.debug("→ EXT_GET_SYSTEM_INFO flags=\(String(format: "%02X", infoFlags))", source: "ISO15693")
        let (responseFlags, response): (NFCISO15693ResponseFlag, Data) = try await withNFCErrorMapping(terminationMonitor) {
            try await withCheckedThrowingContinuation { continuation in
                tag.sendRequest(
                    requestFlags: Int(NFCISO15693RequestFlag.highDataRate.rawValue),
                    commandCode: Int(ISO15693ExtendedSystemInfo.commandCode),
                    data: Data([infoFlags])
                ) { result in
                    switch result {
                    case let .success((flags, responseData)):
                        continuation.resume(returning: (flags, responseData ?? Data()))
                    case let .failure(error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
        if responseFlags.contains(.error) {
            throw NFCError.iso15693Error(code: response.first ?? 0)
        }
        NFCLog.debug("← EXT_SYSTEM_INFO \(NFCLog.payload(response))", source: "ISO15693")
        return response
    }

    /// Get locked flags for a range of blocks.
    open func getBlockSecurityStatus(range: NSRange) async throws -> [Bool] {
        let statuses = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.getMultipleBlockSecurityStatus(
                requestFlags: [.highDataRate],
                blockRange: range
            )
        }
        return ISO15693BlockSecurityStatus.lockFlags(from: statuses.map(\.uint8Value))
    }

    open func writeAFI(_ afi: UInt8) async throws {
        try await awaitCompletion { tag.writeAFI(requestFlags: [.highDataRate], afi: afi, completionHandler: $0) }
    }

    /// - Warning: Irreversible: permanently locks the AFI (see ``ISO15693TagTransporting/lockAFI()``).
    open func lockAFI() async throws {
        try await awaitCompletion { tag.lockAFI(requestFlags: [.highDataRate], completionHandler: $0) }
    }

    open func writeDSFID(_ dsfid: UInt8) async throws {
        try await awaitCompletion { tag.writeDSFID(requestFlags: [.highDataRate], dsfid: dsfid, completionHandler: $0) }
    }

    /// - Warning: Irreversible: permanently locks the DSFID (see ``ISO15693TagTransporting/lockDSFID()``).
    open func lockDSFID() async throws {
        try await awaitCompletion { tag.lockDSFID(requestFlags: [.highDataRate], completionHandler: $0) }
    }

    open func customCommand(code: Int, parameters: Data) async throws -> Data {
        try await withNFCErrorMapping(terminationMonitor) {
            try await withCheckedThrowingContinuation { continuation in
                tag.customCommand(
                    requestFlags: [.highDataRate],
                    customCommandCode: code,
                    customRequestParameters: parameters
                ) { result in
                    continuation.resume(with: result)
                }
            }
        }
    }

    open func challenge(cryptoSuiteIdentifier: Int, message: Data) async throws {
        try await withNFCErrorMapping(terminationMonitor) {
            try await tag.challenge(
                requestFlags: [.highDataRate],
                cryptoSuiteIdentifier: cryptoSuiteIdentifier,
                message: message
            )
        }
    }

    open func authenticate(
        cryptoSuiteIdentifier: Int,
        message: Data
    ) async throws -> ISO15693SecurityResponse {
        let (flags, response) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.authenticate(
                requestFlags: [.highDataRate],
                cryptoSuiteIdentifier: cryptoSuiteIdentifier,
                message: message
            )
        }
        return ISO15693SecurityResponse(
            responseFlags: Int(flags.rawValue),
            data: response
        )
    }

    open func keyUpdate(
        keyIdentifier: Int,
        message: Data
    ) async throws -> ISO15693SecurityResponse {
        let (flags, response) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.keyUpdate(
                requestFlags: [.highDataRate],
                keyIdentifier: keyIdentifier,
                message: message
            )
        }
        return ISO15693SecurityResponse(
            responseFlags: Int(flags.rawValue),
            data: response
        )
    }

    /// Bridge a CoreNFC `(Error?) -> Void` completion call to async/await.
    public func awaitCompletion(_ start: (@escaping @Sendable ((any Error)?) -> Void) -> Void) async throws {
        try await withNFCErrorMapping(terminationMonitor) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                start { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            }
        }
    }

    /// Build ``ISO15693SystemInfo`` from CoreNFC's `NFCISO15693SystemInfo` fields.
    ///
    /// ISO/IEC 15693-3 makes DSFID, AFI, memory size and IC reference optional
    /// (Info flags b1–b4), and CoreNFC reports an absent field as `-1`.
    /// Absent byte fields become `nil` (never trapping on `UInt8(-1)`); absent memory
    /// size is normalised to `-1` and rejected by the dump and NDEF paths.
    open class func makeSystemInfo(
        uid: Data,
        dsfid: Int,
        afi: Int,
        blockSize: Int,
        totalBlocks: Int,
        icReference: Int
    ) -> ISO15693SystemInfo {
        ISO15693SystemInfo(
            uid: uid,
            dsfid: UInt8(exactly: dsfid),
            afi: UInt8(exactly: afi),
            blockSize: blockSize > 0 ? blockSize : -1,
            blockCount: totalBlocks > 0 ? totalBlocks : -1,
            icReference: UInt8(exactly: icReference)
        )
    }
}
