import Foundation

/// Type 4 Capability Container parsed from CC file.
///
/// NFC Forum T4T 2.0/3.0 §5.1. Mapping 2.0 uses the NDEF File Control TLV
/// (T = 04h, L = 06h, 2-byte max size, NLEN prefix of 2 bytes). Mapping 3.0 may
/// instead use the Extended NDEF File Control TLV (T = 06h, L = 08h, 4-byte max
/// size), in which case the NDEF file starts with a 4-byte ENLEN.
public struct Type4CC: Sendable {
    /// CC file length.
    public let ccLen: UInt16
    /// Mapping version.
    public let mappingVersion: UInt8
    /// Maximum R-APDU data size (MLe).
    public let mle: UInt16
    /// Maximum C-APDU data size (MLc).
    public let mlc: UInt16
    /// NDEF file control TLV — file ID.
    public let ndefFileID: Data
    /// Maximum NDEF file size, clamped to 16 bits.
    /// See ``maxNDEFFileSize`` for the full value of an Extended NDEF File Control TLV.
    public let ndefMaxSize: UInt16
    /// Maximum NDEF file size (including the NLEN/ENLEN field).
    public let maxNDEFFileSize: UInt32
    /// Whether the CC carries an Extended NDEF File Control TLV (T = 06h),
    /// meaning the NDEF file starts with a 4-byte ENLEN instead of a 2-byte NLEN.
    public let usesExtendedNDEFFile: Bool
    /// Read access: 0x00 = free.
    public let readAccess: UInt8
    /// Write access: 0x00 = free, 0xFF = denied.
    public let writeAccess: UInt8

    /// Size of the NLEN (2) or ENLEN (4) field at the start of the NDEF file.
    public var ndefLengthFieldSize: Int {
        usesExtendedNDEFFile ? 4 : 2
    }

    /// Parse a CC file (15 bytes for an NDEF File Control TLV, 17 bytes for an
    /// Extended NDEF File Control TLV).
    public init(data: Data) throws {
        guard data.count >= 15 else {
            throw NFCError.invalidResponse(data)
        }
        let d = Array(data)
        ccLen = UInt16(d[0]) << 8 | UInt16(d[1])
        mappingVersion = d[2]
        mle = UInt16(d[3]) << 8 | UInt16(d[4])
        mlc = UInt16(d[5]) << 8 | UInt16(d[6])

        // A reader must not use a mapping whose major version it does not support.
        guard mappingVersion >> 4 <= 3 else {
            throw NFCError.invalidResponse(data)
        }
        // T4T §5.1 requires MLe >= 000Fh and MLc >= 0001h; zero values would
        // stall chunked transfers.
        guard mle > 0, mlc > 0 else {
            throw NFCError.invalidResponse(data)
        }

        switch (d[7], d[8]) {
        case (0x04, 0x06):
            // NDEF File Control TLV
            ndefFileID = Data([d[9], d[10]])
            let size = UInt16(d[11]) << 8 | UInt16(d[12])
            ndefMaxSize = size
            maxNDEFFileSize = UInt32(size)
            usesExtendedNDEFFile = false
            readAccess = d[13]
            writeAccess = d[14]
        case (0x06, 0x08) where mappingVersion >> 4 == 3 && d.count >= 17:
            // Extended NDEF File Control TLV (T4T 3.0)
            ndefFileID = Data([d[9], d[10]])
            let size = UInt32(d[11]) << 24 | UInt32(d[12]) << 16 | UInt32(d[13]) << 8 | UInt32(d[14])
            ndefMaxSize = UInt16(clamping: size)
            maxNDEFFileSize = size
            usesExtendedNDEFFile = true
            readAccess = d[15]
            writeAccess = d[16]
        default:
            throw NFCError.invalidResponse(data)
        }
    }

    /// CC file bytes re-encoded from the parsed fields.
    public var encoded: Data {
        var data = Data([
            UInt8((ccLen >> 8) & 0xFF), UInt8(ccLen & 0xFF),
            mappingVersion,
            UInt8((mle >> 8) & 0xFF), UInt8(mle & 0xFF),
            UInt8((mlc >> 8) & 0xFF), UInt8(mlc & 0xFF),
        ])
        if usesExtendedNDEFFile {
            data.append(contentsOf: [0x06, 0x08])
            data.append(ndefFileID)
            data.append(contentsOf: [
                UInt8((maxNDEFFileSize >> 24) & 0xFF), UInt8((maxNDEFFileSize >> 16) & 0xFF),
                UInt8((maxNDEFFileSize >> 8) & 0xFF), UInt8(maxNDEFFileSize & 0xFF),
            ])
        } else {
            data.append(contentsOf: [0x04, 0x06])
            data.append(ndefFileID)
            data.append(contentsOf: [UInt8((ndefMaxSize >> 8) & 0xFF), UInt8(ndefMaxSize & 0xFF)])
        }
        data.append(contentsOf: [readAccess, writeAccess])
        return data
    }

    /// Encode an NDEF file body: the NLEN (2 bytes) or ENLEN (4 bytes)
    /// big-endian length followed by the message.
    public func encodeNDEFFile(_ message: Data) -> Data {
        var data = Data()
        for shift in stride(from: (ndefLengthFieldSize - 1) * 8, through: 0, by: -8) {
            data.append(UInt8((message.count >> shift) & 0xFF))
        }
        data.append(message)
        return data
    }
}

/// Type 4 NDEF tag reader.
/// Ported from libnfc examples/nfc-emulate-forum-tag4.c.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class Type4Reader: @unchecked Sendable {
    public let transport: any NFCTagTransport

    /// AID of the NDEF Tag Application selected by the last
    /// ``readCapabilityContainer()``: ``Type4Constants/ndefAID`` or, on a T4T
    /// mapping 1.0 tag, ``Type4Constants/ndefAIDVersion1``.
    public var selectedApplicationAID: Data {
        selectedAID.withLock { $0 }
    }

    private let selectedAID = LockedValue(Type4Constants.ndefAID)

    /// Highest file offset expressible in READ/UPDATE BINARY with P1 b8 = 0
    /// (ISO/IEC 7816-4). Larger offsets need the odd-INS variants.
    public static let maxShortFileOffset = 0x7FFF

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    /// Full NDEF read sequence:
    /// SELECT AID → SELECT CC → READ CC → SELECT NDEF → READ NDEF.
    open func readNDEF() async throws -> Data {
        NFCLog.info("Type 4 NDEF read", source: "Type4")
        let cc = try await readCapabilityContainer()

        try await selectFile(cc.ndefFileID)

        // Read NLEN (2 bytes) or ENLEN (4 bytes).
        let headerLength = cc.ndefLengthFieldSize
        let lenResp = try await transport.sendAPDU(
            CommandAPDU.readBinary(offset: 0, length: UInt8(headerLength))
        )
        guard lenResp.isSuccess else {
            throw NFCError.unexpectedStatusWord(lenResp.sw1, lenResp.sw2)
        }
        let header = [UInt8](lenResp.data)
        guard header.count >= headerLength else {
            throw NFCError.invalidResponse(lenResp.data)
        }
        let ndefLen = header.prefix(headerLength).reduce(0) { $0 << 8 | Int($1) }
        guard ndefLen > 0 else { return Data() }

        // T4T §5.1: NLEN must fit in the NDEF file (NLEN <= max size - 2).
        guard ndefLen <= Int(cc.maxNDEFFileSize) - headerLength else {
            throw NFCError.invalidResponse(lenResp.data)
        }
        NFCLog.debug("NDEF length=\(ndefLen), reading in chunks (MLe=\(cc.mle))", source: "Type4")

        let maxRead = min(Int(cc.mle), 255)
        var ndefData = Data()
        var offset = headerLength

        while ndefData.count < ndefLen {
            try Task.checkCancellation()
            guard offset <= Self.maxShortFileOffset else {
                throw NFCError.unsupportedOperation("Type 4 NDEF files larger than 32 KB are not supported")
            }
            let readSize = min(ndefLen - ndefData.count, maxRead)
            let readAPDU = CommandAPDU.readBinary(offset: UInt16(offset), length: UInt8(readSize))
            let resp = try await transport.sendAPDU(readAPDU)
            guard resp.isSuccess else {
                throw NFCError.unexpectedStatusWord(resp.sw1, resp.sw2)
            }
            // A success response without data makes no progress and would loop forever.
            guard !resp.data.isEmpty else {
                throw NFCError.invalidResponse(resp.data)
            }
            let chunk = resp.data.prefix(readSize)
            ndefData.append(chunk)
            offset += chunk.count
        }

        return ndefData
    }

    /// Read and parse the Capability Container.
    ///
    /// Selects the NDEF Tag Application D2760000850101 and, when the card refuses
    /// it, the mapping 1.0 application D2760000850100 (as nfcpy `tt4.py` does);
    /// files of a mapping 1.0 application are then selected with P2 = 00h.
    /// Throws ``NFCError/tagNotNDEFFormatted`` when the card has neither (SELECT
    /// answered `6A82` file not found or `6A86` incorrect P1-P2).
    open func readCapabilityContainer() async throws -> Type4CC {
        let aidResp = try await transport.sendAPDU(CommandAPDU.select(aid: Type4Constants.ndefAID))
        if aidResp.isSuccess {
            selectedAID.withLock { $0 = Type4Constants.ndefAID }
        } else {
            // Mapping 1.0 SELECT carries no Le (nfcpy tt4.py).
            let legacySelect = CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: Type4Constants.ndefAIDVersion1)
            let legacyResp = try await transport.sendAPDU(legacySelect)
            guard legacyResp.isSuccess else {
                if aidResp.sw1 == 0x6A, aidResp.sw2 == 0x82 || aidResp.sw2 == 0x86 {
                    throw NFCError.tagNotNDEFFormatted
                }
                throw NFCError.unexpectedStatusWord(aidResp.sw1, aidResp.sw2)
            }
            NFCLog.debug("Selected the T4T mapping 1.0 NDEF application", source: "Type4")
            selectedAID.withLock { $0 = Type4Constants.ndefAIDVersion1 }
        }

        try await selectFile(Type4Constants.ccFileID)

        let readCC = CommandAPDU.readBinary(offset: 0, length: 15)
        let ccResp = try await transport.sendAPDU(readCC)
        guard ccResp.isSuccess else {
            throw NFCError.unexpectedStatusWord(ccResp.sw1, ccResp.sw2)
        }

        var ccData = Data(ccResp.data)
        let ccBytes = [UInt8](ccData)
        if ccBytes.count == 15, ccBytes[7] == 0x06 {
            // Extended NDEF File Control TLV: the CC is 17 bytes long.
            let tailResp = try await transport.sendAPDU(CommandAPDU.readBinary(offset: 15, length: 2))
            guard tailResp.isSuccess else {
                throw NFCError.unexpectedStatusWord(tailResp.sw1, tailResp.sw2)
            }
            ccData.append(tailResp.data)
        }

        return try Type4CC(data: ccData)
    }

    /// Write NDEF message to Type 4 tag.
    ///
    /// Follows the T4T NDEF write procedure: NLEN / ENLEN is written as zero, then
    /// the message, then the real length, each UPDATE BINARY carrying at most MLc
    /// bytes. The final length update is atomic only when MLc covers the whole
    /// length field (MLc ≥ 2 for NLEN, ≥ 4 for ENLEN). A card announcing a smaller
    /// MLc gets the length in several UPDATE BINARY commands, so a write interrupted
    /// between them can leave a length mixing old and new bytes; such cards are
    /// still written, without that guarantee.
    open func writeNDEF(_ message: Data) async throws {
        NFCLog.info("Type 4 NDEF write: \(message.count) bytes", source: "Type4")
        let cc = try await readCapabilityContainer()

        guard cc.writeAccess == 0x00 else {
            throw NFCError.tagLocked
        }
        let headerLength = cc.ndefLengthFieldSize
        guard message.count + headerLength <= Int(cc.maxNDEFFileSize) else {
            throw NFCError.ndefCapacityExceeded(
                required: message.count + headerLength,
                capacity: Int(cc.maxNDEFFileSize)
            )
        }
        guard message.count + headerLength <= Self.maxShortFileOffset + 1 else {
            throw NFCError.unsupportedOperation("Type 4 NDEF files larger than 32 KB are not supported")
        }

        try await selectFile(cc.ndefFileID)

        // Every UPDATE BINARY, including the NLEN/ENLEN header, carries at most MLc
        // bytes (T4T §5.1.3); MLc may be as small as 1.
        let maxWrite = min(Int(cc.mlc), 255)

        // Write NLEN/ENLEN = 0 first (marks the write as in progress).
        try await updateBinaryChunked(offset: 0, data: Data(repeating: 0x00, count: headerLength), maxWrite: maxWrite)

        try await updateBinaryChunked(offset: headerLength, data: message, maxWrite: maxWrite)

        // Write the real NLEN/ENLEN last.
        try await updateBinaryChunked(
            offset: 0,
            data: Data(cc.encodeNDEFFile(message).prefix(headerLength)),
            maxWrite: maxWrite
        )
    }

    /// UPDATE BINARY `data` at `offset` in chunks of at most `maxWrite` bytes.
    open func updateBinaryChunked(offset: Int, data: Data, maxWrite: Int) async throws {
        var offset = offset
        var remaining = data[...]
        while !remaining.isEmpty {
            try Task.checkCancellation()
            let chunk = Data(remaining.prefix(maxWrite))
            try await updateBinary(offset: offset, data: chunk)
            remaining = remaining.dropFirst(chunk.count)
            offset += chunk.count
        }
    }

    /// SELECT FILE by 2-byte file ID in the currently selected application.
    /// P2 is 0Ch (no response data), or 00h in a mapping 1.0 application.
    open func selectFile(_ fileID: Data) async throws {
        var command = CommandAPDU.selectFile(id: fileID)
        if selectedApplicationAID == Type4Constants.ndefAIDVersion1 {
            command = CommandAPDU(cla: command.cla, ins: command.ins, p1: command.p1, p2: 0x00, data: fileID)
        }
        let response = try await transport.sendAPDU(command)
        guard response.isSuccess else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
    }

    /// One UPDATE BINARY at a short (15-bit) file offset.
    open func updateBinary(offset: Int, data: Data) async throws {
        guard offset <= Self.maxShortFileOffset, let fileOffset = UInt16(exactly: offset) else {
            throw NFCError.unsupportedOperation("Type 4 NDEF files larger than 32 KB are not supported")
        }
        let response = try await transport.sendAPDU(CommandAPDU.updateBinary(offset: fileOffset, data: data))
        guard response.isSuccess else {
            // 6982 security status not satisfied / 6985 conditions of use not satisfied:
            // the NDEF file is write-protected even though the CC said otherwise.
            if response.sw1 == 0x69, response.sw2 == 0x82 || response.sw2 == 0x85 {
                throw NFCError.tagLocked
            }
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
    }
}
