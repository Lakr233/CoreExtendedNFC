import Foundation

/// NTAG 424 DNA native file commands in CommMode.Plain (NXP NT4H2421Gx datasheet).
///
/// Commands use the ISO/IEC 7816-4 wrapping shared with DESFire,
/// `[0x90, CMD, 0x00, 0x00, LEN, DATA..., 0x00]`, and the NDEF application
/// (`D2760000850101`) must already be selected, as it is when iOS connects with
/// that AID first in `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
/// or after a Type 4 NDEF read.
///
/// Only plain, unauthenticated framing is implemented: no CommMode.MAC / Full,
/// no EV2 command counter and no response MAC verification. Inside an
/// authenticated session the card appends a MAC to MAC-protected responses, which
/// ``NTAG424FileSettings`` rejects as trailing bytes.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class NTAG424Commands: @unchecked Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    // MARK: - Command Codes

    /// GetFileSettings.
    public static let GET_FILE_SETTINGS: UInt8 = 0xF5
    /// WriteData (NTAG 424 DNA native `8Dh`, not the DESFire `3Dh`).
    public static let WRITE_DATA: UInt8 = 0x8D

    // MARK: - Limits

    /// Largest file number: FileNo bits 4-0.
    public static let maxFileID: UInt8 = 0x1F
    /// Largest 24-bit offset or length value.
    public static let maxUInt24: UInt32 = 0x00FF_FFFF
    /// WriteData header: FileNo (1) ‖ Offset (3) ‖ Length (3).
    public static let writeDataHeaderLength = 7
    /// Largest data chunk per WriteData that keeps the command a short APDU
    /// (Lc ≤ 255 including the 7-byte header).
    public static let maxWriteChunkSize = 255 - writeDataHeaderLength
    /// Default data bytes per WriteData command.
    public static let defaultWriteChunkSize = 128

    // MARK: - Commands

    /// GetFileSettings (`F5h`) for `fileID`, parsed strictly.
    open func getFileSettings(fileID: UInt8) async throws -> NTAG424FileSettings {
        try Self.validateFileID(fileID)
        let data = try await DESFireCommands(transport: transport)
            .sendCommand(Self.GET_FILE_SETTINGS, data: Data([fileID]))
        return try NTAG424FileSettings(data: data)
    }

    /// WriteData (`8Dh`) in CommMode.Plain.
    ///
    /// `data` is split into WriteData commands of at most `chunkSize` bytes, each
    /// with its own 3-byte little-endian offset and length, sent in order. Every
    /// command must be answered `91 00`; a failure stops the write and earlier
    /// chunks stay written. Arguments are checked before anything is sent:
    /// `fileID` must be `0x00...0x1F`, `data` must not be empty, `offset + data.count`
    /// must not exceed 2^24, and `chunkSize` must be `1...maxWriteChunkSize`.
    open func writeDataPlain(
        fileID: UInt8,
        offset: UInt32,
        data: Data,
        chunkSize: Int = NTAG424Commands.defaultWriteChunkSize
    ) async throws {
        let frames = try Self.writeDataPlainPayloads(
            fileID: fileID,
            offset: offset,
            data: data,
            chunkSize: chunkSize
        )
        let desfire = DESFireCommands(transport: transport)
        for payload in frames {
            try Task.checkCancellation()
            let response = try await transport.sendAPDU(
                CommandAPDU.desfireWrap(command: Self.WRITE_DATA, data: payload)
            )
            try desfire.validateDESFireStatus(response, expected: .operationOK)
        }
    }

    // MARK: - Payload Construction

    /// The WriteData command data for each chunk:
    /// `FileNo ‖ Offset (3, LE) ‖ Length (3, LE) ‖ Data`.
    open class func writeDataPlainPayloads(
        fileID: UInt8,
        offset: UInt32,
        data: Data,
        chunkSize: Int = NTAG424Commands.defaultWriteChunkSize
    ) throws -> [Data] {
        try validateFileID(fileID)
        guard !data.isEmpty else {
            throw NFCError.invalidParameter("NTAG 424 WriteData needs at least one byte")
        }
        guard (1 ... maxWriteChunkSize).contains(chunkSize) else {
            throw NFCError.invalidParameter(
                "NTAG 424 WriteData chunk size must be 1...\(maxWriteChunkSize)"
            )
        }
        guard offset <= maxUInt24 else {
            throw NFCError.invalidParameter("NTAG 424 offset must fit in 3 bytes (0x000000...0xFFFFFF)")
        }
        guard UInt64(offset) + UInt64(data.count) <= UInt64(maxUInt24) + 1 else {
            throw NFCError.invalidParameter("NTAG 424 offset + length must not exceed 0x1000000")
        }

        let bytes = [UInt8](data)
        var payloads: [Data] = []
        var position = 0
        while position < bytes.count {
            let end = min(position + chunkSize, bytes.count)
            var payload = Data([fileID])
            payload.append(uint24LE(offset + UInt32(position)))
            payload.append(uint24LE(UInt32(end - position)))
            payload.append(contentsOf: bytes[position ..< end])
            payloads.append(payload)
            position = end
        }
        return payloads
    }

    /// Encode the low 24 bits of `value` little-endian.
    public static func uint24LE(_ value: UInt32) -> Data {
        Data([
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
        ])
    }

    /// Throw `invalidParameter` for a file number above ``maxFileID``.
    public static func validateFileID(_ fileID: UInt8) throws {
        guard fileID <= maxFileID else {
            throw NFCError.invalidParameter("NTAG 424 file number must be 0x00...0x1F")
        }
    }
}
