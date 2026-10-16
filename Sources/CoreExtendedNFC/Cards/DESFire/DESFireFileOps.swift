import Foundation

/// DESFire file types.
public enum DESFireFileType: UInt8, Sendable {
    case standardData = 0x00
    case backupData = 0x01
    case valueFile = 0x02
    case linearRecord = 0x03
    case cyclicRecord = 0x04
    /// Transaction MAC file (EV2/EV3, MF3D(H)x2/x3). Holds TMC (4) ‖ TMV (8).
    case transactionMAC = 0x05
}

/// DESFire file settings parsed from GET_FILE_SETTINGS response.
public struct DESFireFileSettings: Sendable {
    public let fileType: DESFireFileType
    public let communicationSettings: UInt8
    public let accessRights: UInt16
    public let fileSize: UInt32 // for data files
    public let recordSize: UInt32? // for record files
    public let maxRecords: UInt32? // for record files
    public let currentRecords: UInt32? // for record files

    public init(data: Data) throws {
        // Common header: FileType ‖ FileOption ‖ AccessRights (2).
        guard data.count >= 4 else {
            throw NFCError.invalidResponse(data)
        }
        let d = Array(data)
        guard let ft = DESFireFileType(rawValue: d[0]) else {
            throw NFCError.invalidResponse(data)
        }
        // Every type except the Transaction MAC file carries at least a 3-byte
        // size / record-size field after the header.
        guard ft == .transactionMAC || data.count >= 7 else {
            throw NFCError.invalidResponse(data)
        }
        fileType = ft
        communicationSettings = d[1]
        accessRights = UInt16(d[2]) | UInt16(d[3]) << 8

        switch fileType {
        case .transactionMAC:
            // TMAC settings carry TMKeyOption / key version instead of a size;
            // the file content is TMC (4 bytes) ‖ TMV (8 bytes).
            fileSize = 12
            recordSize = nil
            maxRecords = nil
            currentRecords = nil

        case .standardData, .backupData:
            fileSize = UInt32(d[4]) | UInt32(d[5]) << 8 | UInt32(d[6]) << 16
            recordSize = nil
            maxRecords = nil
            currentRecords = nil

        case .valueFile:
            fileSize = 4 // value is always 4 bytes
            recordSize = nil
            maxRecords = nil
            currentRecords = nil

        case .linearRecord, .cyclicRecord:
            guard data.count >= 13 else {
                throw NFCError.invalidResponse(data)
            }
            recordSize = UInt32(d[4]) | UInt32(d[5]) << 8 | UInt32(d[6]) << 16
            maxRecords = UInt32(d[7]) | UInt32(d[8]) << 8 | UInt32(d[9]) << 16
            currentRecords = UInt32(d[10]) | UInt32(d[11]) << 8 | UInt32(d[12]) << 16
            // recordSize and maxRecords are 24-bit each, so the product can
            // exceed UInt32 on a malformed answer; reject instead of trapping.
            let (total, overflow) = (recordSize ?? 0)
                .multipliedReportingOverflow(by: maxRecords ?? 0)
            guard !overflow else {
                throw NFCError.invalidResponse(data)
            }
            fileSize = total
        }
    }
}

public extension DESFireCommands {
    /// GET_FILE_SETTINGS: Get settings for a specific file.
    func getFileSettings(_ fileID: UInt8) async throws -> DESFireFileSettings {
        let data = try await sendCommand(Self.GET_FILE_SETTINGS, data: Data([fileID]))
        return try DESFireFileSettings(data: data)
    }

    /// READ_DATA: Read data from a standard or backup data file.
    func readData(fileID: UInt8, offset: UInt32 = 0, length: UInt32 = 0) async throws -> Data {
        let payload = try desfireRangePayload(
            fileID: fileID,
            firstValue: offset,
            firstLabel: "offset",
            secondValue: length,
            secondLabel: "length"
        )
        return try await sendCommand(Self.READ_DATA, data: payload)
    }

    /// READ_RECORDS: Read records from a linear or cyclic record file.
    func readRecords(fileID: UInt8, offset: UInt32 = 0, count: UInt32 = 0) async throws -> Data {
        let payload = try desfireRangePayload(
            fileID: fileID,
            firstValue: offset,
            firstLabel: "offset",
            secondValue: count,
            secondLabel: "count"
        )
        return try await sendCommand(Self.READ_RECORDS, data: payload)
    }

    /// GET_VALUE: Read value from a value file.
    func getValue(fileID: UInt8) async throws -> Int32 {
        let data = try await sendCommand(Self.GET_VALUE, data: Data([fileID]))
        return try Self.decodeDESFireValue(data)
    }

    /// Decode a plain GET_VALUE payload: exactly 4 bytes, signed little-endian.
    static func decodeDESFireValue(_ data: Data) throws -> Int32 {
        guard data.count == 4 else {
            throw NFCError.invalidResponse(data)
        }
        return Int32(bitPattern: data.uint32LE)
    }
}

public extension DESFireCommands {
    func desfireRangePayload(
        fileID: UInt8,
        firstValue: UInt32,
        firstLabel: String,
        secondValue: UInt32,
        secondLabel: String
    ) throws -> Data {
        var payload = Data([fileID])
        try payload.append(desfireUInt24(firstValue, label: firstLabel))
        try payload.append(desfireUInt24(secondValue, label: secondLabel))
        return payload
    }

    func desfireUInt24(_ value: UInt32, label: String) throws -> Data {
        guard value <= 0x00FF_FFFF else {
            throw NFCError.invalidParameter(
                "DESFire \(label) must fit in 3 bytes (0x000000...0xFFFFFF)"
            )
        }

        return Data([
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value >> 16),
        ])
    }
}
