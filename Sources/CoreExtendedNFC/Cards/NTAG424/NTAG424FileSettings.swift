import Foundation

/// File settings of an NTAG 424 DNA file, parsed from a plain GetFileSettings (`F5h`)
/// response (NXP NT4H2421Gx datasheet, GetFileSettings).
///
/// Layout:
///
/// ```
/// FileType (1) ‖ FileOption (1) ‖ AccessRights (2) ‖ FileSize (3, LE)
/// [ SDMOptions (1) ‖ SDMAccessRights (2)
///   ‖ UIDOffset (3)         if SDMOptions.uid and SDMMetaRead == Eh
///   ‖ SDMReadCtrOffset (3)  if SDMOptions.readCounter and SDMMetaRead == Eh
///   ‖ PICCDataOffset (3)    if SDMMetaRead is a key (0h...4h)
///   ‖ SDMMACInputOffset (3) if SDMFileRead != Fh
///   ‖ SDMENCOffset (3)      if SDMOptions.encryptedFileData and SDMFileRead != Fh
///   ‖ SDMENCLength (3)      if SDMOptions.encryptedFileData and SDMFileRead != Fh
///   ‖ SDMMACOffset (3)      if SDMFileRead != Fh
///   ‖ SDMReadCtrLimit (3)   if SDMOptions.readCounterLimit ]   only when FileOption bit 6 is set
/// ```
///
/// The parser is strict: a truncated response, trailing bytes (for example the
/// 8-byte response MAC of an authenticated session, which this parser does not
/// verify), a file type other than StandardData, or an SDMMetaRead value that is
/// neither a key number, `Eh` nor `Fh` throws ``NFCError/invalidResponse(_:)``.
public struct NTAG424FileSettings: Sendable, Equatable {
    /// The only file type NTAG 424 DNA supports: StandardData.
    public static let standardDataFileType: UInt8 = 0x00

    /// FileOption bit 6: Secure Dynamic Messaging (SDM) and mirroring enabled.
    public static let sdmEnabledBit: UInt8 = 0x40

    /// Communication mode, FileOption bits 1-0.
    public enum CommunicationMode: Sendable, Equatable {
        /// `00b` (and `10b`): plain.
        case plain
        /// `01b`: MACed.
        case mac
        /// `11b`: fully enciphered.
        case full

        /// Decode FileOption bits 1-0.
        public init(fileOption: UInt8) {
            switch fileOption & 0x03 {
            case 0x01: self = .mac
            case 0x03: self = .full
            default: self = .plain
            }
        }
    }

    /// The meaning of one 4-bit access condition nibble.
    public enum AccessCondition: Sendable, Equatable {
        /// `0h...4h`: granted after authenticating with this application key.
        case key(UInt8)
        /// `Eh`: free access.
        case free
        /// `Fh`: no access.
        case never
        /// `5h...Dh`: reserved for future use.
        case reserved(UInt8)

        public init(nibble: UInt8) {
            let value = nibble & 0x0F
            switch value {
            case 0x00 ... 0x04: self = .key(value)
            case 0x0E: self = .free
            case 0x0F: self = .never
            default: self = .reserved(value)
            }
        }
    }

    /// File access rights, sent least significant byte first.
    /// Bits 15-12 Read, 11-8 Write, 7-4 ReadWrite, 3-0 Change.
    public struct AccessRights: Sendable, Equatable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Read access nibble (bits 15-12).
        public var read: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 12) & 0x0F }
        /// Write access nibble (bits 11-8).
        public var write: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 8) & 0x0F }
        /// ReadWrite access nibble (bits 7-4).
        public var readWrite: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 4) & 0x0F }
        /// Change (ChangeFileSettings) access nibble (bits 3-0).
        public var change: UInt8 { UInt8(truncatingIfNeeded: rawValue) & 0x0F }

        public var readCondition: AccessCondition { AccessCondition(nibble: read) }
        public var writeCondition: AccessCondition { AccessCondition(nibble: write) }
        public var readWriteCondition: AccessCondition { AccessCondition(nibble: readWrite) }
        public var changeCondition: AccessCondition { AccessCondition(nibble: change) }
    }

    /// SDMOptions bits.
    public struct SDMOptions: OptionSet, Sendable, Equatable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Bit 7: UID mirroring.
        public static let uid = SDMOptions(rawValue: 0x80)
        /// Bit 6: SDMReadCtr mirroring.
        public static let readCounter = SDMOptions(rawValue: 0x40)
        /// Bit 5: SDMReadCtrLimit enabled.
        public static let readCounterLimit = SDMOptions(rawValue: 0x20)
        /// Bit 4: SDMENCFileData (encrypted file data mirroring).
        public static let encryptedFileData = SDMOptions(rawValue: 0x10)
        /// Bit 0: ASCII encoding of mirrored data.
        public static let asciiEncoding = SDMOptions(rawValue: 0x01)
    }

    /// SDM access rights, sent least significant byte first.
    /// Bits 15-12 SDMMetaRead, 11-8 SDMFileRead, 7-4 RFU, 3-0 SDMCtrRet
    /// (AN12196 decodes the bytes `F1 21` as RFU Fh, SDMCtrRet 1h, SDMMetaRead 2h,
    /// SDMFileRead 1h).
    public struct SDMAccessRights: Sendable, Equatable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// SDMMetaRead (bits 15-12): `Eh` plain PICC data mirroring, `0h...4h`
        /// encrypted PICC data with that key, `Fh` no PICC data mirroring.
        public var metaRead: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 12) & 0x0F }
        /// SDMFileRead (bits 11-8): `0h...4h` SDM MAC (and encryption) key, `Fh` no SUN MAC.
        public var fileRead: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 8) & 0x0F }
        /// Reserved nibble (bits 7-4).
        public var reserved: UInt8 { UInt8(truncatingIfNeeded: rawValue >> 4) & 0x0F }
        /// SDMCtrRet (bits 3-0): access condition for GetFileCounters.
        public var counterRetrieval: UInt8 { UInt8(truncatingIfNeeded: rawValue) & 0x0F }
    }

    /// The SDM extension present when FileOption bit 6 is set.
    /// Offsets and lengths are 24-bit values; absent fields are `nil`.
    public struct SDMSettings: Sendable, Equatable {
        public let options: SDMOptions
        public let accessRights: SDMAccessRights
        public let uidOffset: UInt32?
        public let readCounterOffset: UInt32?
        public let piccDataOffset: UInt32?
        public let macInputOffset: UInt32?
        public let encryptedDataOffset: UInt32?
        public let encryptedDataLength: UInt32?
        public let macOffset: UInt32?
        public let readCounterLimit: UInt32?
    }

    /// FileType byte (always ``standardDataFileType``).
    public let fileType: UInt8
    /// Raw FileOption byte.
    public let fileOption: UInt8
    /// Communication mode from FileOption bits 1-0.
    public let communicationMode: CommunicationMode
    public let accessRights: AccessRights
    /// File size in bytes (24-bit).
    public let fileSize: UInt32
    /// SDM settings, or `nil` when SDM is disabled.
    public let sdm: SDMSettings?

    /// `true` when FileOption bit 6 (SDM and mirroring) is set.
    public var isSDMEnabled: Bool {
        sdm != nil
    }

    /// Parse a plain GetFileSettings response payload (status word removed).
    public init(data: Data) throws {
        var reader = NTAG424ByteReader(bytes: [UInt8](data), source: data)

        let fileType = try reader.uint8()
        guard fileType == Self.standardDataFileType else {
            throw NFCError.invalidResponse(data)
        }
        self.fileType = fileType
        fileOption = try reader.uint8()
        communicationMode = CommunicationMode(fileOption: fileOption)
        accessRights = try AccessRights(rawValue: reader.uint16LE())
        fileSize = try reader.uint24LE()

        if fileOption & Self.sdmEnabledBit != 0 {
            let options = try SDMOptions(rawValue: reader.uint8())
            let sdmRights = try SDMAccessRights(rawValue: reader.uint16LE())

            let metaRead = sdmRights.metaRead
            let plainMirroring: Bool
            let encryptedPICCData: Bool
            switch metaRead {
            case 0x0E:
                plainMirroring = true
                encryptedPICCData = false
            case 0x00 ... 0x04:
                plainMirroring = false
                encryptedPICCData = true
            case 0x0F:
                plainMirroring = false
                encryptedPICCData = false
            default:
                // RFU SDMMetaRead value: the layout of the trailing fields is undefined.
                throw NFCError.invalidResponse(data)
            }
            let fileReadEnabled = sdmRights.fileRead != 0x0F
            let encryptedFileData = options.contains(.encryptedFileData) && fileReadEnabled

            let uidOffset = try (options.contains(.uid) && plainMirroring) ? reader.uint24LE() : nil
            let readCounterOffset = try (options.contains(.readCounter) && plainMirroring) ? reader.uint24LE() : nil
            let piccDataOffset = try encryptedPICCData ? reader.uint24LE() : nil
            let macInputOffset = try fileReadEnabled ? reader.uint24LE() : nil
            let encOffset = try encryptedFileData ? reader.uint24LE() : nil
            let encLength = try encryptedFileData ? reader.uint24LE() : nil
            let macOffset = try fileReadEnabled ? reader.uint24LE() : nil
            let readCounterLimit = try options.contains(.readCounterLimit) ? reader.uint24LE() : nil

            sdm = SDMSettings(
                options: options,
                accessRights: sdmRights,
                uidOffset: uidOffset,
                readCounterOffset: readCounterOffset,
                piccDataOffset: piccDataOffset,
                macInputOffset: macInputOffset,
                encryptedDataOffset: encOffset,
                encryptedDataLength: encLength,
                macOffset: macOffset,
                readCounterLimit: readCounterLimit
            )
        } else {
            sdm = nil
        }

        guard reader.isAtEnd else {
            throw NFCError.invalidResponse(data)
        }
    }
}

/// Bounds-checked little-endian reader; every overrun throws `invalidResponse`.
private struct NTAG424ByteReader {
    let bytes: [UInt8]
    let source: Data
    var index = 0

    var isAtEnd: Bool {
        index == bytes.count
    }

    mutating func take(_ count: Int) throws -> ArraySlice<UInt8> {
        guard count <= bytes.count - index else {
            throw NFCError.invalidResponse(source)
        }
        defer { index += count }
        return bytes[index ..< index + count]
    }

    mutating func uint8() throws -> UInt8 {
        let byte = try take(1)
        return byte[byte.startIndex]
    }

    mutating func uint16LE() throws -> UInt16 {
        let b = try Array(take(2))
        return UInt16(b[0]) | UInt16(b[1]) << 8
    }

    mutating func uint24LE() throws -> UInt32 {
        let b = try Array(take(3))
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16
    }
}
