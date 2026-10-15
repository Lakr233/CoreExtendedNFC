import Foundation

enum NDEFTagMapping {
    /// Extract the NDEF message from Type 2 pages.
    ///
    /// NFC Forum T2T 1.0 §6.4.1 NDEF detection: the tag is only in NDEF state
    /// when CC0 (page 3 byte 0) is E1h and the mapping major version (CC1 b7-b4)
    /// is at most 1. The TLV scan is limited to the data area size CC2 × 8.
    static func extractType2Message(from pages: [MemoryDump.Page]) -> Data? {
        guard let ccPage = pages.first(where: { $0.number == 3 }), ccPage.data.count >= 4 else {
            return nil
        }
        let cc = [UInt8](ccPage.data)
        guard cc[0] == 0xE1, cc[1] >> 4 <= 1 else { return nil }
        let dataAreaSize = Int(cc[2]) * 8

        let payload = pages
            .sorted(by: { $0.number < $1.number })
            .filter { $0.number >= 4 }
            .reduce(into: Data()) { result, page in
                result.append(page.data)
            }
        return extractTLVNDEF(from: Data(payload.prefix(dataAreaSize)))
    }

    /// Extract the NDEF message from Type 5 blocks.
    ///
    /// NFC Forum T5T 1.0 §4.3.1: when CC byte 2 (MLEN) is 00h the CC is 8 bytes
    /// long (bytes 6-7 carry the 16-bit MLEN) and the TLV area starts at byte 8;
    /// otherwise the CC is 4 bytes.
    static func extractType5Message(from blocks: [MemoryDump.Block]) -> Data? {
        let contiguous = blocks
            .sorted(by: { $0.number < $1.number })
            .reduce(into: Data()) { result, block in
                result.append(block.data)
            }
        let bytes = [UInt8](contiguous)

        guard bytes.count >= 4 else { return nil }
        guard bytes[0] == 0xE1 || bytes[0] == 0xE2 else { return nil }

        let ccLength = bytes[2] == 0x00 ? 8 : 4
        guard bytes.count >= ccLength else { return nil }

        return extractTLVNDEF(from: Data(bytes[ccLength...]))
    }

    /// Build the 4-byte Capability Container for a Type 2 tag (page 3).
    ///
    /// Layout: `[0xE1, version, size, access]`
    /// - Byte 0: NDEF magic number (0xE1)
    /// - Byte 1: Mapping version 1.0 (0x10)
    /// - Byte 2: Memory size in 8-byte units
    /// - Byte 3: Read/write access (0x00 = read-write)
    static func buildType2CC(memoryMap: UltralightMemoryMap) -> Data {
        let sizeField = UInt8(clamping: memoryMap.userDataByteCount / 8)
        return Data([0xE1, 0x10, sizeField, 0x00])
    }

    static func buildType2Area(message: Data, capacity: Int) throws -> Data {
        let tlv = encodeNDEFTLV(message)
        guard tlv.count <= capacity else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 2 user memory")
        }
        return tlv + Data(repeating: 0x00, count: capacity - tlv.count)
    }

    /// Highest block count reachable with single-byte block addresses
    /// (READ/WRITE SINGLE BLOCK, ISO/IEC 15693-3).
    static let type5SingleByteAddressableBlocks = 256

    /// Build the Type 5 CC and NDEF data area as a list of blocks starting at block 0.
    ///
    /// NFC Forum T5T 1.0 §4.3.1:
    /// - CC byte 0: magic E1h (single-byte block addressing).
    /// - CC byte 1: version 1.0 in b7-b4, read access b3-b2, write access b1-b0
    ///   (00b = granted, 11b = no write access).
    /// - CC byte 2: MLEN in 8-byte units; when it does not fit, byte 2 is 00h and
    ///   the 16-bit MLEN goes in bytes 6-7 of an 8-byte CC.
    /// - CC byte 3: feature flags (none advertised).
    ///
    /// Without extended addressing commands the NDEF area is confined to blocks
    /// 0-255, so at most 256 blocks are returned even when the tag is larger.
    static func buildType5Blocks(
        message: Data,
        blockSize: Int,
        blockCount: Int,
        writeable: Bool = true
    ) throws -> [Data] {
        guard blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }
        guard blockCount >= 2 else {
            throw NFCError.unsupportedOperation("Type 5 tag reports too few blocks for NDEF")
        }

        let addressableBlocks = min(blockCount, type5SingleByteAddressableBlocks)
        let shortCCBlocks = 1
        let shortCapacity = (addressableBlocks - shortCCBlocks) * blockSize
        let usesLongCC = shortCapacity / 8 > 0xFF
        let ccLength = usesLongCC ? 8 : 4
        let ccBlocks = (ccLength + blockSize - 1) / blockSize
        guard addressableBlocks > ccBlocks else {
            throw NFCError.unsupportedOperation("Type 5 tag reports too few blocks for NDEF")
        }
        let userCapacity = (addressableBlocks - ccBlocks) * blockSize
        let memoryLengthUnits = userCapacity / 8

        let tlv = encodeNDEFTLV(message)
        guard tlv.count <= userCapacity else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 5 user memory")
        }

        let accessByte: UInt8 = writeable ? 0x40 : 0x43
        var cc: Data
        if usesLongCC {
            cc = Data([
                0xE1, accessByte, 0x00, 0x00,
                0x00, 0x00,
                UInt8((memoryLengthUnits >> 8) & 0xFF), UInt8(memoryLengthUnits & 0xFF),
            ])
        } else {
            cc = Data([0xE1, accessByte, UInt8(memoryLengthUnits), 0x00])
        }
        cc.append(Data(repeating: 0x00, count: ccBlocks * blockSize - cc.count))

        let userBytes = tlv + Data(repeating: 0x00, count: userCapacity - tlv.count)
        let area = cc + userBytes
        return stride(from: 0, to: area.count, by: blockSize).map { offset in
            Data(area[offset ..< offset + blockSize])
        }
    }

    private static func extractTLVNDEF(from data: Data) -> Data? {
        var offset = 0
        while offset < data.count {
            let tag = data[offset]
            offset += 1

            switch tag {
            case 0x00:
                continue
            case 0xFE:
                return nil
            case 0x03:
                guard let (length, headerBytes) = parseTLVLength(data, offset: offset) else {
                    return nil
                }
                offset += headerBytes
                guard offset + length <= data.count else {
                    return nil
                }
                return Data(data[offset ..< offset + length])
            default:
                guard let (length, headerBytes) = parseTLVLength(data, offset: offset) else {
                    return nil
                }
                offset += headerBytes + length
            }
        }
        return nil
    }

    private static func parseTLVLength(_ data: Data, offset: Int) -> (Int, Int)? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        if first == 0xFF {
            guard offset + 2 < data.count else { return nil }
            let length = Int(UInt16(data[offset + 1]) << 8 | UInt16(data[offset + 2]))
            return (length, 3)
        }
        return (Int(first), 1)
    }

    private static func encodeNDEFTLV(_ message: Data) -> Data {
        var tlv = Data([0x03])
        if message.count > 0xFE {
            tlv.append(0xFF)
            tlv.append(UInt8((message.count >> 8) & 0xFF))
            tlv.append(UInt8(message.count & 0xFF))
        } else {
            tlv.append(UInt8(message.count))
        }
        tlv.append(message)
        tlv.append(0xFE)
        return tlv
    }
}
