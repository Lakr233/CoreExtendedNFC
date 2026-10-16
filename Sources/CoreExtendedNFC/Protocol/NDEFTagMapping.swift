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
    /// - Byte 2: Data area size in 8-byte units (see ``type2DataAreaUnits(for:)``)
    /// - Byte 3: Read/write access (0x00 = read-write)
    static func buildType2CC(for type: CardType) -> Data {
        Data([0xE1, 0x10, type2DataAreaUnits(for: type), 0x00])
    }

    /// CC byte 2 (data area size / 8) that NXP pre-programs or specifies for each
    /// Type 2 product. NTAG213/215/216 datasheet §8.5.6 ("NDEF memory size"):
    /// 12h, 3Eh, 6Dh, so 215 and 216 advertise less than their 504 / 888 user
    /// bytes. NTAG210/212 datasheet §8.5.6: 06h, 10h. The other products use their
    /// whole user area (Ultralight 06h, Ultralight C 12h, EV1 06h / 10h).
    static func type2DataAreaUnits(for type: CardType) -> UInt8 {
        switch type {
        case .ntag215:
            0x3E
        case .ntag216:
            0x6D
        default:
            UInt8(clamping: UltralightMemoryMap.forType(type).userDataByteCount / 8)
        }
    }

    /// Bytes available to the NDEF TLV area on a Type 2 tag whose page 3 holds `cc`
    /// (NFC Forum T2T 1.0 §6.1): CC2 × 8, but never more than the product's user memory,
    /// so a written message is always found again by ``extractType2Message(from:)``.
    /// Throws when the tag is not NDEF formatted, uses an unsupported mapping major
    /// version, or denies write access (CC3 b3-b0 ≠ 0h).
    static func type2WritableCapacity(cc: Data, memoryMap: UltralightMemoryMap) throws -> Int {
        let bytes = [UInt8](cc.prefix(4))
        guard bytes.count == 4, bytes[0] == 0xE1 else {
            throw NFCError.unsupportedOperation("The tag is not NDEF formatted; format it first")
        }
        guard bytes[1] >> 4 <= 1 else {
            throw NFCError.unsupportedOperation("Unsupported Type 2 NDEF mapping version")
        }
        guard bytes[3] & 0x0F == 0x00 else {
            throw NFCError.tagLocked
        }
        return min(memoryMap.userDataByteCount, Int(bytes[2]) * 8)
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

    /// Validate the Type 5 Capability Container at the start of `firstBlock`
    /// (block 0) for an NDEF write and return the CC length (4 or 8 bytes).
    ///
    /// NFC Forum T5T 1.0 §4.3.1 / §7.5.1 (NDEF write procedure):
    /// - byte 0 must be the magic E1h or E2h, otherwise the tag is not NDEF formatted;
    /// - byte 1 b7-b6 is the major mapping version (only 1 is supported);
    /// - byte 1 b1-b0 is write access: only 00b (granted) permits writing;
    /// - byte 2 = 00h selects the 8-byte CC (16-bit MLEN in bytes 6-7).
    static func type5CCLength(firstBlock: Data) throws -> Int {
        let bytes = [UInt8](firstBlock.prefix(4))
        guard bytes.count == 4, bytes[0] == 0xE1 || bytes[0] == 0xE2 else {
            throw NFCError.unsupportedOperation("The tag is not NDEF formatted; format it first")
        }
        guard bytes[1] >> 6 <= 1 else {
            throw NFCError.unsupportedOperation("Unsupported Type 5 NDEF mapping version")
        }
        guard bytes[1] & 0x03 == 0x00 else {
            throw NFCError.tagLocked
        }
        return bytes[2] == 0x00 ? 8 : 4
    }

    /// Plan the block writes that store `message` on an NDEF-formatted Type 5 tag.
    ///
    /// `leadingBytes` are the bytes read from block 0 onwards and must cover the CC.
    /// Only the blocks holding the NDEF TLV and its terminator TLV are returned; the
    /// CC is kept as read (a block it shares with the TLV is rewritten with the
    /// CC bytes unchanged) and memory after the terminator is left untouched.
    /// The data area is bounded by MLEN and by the single-byte addressable blocks.
    static func type5NDEFWrites(
        message: Data,
        leadingBytes: Data,
        blockSize: Int,
        blockCount: Int
    ) throws -> [(block: Int, data: Data)] {
        guard blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }
        let ccLength = try type5CCLength(firstBlock: leadingBytes)
        let cc = [UInt8](leadingBytes.prefix(ccLength))
        guard cc.count == ccLength else {
            throw NFCError.invalidResponse(leadingBytes)
        }
        let memoryLengthUnits = ccLength == 8
            ? Int(cc[6]) << 8 | Int(cc[7])
            : Int(cc[2])

        let addressableBytes = min(blockCount, type5SingleByteAddressableBlocks) * blockSize
        let capacity = min(memoryLengthUnits * 8, max(0, addressableBytes - ccLength))
        let tlv = encodeNDEFTLV(message)
        guard tlv.count <= capacity else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 5 user memory")
        }

        var area = Data(cc) + tlv
        let padding = (blockSize - area.count % blockSize) % blockSize
        area.append(Data(repeating: 0x00, count: padding))

        // Blocks made only of CC bytes are not rewritten.
        let firstBlock = ccLength / blockSize
        let lastBlock = area.count / blockSize - 1
        return (firstBlock ... lastBlock).map { block in
            let offset = block * blockSize
            return (block, Data(area[offset ..< offset + blockSize]))
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
