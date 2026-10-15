import Foundation

enum NDEFTagMapping {
    static func extractType2Message(from pages: [MemoryDump.Page]) -> Data? {
        let payload = pages
            .sorted(by: { $0.number < $1.number })
            .filter { $0.number >= 4 }
            .reduce(into: Data()) { result, page in
                result.append(page.data)
            }
        return extractTLVNDEF(from: payload)
    }

    static func extractType5Message(from blocks: [MemoryDump.Block]) -> Data? {
        let contiguous = blocks
            .sorted(by: { $0.number < $1.number })
            .reduce(into: Data()) { result, block in
                result.append(block.data)
            }

        guard contiguous.count >= 4 else { return nil }
        let magic = contiguous[contiguous.startIndex]
        guard magic == 0xE1 || magic == 0xE2 else { return nil }

        return extractTLVNDEF(from: Data(contiguous.dropFirst(4)))
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

    static func buildType5Blocks(
        message: Data,
        blockSize: Int,
        blockCount: Int,
        writeable: Bool = true
    ) throws -> [Data] {
        let userCapacity = max(0, (blockCount - 1) * blockSize)
        let tlv = encodeNDEFTLV(message)
        guard tlv.count <= userCapacity else {
            throw NFCError.unsupportedOperation("NDEF message exceeds Type 5 user memory")
        }

        guard blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }

        let memoryLengthUnits = userCapacity / 8
        guard memoryLengthUnits <= 0xFF else {
            throw NFCError.unsupportedOperation("Type 5 extended memory lengths are not yet supported")
        }

        var ccBlock = Data([0xE1, 0x40, UInt8(memoryLengthUnits), writeable ? 0x00 : 0x0F])
        if ccBlock.count < blockSize {
            ccBlock.append(Data(repeating: 0x00, count: blockSize - ccBlock.count))
        }

        let userBytes = tlv + Data(repeating: 0x00, count: userCapacity - tlv.count)
        let userBlocks = stride(from: 0, to: userBytes.count, by: blockSize).map { offset in
            Data(userBytes[offset ..< min(offset + blockSize, userBytes.count)])
        }

        return [ccBlock] + userBlocks
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
