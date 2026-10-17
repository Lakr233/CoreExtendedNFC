import Foundation

/// NFC Forum Type 2 / Type 5 tag mappings: Capability Container and NDEF TLV layout.
public enum NDEFTagMapping {
    /// Extract the NDEF message from Type 2 pages.
    ///
    /// NFC Forum T2T 1.0 §6.4.1 NDEF detection: the tag is only in NDEF state
    /// when CC0 (page 3 byte 0) is E1h and the mapping major version (CC1 b7-b4)
    /// is at most 1. The TLV scan is limited to the data area size CC2 × 8.
    /// Lock and reserved bytes declared by Lock Control and Memory Control TLVs
    /// are skipped while reading (see ``extractType2TLVNDEF(from:dataAreaOffset:)``).
    public static func extractType2Message(from pages: [MemoryDump.Page]) -> Data? {
        guard let ccPage = pages.first(where: { $0.number == 3 }), ccPage.data.count >= 4 else {
            return nil
        }
        let cc = [UInt8](ccPage.data)
        guard cc[0] == 0xE1, cc[1] >> 4 <= 1 else { return nil }
        let dataAreaSize = Int(cc[2]) * 8

        let dataPages = pages
            .sorted(by: { $0.number < $1.number })
            .filter { $0.number >= 4 }
        let payload = dataPages.reduce(into: Data()) { result, page in
            result.append(page.data)
        }
        return extractType2TLVNDEF(
            from: Data(payload.prefix(dataAreaSize)),
            dataAreaOffset: Int(dataPages.first?.number ?? 4) * type2PageSize
        )
    }

    /// Bytes per Type 2 page (NFC Forum T2T 1.0 §2.1).
    static let type2PageSize = 4

    /// Number of pages, counted from page 0, that hold the Type 2 data area the CC
    /// on page 3 declares, or `nil` when `pages` has no NDEF CC.
    ///
    /// NFC Forum T2T 1.0 §6.1: the data area starts at page 4 and holds CC byte 2 × 8
    /// bytes, so it ends at page 4 + ⌈CC2 × 8 / 4⌉. The count is capped at 256, the
    /// pages READ (30h) can address with its one-byte page number. Used to read an
    /// NDEF message on a tag whose product (and so memory map) is unknown.
    public static func type2DeclaredPageCount(from pages: [MemoryDump.Page]) -> Int? {
        guard let ccPage = pages.first(where: { $0.number == 3 }), ccPage.data.count >= 4 else {
            return nil
        }
        let cc = [UInt8](ccPage.data)
        guard cc[0] == 0xE1, cc[1] >> 4 <= 1 else { return nil }
        let dataAreaPages = (Int(cc[2]) * 8 + type2PageSize - 1) / type2PageSize
        return min(4 + dataAreaPages, 256)
    }

    /// Lock Control TLV tag (NFC Forum T2T 1.0 §2.3.4).
    static let lockControlTLV: UInt8 = 0x01

    /// Memory Control TLV tag (NFC Forum T2T 1.0 §2.3.5).
    static let memoryControlTLV: UInt8 = 0x02

    /// Absolute byte range (counted from byte 0 of page 0) of the lock bytes or reserved
    /// bytes that a Lock Control (01h) or Memory Control (02h) TLV with the 3-byte
    /// `value` declares, or `nil` for a value that is not 3 bytes long.
    ///
    /// NFC Forum T2T 1.0 §2.3.4 / §2.3.5 (nfcpy `tt2.py`): byte 0 holds PageAddr (b7-b4)
    /// and ByteOffset (b3-b0), byte 1 the size (00h means 256), byte 2 b3-b0
    /// BytesPerPage; the area starts at PageAddr × 2^BytesPerPage + ByteOffset. The
    /// size counts lock bits for a Lock Control TLV (⌈bits / 8⌉ bytes) and bytes for a
    /// Memory Control TLV.
    public static func type2ControlArea(tag: UInt8, value: Data) -> Range<Int>? {
        let bytes = [UInt8](value)
        guard bytes.count == 3, tag == lockControlTLV || tag == memoryControlTLV else { return nil }
        let pageAddress = Int(bytes[0] >> 4)
        let byteOffset = Int(bytes[0] & 0x0F)
        let bytesPerPage = Int(bytes[2] & 0x0F)
        let position = pageAddress * (1 << bytesPerPage) + byteOffset
        let size = bytes[1] == 0 ? 256 : Int(bytes[1])
        let byteCount = tag == lockControlTLV ? (size + 7) / 8 : size
        return position ..< position + byteCount
    }

    /// Find the NDEF TLV in a Type 2 data area and return its value, skipping the
    /// lock and reserved bytes that Lock Control and Memory Control TLVs declare
    /// (NFC Forum T2T 1.0 §2.3.4 / §2.3.5, nfcpy `tt2.py` `_read_ndef_data`).
    ///
    /// `data` is the data area (CC2 × 8 bytes from page 4) and `dataAreaOffset` its
    /// absolute byte address (16 for page 4), which control TLV positions are
    /// relative to. Bytes that a control TLV declares are skipped wherever they fall
    /// after that TLV, including inside the NDEF TLV's length or value. A control TLV
    /// whose length is not 3 is skipped like any other unknown TLV.
    public static func extractType2TLVNDEF(from data: Data, dataAreaOffset: Int) -> Data? {
        let bytes = [UInt8](data)
        var reserved: [Range<Int>] = []
        var index = 0

        /// Next byte of the area that no control TLV reserves, or `nil` at the end.
        func nextByte() -> UInt8? {
            while index < bytes.count, reserved.contains(where: { $0.contains(dataAreaOffset + index) }) {
                index += 1
            }
            guard index < bytes.count else { return nil }
            defer { index += 1 }
            return bytes[index]
        }

        while let tag = nextByte() {
            switch tag {
            case 0x00:
                continue
            case 0xFE:
                return nil
            default:
                guard let first = nextByte() else { return nil }
                var length = Int(first)
                if first == 0xFF {
                    guard let high = nextByte(), let low = nextByte() else { return nil }
                    length = Int(high) << 8 | Int(low)
                }
                var value = Data(capacity: length)
                for _ in 0 ..< length {
                    guard let byte = nextByte() else { return nil }
                    value.append(byte)
                }
                if tag == 0x03 {
                    return value
                }
                if let area = type2ControlArea(tag: tag, value: value) {
                    reserved.append(area)
                }
            }
        }
        return nil
    }

    /// Plan an NDEF write that keeps the Lock Control and Memory Control TLVs found
    /// at the start of a Type 2 data area (NFC Forum T2T 1.0 §2.3.4 / §2.3.5).
    ///
    /// `leadingBytes` are the first bytes of the data area, whose absolute address is
    /// `dataAreaOffset` (16 for page 4), and `capacity` is the writable size of the
    /// data area. NULL TLVs and control TLVs at the start are kept byte for byte as the
    /// returned `preservedPrefix`; the NDEF TLV goes right after them. The returned
    /// `capacity` (counted from the start of the data area, prefix included) stops at
    /// the page holding the first byte a control TLV reserves, so neither the
    /// message nor its padding touches lock or reserved bytes. `endsDataArea` is
    /// `false` when it was shortened that way.
    ///
    /// Leading bytes are only taken for control TLVs when every one of them is well
    /// formed (a 1-byte length of 3) and they are followed, after optional NULL TLVs,
    /// by an NDEF TLV (03h) or a Terminator TLV (FEh). Anything else, such as earlier
    /// non-NDEF data that happens to start with 01h or 02h, is not kept: the layout
    /// then has an empty prefix and the full capacity, so the NDEF TLV is written from
    /// the first byte of the data area.
    ///
    /// Returns `nil` when well-formed control TLVs run to the end of `leadingBytes`
    /// (a TLV is cut off, or only NULL TLVs follow), so the caller can read more bytes
    /// and try again. Throws ``NFCError/unsupportedOperation(_:)`` when a control TLV
    /// reserves bytes in a page the control TLVs occupy. A data area without control
    /// TLVs yields an empty prefix and the full capacity.
    public static func type2WriteLayout(
        leadingBytes: Data,
        dataAreaOffset: Int,
        capacity: Int
    ) throws -> (preservedPrefix: Data, capacity: Int, endsDataArea: Bool)? {
        try type2WriteLayout(
            leadingBytes: leadingBytes,
            dataAreaOffset: dataAreaOffset,
            capacity: capacity,
            keepingControlTLVsBeforeNULLs: false
        )
    }

    /// ``type2WriteLayout(leadingBytes:dataAreaOffset:capacity:)``; with
    /// `keepingControlTLVsBeforeNULLs`, well-formed control TLVs followed only by NULL
    /// TLVs up to the end of `leadingBytes` are kept too. The write path passes it
    /// once no more pages will be read: such TLVs are not stray data, and dropping
    /// them could let the message overwrite the one-time-programmable lock bytes
    /// they declare.
    static func type2WriteLayout(
        leadingBytes: Data,
        dataAreaOffset: Int,
        capacity: Int,
        keepingControlTLVsBeforeNULLs: Bool
    ) throws -> (preservedPrefix: Data, capacity: Int, endsDataArea: Bool)? {
        let bytes = [UInt8](leadingBytes)
        let plainLayout = (preservedPrefix: Data(), capacity: capacity, endsDataArea: true)
        var index = 0
        var prefixLength = 0
        var reserved: [Range<Int>] = []
        var sawControlTLV = false
        scan: while true {
            guard index < bytes.count else {
                // Only NULL TLVs so far, or control TLVs not yet followed by an NDEF or
                // Terminator TLV: more bytes are needed to decide.
                guard sawControlTLV else { return plainLayout }
                guard keepingControlTLVsBeforeNULLs else { return nil }
                break scan
            }
            // Lock and reserved bytes declared by an earlier control TLV are not TLVs.
            if reserved.contains(where: { $0.contains(dataAreaOffset + index) }) {
                index += 1
                continue
            }
            switch bytes[index] {
            case 0x00:
                index += 1
            case lockControlTLV, memoryControlTLV:
                guard index + 1 < bytes.count else { return nil }
                // T2T 1.0 §2.3.4 / §2.3.5: the value is exactly 3 bytes (1-byte length).
                guard bytes[index + 1] == 0x03 else { return plainLayout }
                let valueStart = index + 2
                guard valueStart + 3 <= bytes.count else { return nil }
                let value = Data(bytes[valueStart ..< valueStart + 3])
                if let area = type2ControlArea(tag: bytes[index], value: value) {
                    reserved.append(area)
                }
                index = valueStart + 3
                prefixLength = index
                sawControlTLV = true
            case 0x03, 0xFE:
                break scan
            default:
                return plainLayout
            }
        }
        guard sawControlTLV else { return plainLayout }

        let prefixEnd = dataAreaOffset + prefixLength
        var end = dataAreaOffset + capacity
        for area in reserved where area.upperBound > dataAreaOffset && area.lowerBound < end {
            end = min(end, area.lowerBound / type2PageSize * type2PageSize)
        }
        guard end >= prefixEnd else {
            throw NFCError.unsupportedOperation(
                "Type 2 control TLVs reserve bytes next to the control TLVs; NDEF writing is not supported"
            )
        }
        let usable = end - dataAreaOffset
        return (Data(bytes.prefix(prefixLength)), usable, usable == capacity)
    }

    /// Extract the NDEF message from Type 5 blocks.
    ///
    /// NFC Forum T5T 1.0 §4.3.1: when CC byte 2 (MLEN) is 00h the CC is 8 bytes
    /// long (bytes 6-7 carry the 16-bit MLEN) and the TLV area starts at byte 8;
    /// otherwise the CC is 4 bytes. The TLV scan is limited to the T5T_Area of
    /// MLEN × 8 bytes, like the Type 2 data area. A CC with an unsupported major
    /// version or without read access yields `nil` (see
    /// ``type5FormattedCCLength(leadingBytes:)``).
    public static func extractType5Message(from blocks: [MemoryDump.Block]) -> Data? {
        let contiguous = blocks
            .sorted(by: { $0.number < $1.number })
            .reduce(into: Data()) { result, block in
                result.append(block.data)
            }

        guard let ccLength = type5FormattedCCLength(leadingBytes: contiguous),
              let areaLength = type5DataAreaLength(leadingBytes: contiguous)
        else { return nil }

        let area = contiguous.dropFirst(ccLength).prefix(areaLength)
        return extractTLVNDEF(from: Data(area))
    }

    /// CC length (4 or 8 bytes) when `leadingBytes` (block 0 onwards) starts with a
    /// readable Type 5 CC, otherwise `nil`.
    ///
    /// NFC Forum T5T 1.0 §4.3.1 / §7.3 (NDEF detection): byte 0 must be the magic E1h
    /// or E2h, byte 1 b7-b6 the major mapping version 1 (or lower), and byte 1 b3-b2
    /// read access 00b (granted). ``type5ReadableCCLength(leadingBytes:)`` reports
    /// which check failed.
    public static func type5FormattedCCLength(leadingBytes: Data) -> Int? {
        try? type5ReadableCCLength(leadingBytes: leadingBytes)
    }

    /// CC length (4 or 8 bytes) of a Type 5 tag whose CC allows reading the NDEF
    /// message (see ``type5FormattedCCLength(leadingBytes:)``).
    ///
    /// Throws ``NFCError/tagNotNDEFFormatted`` when the CC magic is not E1h / E2h or
    /// the major mapping version is above 1, and ``NFCError/tagLocked`` when the CC
    /// denies read access (CC byte 1 b3-b2 ≠ 00b). The same checks as ST's RFAL NDEF
    /// library (`ndefT5TPollerNdefDetect`, "Check version - 7.5.1.2" / "Check read
    /// access - 7.5.1.2"); neard `nfctype5.c` (`t5_cc_is_valid`) also treats another
    /// major version as not NDEF formatted.
    public static func type5ReadableCCLength(leadingBytes: Data) throws -> Int {
        guard let ccLength = type5CCLengthFromMagic(leadingBytes) else {
            throw NFCError.tagNotNDEFFormatted
        }
        let access = leadingBytes[leadingBytes.startIndex + 1]
        guard access >> 6 <= 1 else {
            throw NFCError.tagNotNDEFFormatted
        }
        guard access & 0x0C == 0x00 else {
            throw NFCError.tagLocked
        }
        return ccLength
    }

    /// CC length from the magic and MLEN byte alone, without version or access checks.
    static func type5CCLengthFromMagic(_ leadingBytes: Data) -> Int? {
        let bytes = [UInt8](leadingBytes.prefix(4))
        guard bytes.count == 4, bytes[0] == 0xE1 || bytes[0] == 0xE2 else { return nil }
        return bytes[2] == 0x00 ? 8 : 4
    }

    /// Size in bytes of the T5T_Area announced by the CC (MLEN × 8, NFC Forum T5T 1.0
    /// §4.3.1), or `nil` when `leadingBytes` does not hold a complete CC.
    public static func type5DataAreaLength(leadingBytes: Data) -> Int? {
        guard let ccLength = type5CCLengthFromMagic(leadingBytes) else { return nil }
        let cc = [UInt8](leadingBytes.prefix(ccLength))
        guard cc.count == ccLength else { return nil }
        let memoryLengthUnits = ccLength == 8
            ? Int(cc[6]) << 8 | Int(cc[7])
            : Int(cc[2])
        return memoryLengthUnits * 8
    }

    /// Build the 4-byte Capability Container for a Type 2 tag (page 3).
    ///
    /// Layout: `[0xE1, version, size, access]`
    /// - Byte 0: NDEF magic number (0xE1)
    /// - Byte 1: Mapping version 1.0 (0x10)
    /// - Byte 2: Data area size in 8-byte units (see ``type2DataAreaUnits(for:)``)
    /// - Byte 3: Read/write access (0x00 = read-write)
    public static func buildType2CC(for type: CardType) -> Data {
        Data([0xE1, 0x10, type2DataAreaUnits(for: type), 0x00])
    }

    /// CC byte 2 (data area size / 8) that NXP pre-programs or specifies for each
    /// Type 2 product. NTAG213/215/216 datasheet §8.5.6 ("NDEF memory size"):
    /// 12h, 3Eh, 6Dh, so 215 and 216 advertise less than their 504 / 888 user
    /// bytes. NTAG210/212 datasheet §8.5.6: 06h, 10h. The other products use their
    /// whole user area (Ultralight 06h, Ultralight C 12h, EV1 06h / 10h).
    public static func type2DataAreaUnits(for type: CardType) -> UInt8 {
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
    /// Throws ``NFCError/tagNotNDEFFormatted`` when the tag is not NDEF formatted, uses
    /// an unsupported mapping major
    /// version, or denies write access (CC3 b3-b0 ≠ 0h).
    public static func type2WritableCapacity(cc: Data, memoryMap: UltralightMemoryMap) throws -> Int {
        let bytes = [UInt8](cc.prefix(4))
        guard bytes.count == 4, bytes[0] == 0xE1 else {
            throw NFCError.tagNotNDEFFormatted
        }
        guard bytes[1] >> 4 <= 1 else {
            throw NFCError.unsupportedOperation("Unsupported Type 2 NDEF mapping version")
        }
        guard bytes[3] & 0x0F == 0x00 else {
            throw NFCError.tagLocked
        }
        return min(memoryMap.userDataByteCount, Int(bytes[2]) * 8)
    }

    /// Lay out the `capacity`-byte Type 2 data area for `message`: the NDEF TLV
    /// starting at the first byte, a Terminator TLV when there is room for one,
    /// and zero padding. A message whose NDEF TLV fills the area exactly is
    /// written without a terminator (NFC Forum T2T 1.0 §2.3, nfcpy `tt2.py`).
    ///
    /// The NDEF TLV starts right after `preservedPrefix`, the NULL, Lock Control and
    /// Memory Control TLVs kept from the tag (see
    /// ``type2WriteLayout(leadingBytes:dataAreaOffset:capacity:)``); with an empty
    /// prefix it starts at the first byte of the area. `capacity` includes the
    /// prefix. Pass `endsDataArea: false` when `capacity` stops short of the data
    /// area (before reserved bytes), which keeps the Terminator TLV.
    public static func buildType2Area(
        message: Data,
        capacity: Int,
        preservedPrefix: Data = Data(),
        endsDataArea: Bool = true
    ) throws -> Data {
        let preservedPrefix = Data(preservedPrefix) // Rebase a slice to index from zero.
        let available = max(0, capacity - preservedPrefix.count)
        let tlvSize = ndefTLVSize(messageLength: message.count)
        // The Terminator TLV is optional when the NDEF TLV ends the data area.
        let dropsTerminator = endsDataArea && tlvSize - 1 == available
        guard message.count <= maximumNDEFTLVValueLength,
              tlvSize - (dropsTerminator ? 1 : 0) <= available
        else {
            throw NFCError.ndefCapacityExceeded(
                required: tlvSize - 1,
                capacity: min(available, maximumNDEFTLVSize - 1)
            )
        }
        var tlv = try preservedPrefix + encodeNDEFTLV(message)
        if dropsTerminator {
            tlv.removeLast()
        }
        return tlv + Data(repeating: 0x00, count: capacity - tlv.count)
    }

    /// Order a write plan the way the NFC Forum NDEF write procedure requires
    /// (T2T 1.0 §6.4.3, T5T 1.0 §7.5.1, nfcpy `tt2.py`): first the blocks holding
    /// the NDEF TLV length with that length set to zero, then the other blocks,
    /// and finally the length blocks with the real length. A write interrupted
    /// part-way therefore leaves an empty NDEF message, never a truncated one.
    ///
    /// `writes` holds the block contents in block order. `tlvOffset` is the byte
    /// offset of the NDEF TLV's T field counted from the start of block 0, and
    /// `blockSize` is the size of one block (4 bytes for a Type 2 page). Length
    /// blocks whose content does not change (an empty message, `03 00`) are not
    /// written twice.
    ///
    /// When a 3-byte length (`FF hi lo`) spans two blocks, the final length blocks
    /// are written in descending block order: the block holding the first length
    /// byte (still 00h, so the message reads as empty) goes last, which makes the
    /// switch to the real length a single block write. Written in ascending order,
    /// a write interrupted between them would leave `FF` with a stale low byte, a
    /// wrong non-zero length.
    public static func lengthLastWriteOrder(
        _ writes: [(block: Int, data: Data)],
        blockSize: Int,
        tlvOffset: Int
    ) -> [(block: Int, data: Data)] {
        guard blockSize > 0 else { return writes }
        /// Byte at absolute `offset`, when a planned write covers it.
        func byte(at offset: Int) -> UInt8? {
            guard let write = writes.first(where: { $0.block == offset / blockSize }) else { return nil }
            let index = offset % blockSize
            return index < write.data.count ? write.data[write.data.startIndex + index] : nil
        }
        guard let first = byte(at: tlvOffset + 1) else { return writes }
        let lengthRange = (tlvOffset + 1) ..< (tlvOffset + 1 + (first == 0xFF ? 3 : 1))

        var interim: [(block: Int, data: Data)] = []
        var body: [(block: Int, data: Data)] = []
        var final: [(block: Int, data: Data)] = []
        for write in writes {
            let start = write.block * blockSize
            let lower = max(start, lengthRange.lowerBound)
            let upper = min(start + write.data.count, lengthRange.upperBound)
            guard lower < upper else {
                body.append(write)
                continue
            }
            var zeroed = write.data
            for offset in lower ..< upper {
                zeroed[zeroed.startIndex + offset - start] = 0x00
            }
            interim.append((write.block, zeroed))
            if zeroed != write.data {
                final.append(write)
            }
        }
        return interim + body + final.reversed()
    }

    /// Highest block count reachable with single-byte block addresses
    /// (READ/WRITE SINGLE BLOCK, ISO/IEC 15693-3).
    public static let type5SingleByteAddressableBlocks = 256

    /// Highest block count reachable with two-byte block addresses
    /// (EXTENDED READ/WRITE SINGLE BLOCK, ISO/IEC 15693-3 commands 30h / 31h).
    public static let type5ExtendedAddressableBlocks = 65536

    /// CC byte 3 b4: the tag needs the special frame format for writes
    /// (NFC Forum T5T 1.0 §4.3.1, neard `TYPE5_CC3_SPECIAL_FRAME_FLAG`).
    public static let type5SpecialFrameFlag: UInt8 = 0x10

    /// Largest MLEN an 8-byte CC can announce (16-bit field, NFC Forum T5T 1.0 §4.3.1).
    public static let type5MaximumMemoryLengthUnits = 0xFFFF

    /// Build the Type 5 CC and NDEF data area as a list of blocks starting at block 0.
    ///
    /// NFC Forum T5T 1.0 §4.3.1:
    /// - CC byte 0: magic E1h when the area fits in blocks 0-255 (single-byte block
    ///   addressing), E2h when it runs past block 255 (two-byte block addressing).
    /// - CC byte 1: version 1.0 in b7-b4, read access b3-b2, write access b1-b0
    ///   (00b = granted, 11b = no write access).
    /// - CC byte 2: MLEN in 8-byte units; when it does not fit, byte 2 is 00h and
    ///   the 16-bit MLEN goes in bytes 6-7 of an 8-byte CC.
    /// - CC byte 3: feature flags (none advertised).
    ///
    /// The NDEF area is confined to the first `addressableBlockCount` blocks. The
    /// default, ``type5SingleByteAddressableBlocks``, suits tags without extended
    /// addressing commands, so at most 256 blocks are returned even when the tag is
    /// larger; pass ``type5ExtendedAddressableBlocks`` for a tag that accepts them.
    /// When the memory exceeds the largest MLEN (FFFFh units) only the blocks
    /// covering that area are returned.
    ///
    /// The NDEF TLV starts right after the CC (byte 4 or 8 of block 0 onwards),
    /// whatever the block size, which is where readers start the TLV scan. A message
    /// longer than FFFEh bytes throws ``NFCError/ndefCapacityExceeded(required:capacity:)``.
    public static func buildType5Blocks(
        message: Data,
        blockSize: Int,
        blockCount: Int,
        writeable: Bool = true,
        addressableBlockCount: Int = type5SingleByteAddressableBlocks
    ) throws -> [Data] {
        guard blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }
        guard blockCount >= 2 else {
            throw NFCError.unsupportedOperation("Type 5 tag reports too few blocks for NDEF")
        }

        let addressableBlocks = min(blockCount, addressableBlockCount)
        let addressableBytes = addressableBlocks * blockSize
        let usesLongCC = (addressableBytes - 4) / 8 > 0xFF
        let ccLength = usesLongCC ? 8 : 4
        // MLEN counts whole 8-byte units after the CC, so the advertised T5T_Area can be
        // a few bytes smaller than the user memory; readers stop at MLEN × 8.
        let fullMemoryLengthUnits = max(0, addressableBytes - ccLength) / 8
        let memoryLengthUnits = min(fullMemoryLengthUnits, type5MaximumMemoryLengthUnits)
        guard memoryLengthUnits > 0 else {
            // A 4-byte CC with MLEN 00h would mean "8-byte CC" to readers.
            throw NFCError.unsupportedOperation("Type 5 tag has less than 8 bytes of NDEF memory")
        }
        // Blocks past the largest announceable area are left alone.
        let usedBlocks = fullMemoryLengthUnits > memoryLengthUnits
            ? (ccLength + memoryLengthUnits * 8 + blockSize - 1) / blockSize
            : addressableBlocks

        let capacity = min(memoryLengthUnits * 8, maximumNDEFTLVSize)
        let required = ndefTLVSize(messageLength: message.count)
        guard required <= capacity else {
            throw NFCError.ndefCapacityExceeded(required: required, capacity: capacity)
        }
        let tlv = try encodeNDEFTLV(message)

        let magic: UInt8 = usedBlocks > type5SingleByteAddressableBlocks ? 0xE2 : 0xE1
        let accessByte: UInt8 = writeable ? 0x40 : 0x43
        let cc = if usesLongCC {
            Data([
                magic, accessByte, 0x00, 0x00,
                0x00, 0x00,
                UInt8((memoryLengthUnits >> 8) & 0xFF), UInt8(memoryLengthUnits & 0xFF),
            ])
        } else {
            Data([magic, accessByte, UInt8(memoryLengthUnits), 0x00])
        }

        // NFC Forum T5T 1.0 §4.4: the TLV area starts right after the CC (byte 4 or 8),
        // whatever the block size; readers scan from there.
        let used = cc + tlv
        let area = used + Data(repeating: 0x00, count: usedBlocks * blockSize - used.count)
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
    /// - byte 2 = 00h selects the 8-byte CC (16-bit MLEN in bytes 6-7);
    /// - byte 3 b4 (Special_Frame) means writes need the ISO/IEC 15693 special
    ///   frame (Option flag, response after an EOF). CoreNFC offers no reliable way
    ///   to send it, so such a tag is refused with ``NFCError/unsupportedOperation(_:)``.
    public static func type5CCLength(firstBlock: Data) throws -> Int {
        let bytes = [UInt8](firstBlock.prefix(4))
        guard bytes.count == 4, bytes[0] == 0xE1 || bytes[0] == 0xE2 else {
            throw NFCError.tagNotNDEFFormatted
        }
        guard bytes[1] >> 6 <= 1 else {
            throw NFCError.unsupportedOperation("Unsupported Type 5 NDEF mapping version")
        }
        guard bytes[1] & 0x03 == 0x00 else {
            throw NFCError.tagLocked
        }
        guard bytes[3] & type5SpecialFrameFlag == 0 else {
            throw NFCError.unsupportedOperation("Type 5 tag requires special frame writes, which are not supported")
        }
        return bytes[2] == 0x00 ? 8 : 4
    }

    /// Plan the block writes that store `message` on an NDEF-formatted Type 5 tag.
    ///
    /// `leadingBytes` are the bytes read from block 0 onwards and must cover the CC.
    /// Only the blocks holding the NDEF TLV and its terminator TLV are returned, in
    /// block order (write them in ``lengthLastWriteOrder(_:blockSize:tlvOffset:)``); the
    /// CC is kept as read (a block it shares with the TLV is rewritten with the
    /// CC bytes unchanged) and memory after the terminator is left untouched.
    /// The data area is bounded by MLEN and by the first `addressableBlockCount`
    /// blocks: the default, ``type5SingleByteAddressableBlocks``, keeps every write
    /// in blocks 0-255; pass ``type5ExtendedAddressableBlocks`` to plan writes past
    /// block 255 for a tag that accepts EXTENDED WRITE SINGLE BLOCK. A message
    /// longer than FFFEh bytes, the largest 3-byte TLV length, throws
    /// ``NFCError/ndefCapacityExceeded(required:capacity:)``.
    public static func type5NDEFWrites(
        message: Data,
        leadingBytes: Data,
        blockSize: Int,
        blockCount: Int,
        addressableBlockCount: Int = type5SingleByteAddressableBlocks
    ) throws -> [(block: Int, data: Data)] {
        guard blockSize >= 4 else {
            throw NFCError.unsupportedOperation("Type 5 block size must be at least 4 bytes")
        }
        let ccLength = try type5CCLength(firstBlock: leadingBytes)
        let cc = [UInt8](leadingBytes.prefix(ccLength))
        guard cc.count == ccLength else {
            throw NFCError.invalidResponse(leadingBytes)
        }
        let areaLength = type5DataAreaLength(leadingBytes: leadingBytes) ?? 0

        let addressableBytes = min(blockCount, addressableBlockCount) * blockSize
        // A 3-byte TLV length cannot exceed FFFEh (T5T 1.0 §4.4).
        let capacity = min(areaLength, max(0, addressableBytes - ccLength), maximumNDEFTLVSize)
        let required = ndefTLVSize(messageLength: message.count)
        guard required <= capacity else {
            throw NFCError.ndefCapacityExceeded(required: required, capacity: capacity)
        }
        let tlv = try encodeNDEFTLV(message)

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

    /// Find the NDEF TLV (03h) in a Type 5 (or plain) TLV area and return its value.
    /// NULL TLVs are skipped, other TLVs are stepped over, and a Terminator TLV or a
    /// truncated TLV ends the scan with `nil`.
    public static func extractTLVNDEF(from data: Data) -> Data? {
        let data = Data(data) // Rebase a slice so integer offsets index from zero.
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

    /// Parse the TLV length field at `offset` (counted from the first byte of `data`,
    /// also for a slice): a 1-byte length, or `FF` and a 2-byte big-endian length.
    /// Returns the length and the size of the length field, or `nil` when `data`
    /// ends inside the field.
    public static func parseTLVLength(_ data: Data, offset: Int) -> (Int, Int)? {
        guard offset >= 0, offset < data.count else { return nil }
        let base = data.startIndex + offset
        let first = data[base]
        if first == 0xFF {
            guard offset + 2 < data.count else { return nil }
            let length = Int(data[base + 1]) << 8 | Int(data[base + 2])
            return (length, 3)
        }
        return (Int(first), 1)
    }

    /// Largest NDEF TLV value a 3-byte length field can announce: lengths run from
    /// 00FFh to FFFEh, FFFFh is reserved (NFC Forum T2T 1.0 §2.3, T5T 1.0 §4.4).
    public static let maximumNDEFTLVValueLength = 0xFFFE

    /// Bytes an NDEF TLV holding `messageLength` bytes takes, Terminator TLV included.
    static func ndefTLVSize(messageLength: Int) -> Int {
        1 + (messageLength > 0xFE ? 3 : 1) + messageLength + 1
    }

    /// Size of the largest NDEF TLV, Terminator TLV included.
    static let maximumNDEFTLVSize = ndefTLVSize(messageLength: maximumNDEFTLVValueLength)

    /// Encode `message` as an NDEF TLV (03h) followed by a Terminator TLV (FEh).
    ///
    /// Throws ``NFCError/ndefCapacityExceeded(required:capacity:)`` when the message
    /// is longer than ``maximumNDEFTLVValueLength`` (FFFEh) bytes, which no TLV
    /// length can express.
    public static func encodeNDEFTLV(_ message: Data) throws -> Data {
        guard message.count <= maximumNDEFTLVValueLength else {
            throw NFCError.ndefCapacityExceeded(
                required: ndefTLVSize(messageLength: message.count),
                capacity: maximumNDEFTLVSize
            )
        }
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
