// NDEF mapping robustness: seeded fuzzing, write tearing, TLV length limits, Type 5 CC
// checks and Data-slice inputs. Regression tests for the round-3 adversarial review.
//
// ## References
// - NFC Forum Type 2 Tag Technical Specification 1.0 §2.3 (TLV blocks), §6.4.3 (NDEF write)
// - NFC Forum Type 5 Tag Technical Specification 1.0 §4.3.1 (CC), §4.4 (TLV), §7.5.1 (NDEF write)
// - NFC Forum NDEF 1.0 §2.3.3 (chunked records)
@testable import CoreExtendedNFC
import Foundation
import Testing

/// Deterministic generator so every fuzz run checks the same inputs.
private struct SplitMix: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ count: Int) -> Data {
        Data((0 ..< count).map { _ in UInt8.random(in: 0 ... 255, using: &self) })
    }

    mutating func int(_ range: ClosedRange<Int>) -> Int {
        Int.random(in: range, using: &self)
    }

    mutating func mutate(_ data: Data) -> Data {
        var bytes = [UInt8](data)
        for _ in 0 ..< int(1 ... 4) {
            switch int(0 ... 4) {
            case 0 where !bytes.isEmpty: bytes[int(0 ... bytes.count - 1)] = UInt8(int(0 ... 255))
            case 1 where !bytes.isEmpty: bytes[int(0 ... bytes.count - 1)] ^= UInt8(1 << int(0 ... 7))
            case 2: bytes.insert(UInt8(int(0 ... 255)), at: int(0 ... bytes.count))
            case 3 where !bytes.isEmpty: bytes.remove(at: int(0 ... bytes.count - 1))
            case 4 where !bytes.isEmpty: bytes = Array(bytes.prefix(int(0 ... bytes.count)))
            default: break
            }
        }
        return Data(bytes)
    }
}

private let seedImages: [Data] = [
    NDEFMessage.text("hello").data,
    NDEFMessage.uri("https://example.com/a").data,
    NDEFMessage(records: [.smartPoster(uri: "https://a.b", title: "T"), .mime(type: "a/b", data: Data([1, 2, 3]))]).data,
    NDEFMessage(records: [.external(type: "x.com:y", data: Data(repeating: 7, count: 300))]).data,
    Data([0xB5, 0x00, 0x02, 0xAA, 0x36, 0x00, 0x01, 0xBB, 0x56, 0x00, 0x01, 0xCC]), // chunked Unknown
    Data([0xD9, 0x01, 0x01, 0x01, 0x55, 0xAA, 0x00]),
]

/// Type 2 tag memory that fails every page write after the first `failAfter`.
private final class TearingType2Tag: NFCTagTransport, @unchecked Sendable {
    let identifier = Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    var pages: [UInt8: Data]
    let failAfter: Int
    var writes = 0

    init(pages: [UInt8: Data], failAfter: Int = .max) {
        self.pages = pages
        self.failAfter = failAfter
    }

    func send(_ command: Data) async throws -> Data {
        let bytes = [UInt8](command)
        if bytes[0] == 0x30 {
            return (0 ..< 4).reduce(into: Data()) { $0.append(pages[bytes[1] &+ UInt8($1)] ?? Data(count: 4)) }
        }
        if bytes[0] == 0xA2 {
            guard writes < failAfter else { throw NFCError.tagConnectionLost }
            writes += 1
            pages[bytes[1]] = Data(bytes[2...])
            return Data([0x0A])
        }
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    /// Data area bytes from page 4.
    func dataArea(_ length: Int) -> Data {
        Data((4 ..< 128).reduce(into: Data()) { $0.append(pages[UInt8($1)] ?? Data(count: 4)) }.prefix(length))
    }
}

struct NDEFRobustnessTests {
    // MARK: - Seeded fuzzing

    @Test
    func `Fuzzed NDEF messages parse or throw NFCError and round-trip`() {
        var rng = SplitMix(state: 1)
        for index in 0 ..< 6000 {
            let input = index % 2 == 0
                ? rng.bytes(rng.int(0 ... 48))
                : rng.mutate(seedImages[index % seedImages.count])
            do {
                let message = try NDEFMessage(data: input)
                for record in message.records {
                    _ = record.displayType
                    _ = record.displayValue
                }
                if let encoded = try? message.validatedData() {
                    #expect((try? NDEFMessage(data: encoded)) == message, "round trip \(input.hexString)")
                }
            } catch {
                #expect(error is NFCError)
            }
        }
    }

    @Test
    func `Fuzzed Type 2 TLV areas never trap`() throws {
        var rng = SplitMix(state: 2)
        for index in 0 ..< 6000 {
            var input: Data
            if index % 2 == 0 {
                input = rng.bytes(rng.int(0 ... 160))
            } else {
                let control = Data([
                    UInt8(rng.int(1 ... 2)), 0x03,
                    UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 255)),
                ])
                input = try rng.mutate(control + NDEFTagMapping.encodeNDEFTLV(seedImages[index % seedImages.count]))
            }
            _ = NDEFTagMapping.extractType2TLVNDEF(from: input, dataAreaOffset: rng.int(0 ... 64))
            _ = NDEFTagMapping.extractTLVNDEF(from: input)
            let pages = stride(from: 0, to: input.count, by: 4).map {
                MemoryDump.Page(number: UInt8(3 + $0 / 4), data: Data(input[$0 ..< min($0 + 4, input.count)]))
            }
            _ = NDEFTagMapping.extractType2Message(from: pages)
            _ = try? NDEFTagMapping.type2WriteLayout(leadingBytes: input, dataAreaOffset: 16, capacity: rng.int(0 ... 200))
        }
    }

    @Test
    func `Fuzzed Type 4 CC files parse or throw NFCError`() {
        var rng = SplitMix(state: 3)
        for index in 0 ..< 6000 {
            var cc = rng.bytes(rng.int(0 ... 20))
            if index % 2 == 0, cc.count >= 9 {
                cc[2] = [0x10, 0x20, 0x30, 0x40][rng.int(0 ... 3)]
                cc[7] = [0x04, 0x06][rng.int(0 ... 1)]
                cc[8] = cc[7] == 4 ? 6 : 8
            }
            do {
                let parsed = try Type4CC(data: cc)
                _ = parsed.encoded
                _ = parsed.encodeNDEFFile(rng.bytes(rng.int(0 ... 10)))
            } catch {
                #expect(error is NFCError)
            }
        }
    }

    /// Whenever a Type 5 write plan is returned, applying it must read the message back.
    @Test
    func `Fuzzed Type 5 write plans read back`() {
        var rng = SplitMix(state: 4)
        var mismatches: [String] = []
        for index in 0 ..< 3000 {
            let blockSize = [4, 8, 16, 32, rng.int(1 ... 40)][rng.int(0 ... 4)]
            let blockCount = [rng.int(1 ... 300), rng.int(1 ... 3000)][rng.int(0 ... 1)]
            var lead = rng.bytes(max(8, blockSize * ((8 + blockSize - 1) / blockSize)))
            lead[0] = [0xE1, 0xE2, UInt8(rng.int(0 ... 255))][rng.int(0 ... 2)]
            if index % 2 == 0 {
                lead[1] = 0x40
                lead[3] = 0
            }
            if index % 3 == 0 { lead[2] = 0 }
            let message = index % 5 == 0 ? Data() : seedImages[index % seedImages.count]
            let addressable = index % 4 == 0
                ? NDEFTagMapping.type5ExtendedAddressableBlocks
                : NDEFTagMapping.type5SingleByteAddressableBlocks
            guard let writes = try? NDEFTagMapping.type5NDEFWrites(
                message: message,
                leadingBytes: lead,
                blockSize: blockSize,
                blockCount: blockCount,
                addressableBlockCount: addressable
            ) else { continue }

            var memory = [Int: Data]()
            for block in 0 ..< lead.count / blockSize {
                memory[block] = Data(lead[block * blockSize ..< (block + 1) * blockSize])
            }
            for write in writes {
                #expect(write.data.count == blockSize)
                #expect(write.block < blockCount)
                memory[write.block] = write.data
            }
            // A CC that denies read access (or a newer major version) is not read back.
            guard NDEFTagMapping.type5FormattedCCLength(leadingBytes: lead) != nil else { continue }
            let blocks = (0 ... (memory.keys.max() ?? 0)).map {
                MemoryDump.Block(number: $0, data: memory[$0] ?? Data(count: blockSize))
            }
            if NDEFTagMapping.extractType5Message(from: blocks) != message {
                mismatches.append("bs=\(blockSize) bc=\(blockCount) cc=\(lead.prefix(8).hexString)")
            }
        }
        #expect(mismatches.isEmpty, "\(mismatches.prefix(3))")
    }

    @Test
    func `Fuzzed Type 5 formats read back for any block size`() {
        var rng = SplitMix(state: 5)
        var bad: [String] = []
        for index in 0 ..< 600 {
            let blockSize = rng.int(1 ... 40)
            let blockCount = [rng.int(0 ... 300), rng.int(0 ... 70000)][index % 2]
            let message = seedImages[index % seedImages.count]
            guard let blocks = try? NDEFTagMapping.buildType5Blocks(
                message: message,
                blockSize: blockSize,
                blockCount: blockCount,
                addressableBlockCount: index % 3 == 0 ? 65536 : 256
            ) else { continue }
            let read = NDEFTagMapping.extractType5Message(
                from: blocks.enumerated().map { .init(number: $0.offset, data: $0.element) }
            )
            if read != message { bad.append("bs=\(blockSize) bc=\(blockCount)") }
        }
        #expect(bad.isEmpty, "\(bad.prefix(3))")
    }

    /// Random control-TLV prefixes: a produced layout must read back, and every prefix
    /// of the ordered writes must leave the old, an empty or the new message.
    @Test
    func `Fuzzed Type 2 writes survive tearing at every write`() throws {
        var rng = SplitMix(state: 6)
        var readBad: [String] = []
        var tornBad: [String] = []
        let offset = 16
        for index in 0 ..< 1500 {
            let capacity = [48, 144, 496, 872, rng.int(8 ... 400)][rng.int(0 ... 4)]
            var lead = Data()
            for _ in 0 ..< rng.int(0 ... 3) {
                switch rng.int(0 ... 3) {
                case 0: lead.append(0x00)
                case 1: lead += Data([0x01, 0x03, UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 4))])
                case 2: lead += Data([0x02, 0x03, UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 255)), UInt8(rng.int(0 ... 4))])
                default: lead += Data([0x01, 0x03, 0xF0, 0x10, 0x04]) // reserves bytes far away
                }
            }
            let oldMessage = NDEFMessage.text(String(repeating: "o", count: rng.int(1 ... 300))).data
            let newMessage = index % 7 == 0
                ? Data()
                : NDEFMessage(records: [.mime(type: "a/b", data: Data(repeating: 0x5A, count: rng.int(0 ... 400)))]).data
            // The tag as read: control TLVs, then the old NDEF TLV.
            let leading = try Data((lead + NDEFTagMapping.encodeNDEFTLV(oldMessage)).prefix(min(capacity, 12 + rng.int(0 ... 4) * 4)))
            guard let layout = try? NDEFTagMapping.type2WriteLayout(leadingBytes: leading, dataAreaOffset: offset, capacity: capacity),
                  let area = try? NDEFTagMapping.buildType2Area(
                      message: newMessage,
                      capacity: layout.capacity,
                      preservedPrefix: layout.preservedPrefix,
                      endsDataArea: layout.endsDataArea
                  )
            else { continue }

            // The old message, or an empty one when it does not fit the layout.
            let oldArea = try (try? NDEFTagMapping.buildType2Area(
                message: oldMessage,
                capacity: layout.capacity,
                preservedPrefix: layout.preservedPrefix,
                endsDataArea: layout.endsDataArea
            )) ?? NDEFTagMapping.buildType2Area(
                message: Data(),
                capacity: layout.capacity,
                preservedPrefix: layout.preservedPrefix,
                endsDataArea: layout.endsDataArea
            )
            var memory = [UInt8](oldArea)
            memory += [UInt8](rng.bytes(capacity - memory.count))
            let oldReadable = NDEFTagMapping.extractType2TLVNDEF(from: Data(memory), dataAreaOffset: offset)
            let pages = stride(from: 0, to: area.count, by: 4).map {
                (block: 4 + $0 / 4, data: Data(area[$0 ..< min($0 + 4, area.count)]))
            }
            let order = NDEFTagMapping.lengthLastWriteOrder(pages, blockSize: 4, tlvOffset: offset + layout.preservedPrefix.count)
            for (step, write) in order.enumerated() {
                let start = (write.block - 4) * 4
                for (position, byte) in write.data.enumerated() {
                    memory[start + position] = byte
                }
                let read = NDEFTagMapping.extractType2TLVNDEF(from: Data(memory), dataAreaOffset: offset)
                let fine = read == nil || read == Data() || read == newMessage || read == oldReadable
                if !fine {
                    tornBad.append("prefix=\(layout.preservedPrefix.hexString) new=\(newMessage.count) step=\(step)/\(order.count)")
                }
            }
            if NDEFTagMapping.extractType2TLVNDEF(from: Data(memory), dataAreaOffset: offset) != newMessage {
                readBad.append("prefix=\(layout.preservedPrefix.hexString) cap=\(layout.capacity) n=\(newMessage.count)")
            }
        }
        #expect(readBad.isEmpty, "\(readBad.prefix(3))")
        #expect(tornBad.isEmpty, "\(tornBad.prefix(3))")
    }

    // MARK: - Tearing with a 3-byte length spanning two blocks

    @Test(arguments: [(5, 4), (10, 4), (5, 8), (10, 8), (3, 4), (6, 8)])
    func `Every tear point leaves the old, an empty or the new message`(prefixLength: Int, blockSize: Int) throws {
        // The TLV area starts at block 2; NULL TLVs fill the prefix so the NDEF TLV
        // starts at `prefixLength`, which puts FF hi lo across a block boundary.
        let baseOffset = 2 * blockSize
        let capacity = 1024
        let oldMessage = Data(repeating: 0x11, count: 0x0104)
        let newMessage = Data(repeating: 0x22, count: 0x0230)
        let prefix = Data(count: prefixLength)

        var memory = Data(count: baseOffset) + prefix + (try NDEFTagMapping.encodeNDEFTLV(oldMessage))
        memory += Data(count: baseOffset + capacity - memory.count)
        var newArea = prefix + (try NDEFTagMapping.encodeNDEFTLV(newMessage))
        newArea += Data(count: (blockSize - newArea.count % blockSize) % blockSize)
        let writes = stride(from: 0, to: newArea.count, by: blockSize).map {
            (block: 2 + $0 / blockSize, data: Data(newArea[$0 ..< $0 + blockSize]))
        }
        let order = NDEFTagMapping.lengthLastWriteOrder(writes, blockSize: blockSize, tlvOffset: baseOffset + prefixLength)

        for (step, write) in order.enumerated() {
            memory.replaceSubrange(write.block * blockSize ..< (write.block + 1) * blockSize, with: write.data)
            let read = NDEFTagMapping.extractTLVNDEF(from: Data(memory[baseOffset...]))
            #expect(
                read == oldMessage || read == Data() || read == newMessage,
                "tear after write \(step + 1) of \(order.count): length \(read?.count ?? -1)"
            )
        }
        #expect(NDEFTagMapping.extractTLVNDEF(from: Data(memory[baseOffset...])) == newMessage)
    }

    @Test
    func `Length blocks spanning a boundary are finalised in descending block order`() {
        // TLV at byte 2 of block 0: 03 FF | 01 2C ...
        let writes: [(block: Int, data: Data)] = [
            (0, Data([0xE1, 0x40, 0x03, 0xFF])),
            (1, Data([0x01, 0x2C, 0xAA, 0xAA])),
            (2, Data([0xAA, 0xAA, 0xAA, 0xAA])),
        ]
        let ordered = NDEFTagMapping.lengthLastWriteOrder(writes, blockSize: 4, tlvOffset: 2)
        // before: [0, 1, 2, 0, 1], a tear before the last write left FF 01 2C... as FF 01 00.
        #expect(ordered.map(\.block) == [0, 1, 2, 1, 0])
        #expect(ordered.last?.data == writes[0].data)
    }

    @Test
    func `Type 2 write with a Lock Control TLV survives tearing at every write`() async throws {
        // NTAG215 (CC2 3Eh, 496 bytes); a 5-byte Lock Control TLV puts the NDEF TLV at
        // byte 21, so its 3-byte length FF 01 22 spans pages 5 and 6.
        let lockTLV = Data([0x01, 0x03, 0x88, 0x10, 0x06])
        let oldMessage = NDEFMessage.text("old").data
        let message = NDEFMessage(records: [.mime(type: "a/b", data: Data(repeating: 0x5A, count: 291))])
        var base: [UInt8: Data] = [3: Data([0xE1, 0x10, 0x3E, 0x00])]
        let oldArea = try NDEFTagMapping.buildType2Area(message: oldMessage, capacity: 496, preservedPrefix: lockTLV)
        for page in 0 ..< 124 {
            base[UInt8(4 + page)] = Data(oldArea[page * 4 ..< page * 4 + 4])
        }
        let info = CardInfo(type: .ntag215, uid: Data([0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))

        let probe = TearingType2Tag(pages: base)
        try await CoreExtendedNFC.writeNDEF(message, info: info, transport: probe)
        #expect(NDEFTagMapping.extractType2TLVNDEF(from: probe.dataArea(496), dataAreaOffset: 16) == message.data)
        #expect(probe.dataArea(5) == lockTLV)

        for completed in 0 ..< probe.writes {
            let tag = TearingType2Tag(pages: base, failAfter: completed)
            _ = try? await CoreExtendedNFC.writeNDEF(message, info: info, transport: tag)
            let read = NDEFTagMapping.extractType2TLVNDEF(from: tag.dataArea(496), dataAreaOffset: 16)
            #expect(
                read == nil || read == Data() || read == message.data || read == oldMessage,
                "tear after \(completed) writes: length \(read?.count ?? -1)"
            )
        }
    }

    // MARK: - TLV length limit (00FFh-FFFEh)

    @Test
    func `NDEF TLV lengths stop at FFFEh`() throws {
        let largest = try NDEFTagMapping.encodeNDEFTLV(Data(count: 0xFFFE))
        #expect(largest.prefix(4) == Data([0x03, 0xFF, 0xFF, 0xFE]))
        // before: FFFFh was encoded as the reserved length FF FF FF, 70000 as 11 70
        #expect(throws: NFCError.self) { try NDEFTagMapping.encodeNDEFTLV(Data(count: 0xFFFF)) }
        #expect(throws: NFCError.self) { try NDEFTagMapping.encodeNDEFTLV(Data(count: 70000)) }
    }

    @Test
    func `Type 5 extended write refuses a message longer than FFFEh bytes`() throws {
        // 8-byte CC (E2h, MLEN FFFFh), 32-byte blocks, 8192 blocks.
        let lead = Data([0xE2, 0x40, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]) + Data(count: 24)
        let message = try NDEFMessage(records: [.mime(type: "a/b", data: Data(repeating: 0x33, count: 70000))]).validatedData()
        #expect(throws: NFCError.ndefCapacityExceeded(required: message.count + 5, capacity: 0xFFFE + 5)) {
            try NDEFTagMapping.type5NDEFWrites(
                message: message,
                leadingBytes: lead,
                blockSize: 32,
                blockCount: 8192,
                addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
            )
        }
        #expect(throws: NFCError.self) {
            try NDEFTagMapping.buildType5Blocks(
                message: message,
                blockSize: 32,
                blockCount: 8192,
                addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
            )
        }

        // The largest message still fits and reads back.
        let largest = Data(repeating: 0x44, count: 0xFFFE)
        let writes = try NDEFTagMapping.type5NDEFWrites(
            message: largest,
            leadingBytes: lead,
            blockSize: 32,
            blockCount: 8192,
            addressableBlockCount: NDEFTagMapping.type5ExtendedAddressableBlocks
        )
        var memory = [0: lead]
        for write in writes {
            memory[write.block] = write.data
        }
        let blocks = (0 ... memory.keys.max()!).map { MemoryDump.Block(number: $0, data: memory[$0] ?? Data(count: 32)) }
        #expect(NDEFTagMapping.extractType5Message(from: blocks) == largest)
    }

    // MARK: - Type 2 leading bytes that are not control TLVs

    @Test
    func `Type 2 write overwrites page 4 garbage that starts with 01h`() async throws {
        // before: 01 FF 12 34 was read as a 4660-byte Lock Control TLV and the write refused.
        var base: [UInt8: Data] = [3: Data([0xE1, 0x10, 0x12, 0x00]), 4: Data([0x01, 0xFF, 0x12, 0x34])]
        for page in 5 ..< 45 {
            base[UInt8(page)] = Data([0xAB, 0xCD, 0xEF, 0x01])
        }
        let tag = TearingType2Tag(pages: base)
        let info = CardInfo(type: .ntag213, uid: tag.identifier)
        try await CoreExtendedNFC.writeNDEF(.text("x"), info: info, transport: tag)
        #expect(tag.pages[4]?.first == 0x03)
        #expect(NDEFTagMapping.extractType2TLVNDEF(from: tag.dataArea(144), dataAreaOffset: 16) == NDEFMessage.text("x").data)
    }

    @Test
    func `Type 2 write does not keep a well-formed control TLV followed by garbage`() async throws {
        // before: 01 03 12 34 56 was kept as a prefix in front of the new NDEF TLV.
        var base: [UInt8: Data] = [
            3: Data([0xE1, 0x10, 0x12, 0x00]),
            4: Data([0x01, 0x03, 0x12, 0x34]),
            5: Data([0x56, 0xAB, 0xCD, 0xEF]),
        ]
        for page in 6 ..< 45 {
            base[UInt8(page)] = Data([0xAB, 0xCD, 0xEF, 0x01])
        }
        let tag = TearingType2Tag(pages: base)
        try await CoreExtendedNFC.writeNDEF(.text("x"), info: CardInfo(type: .ntag213, uid: tag.identifier), transport: tag)
        #expect(tag.pages[4]?.first == 0x03)
        #expect(NDEFTagMapping.extractType2TLVNDEF(from: tag.dataArea(144), dataAreaOffset: 16) == NDEFMessage.text("x").data)
    }

    @Test
    func `Type 2 layout keeps control TLVs only when an NDEF or Terminator TLV follows`() throws {
        let lock = Data([0x01, 0x03, 0xA0, 0x10, 0x44])
        // Followed by an NDEF TLV (after a NULL TLV) or a Terminator TLV: kept.
        let kept = try NDEFTagMapping.type2WriteLayout(leadingBytes: lock + Data([0x00, 0x03, 0x00, 0xFE]), dataAreaOffset: 16, capacity: 144)
        #expect(kept?.preservedPrefix == lock)
        let terminated = try NDEFTagMapping.type2WriteLayout(leadingBytes: lock + Data([0xFE, 0x00]), dataAreaOffset: 16, capacity: 144)
        #expect(terminated?.preservedPrefix == lock)
        // Followed by other bytes, or with a length other than 3: written from the start.
        for leading in [lock + Data([0xAB, 0xCD]), Data([0x01, 0xFF, 0x12, 0x34, 0x00]), Data([0x02, 0x02, 0x00, 0x00, 0x03])] {
            let plain = try NDEFTagMapping.type2WriteLayout(leadingBytes: leading, dataAreaOffset: 16, capacity: 144)
            #expect(plain?.preservedPrefix == Data())
            #expect(plain?.capacity == 144)
        }
        // Only NULL TLVs after it so far: more bytes are needed.
        #expect(try NDEFTagMapping.type2WriteLayout(leadingBytes: lock + Data(count: 7), dataAreaOffset: 16, capacity: 144) == nil)
        // A confirmed Memory Control TLV reserving bytes next to it is still refused.
        #expect(throws: NFCError.self) {
            try NDEFTagMapping.type2WriteLayout(
                leadingBytes: Data([0x02, 0x03, 0x30, 0x08, 0x02, 0x03, 0x00, 0xFE]),
                dataAreaOffset: 16,
                capacity: 48
            )
        }
    }

    @Test
    func `Type 2 control area and exact-fill edges`() throws {
        // Size 00h means 256 lock bits (32 bytes); BytesPerPage 15.
        #expect(NDEFTagMapping.type2ControlArea(tag: 1, value: Data([0x00, 0x00, 0x02])) == 0 ..< 32)
        #expect(NDEFTagMapping.type2ControlArea(tag: 2, value: Data([0xFF, 0x00, 0x0F])) == (15 * 32768 + 15) ..< (15 * 32768 + 15 + 256))
        // A truncated FF FF FF length does not read.
        #expect(NDEFTagMapping.extractType2TLVNDEF(from: Data([0x03, 0xFF, 0xFF, 0xFF]) + Data(count: 100), dataAreaOffset: 16) == nil)
        // 46-byte message: TLV 48 bytes, terminator 49.
        let message = Data(repeating: 0xD0, count: 46)
        #expect(throws: NFCError.self) { try NDEFTagMapping.buildType2Area(message: message, capacity: 47) }
        #expect(try NDEFTagMapping.buildType2Area(message: message, capacity: 48).count == 48)
        #expect(try NDEFTagMapping.buildType2Area(message: message, capacity: 49).last == 0xFE)
        #expect(try NDEFTagMapping.buildType2Area(message: message, capacity: 50).count == 50)
        // An empty message's length block is written once.
        let order = NDEFTagMapping.lengthLastWriteOrder([(4, Data([0x03, 0x00, 0xFE, 0x00]))], blockSize: 4, tlvOffset: 16)
        #expect(order.count == 1)
    }

    // MARK: - Type 5 CC checks

    @Test
    func `Type 5 read checks the CC version and read access`() {
        let tlv = [MemoryDump.Block(number: 1, data: Data([0x03, 0x03, 0xD0, 0x00])), .init(number: 2, data: Data([0x00, 0xFE, 0, 0]))]
        func read(_ cc: [UInt8]) -> Data? {
            NDEFTagMapping.extractType5Message(from: [.init(number: 0, data: Data(cc))] + tlv)
        }
        #expect(read([0xE1, 0x40, 0x02, 0x00]) == Data([0xD0, 0x00, 0x00]))
        // Read-only (write access 11b) is still readable.
        #expect(read([0xE1, 0x43, 0x02, 0x00]) == Data([0xD0, 0x00, 0x00]))
        // before: version 2.0 and read access denied were read anyway.
        #expect(read([0xE1, 0x8C, 0x02, 0x00]) == nil)
        #expect(read([0xE1, 0x80, 0x02, 0x00]) == nil)
        #expect(read([0xE1, 0x44, 0x02, 0x00]) == nil)
        #expect(read([0xE1, 0x4C, 0x02, 0x00]) == nil)

        #expect(throws: NFCError.tagNotNDEFFormatted) {
            try NDEFTagMapping.type5ReadableCCLength(leadingBytes: Data([0xE1, 0x80, 0x02, 0x00]))
        }
        #expect(throws: NFCError.tagLocked) {
            try NDEFTagMapping.type5ReadableCCLength(leadingBytes: Data([0xE1, 0x44, 0x02, 0x00]))
        }
        #expect(throws: NFCError.tagNotNDEFFormatted) {
            try NDEFTagMapping.type5ReadableCCLength(leadingBytes: Data([0x00, 0x40, 0x02, 0x00]))
        }

        // MLEN 0 in the 4-byte CC selects the 8-byte CC; 8-byte MLEN 0 reads nothing.
        let empty = [MemoryDump.Block(number: 0, data: Data([0xE1, 0x40, 0x00, 0x00])), .init(number: 1, data: Data(count: 4)), .init(number: 2, data: Data([0x03, 0x00, 0xFE, 0]))]
        #expect(NDEFTagMapping.extractType5Message(from: empty) == nil)
        let long = [MemoryDump.Block(number: 0, data: Data([0xE1, 0x40, 0x00, 0x00])), .init(number: 1, data: Data([0, 0, 0, 0x02])), .init(number: 2, data: Data([0x03, 0x03, 0xD0, 0x00])), .init(number: 3, data: Data([0x00, 0xFE, 0, 0]))]
        #expect(NDEFTagMapping.extractType5Message(from: long) == Data([0xD0, 0x00, 0x00]))
    }

    @Test
    func `Type 5 read refuses a CC without read access or with a newer major version`() async {
        let cases: [(Data, NFCError)] = [
            (Data([0xE1, 0x44, 0x02, 0x00]), .tagLocked),
            (Data([0xE1, 0x80, 0x02, 0x00]), .tagNotNDEFFormatted),
        ]
        for (cc, expected) in cases {
            let transport = ExtendedMemoryISO15693Tag(blockCount: 16, stored: [0: cc, 1: Data([0x03, 0x03, 0xD0, 0x00]), 2: Data([0x00, 0xFE, 0, 0])])
            let info = CardInfo(type: .iso15693_generic, uid: transport.identifier, icManufacturer: 0x04)
            await #expect(throws: expected) { try await CoreExtendedNFC.readNDEF(info: info, transport: transport) }
        }
    }

    @Test(arguments: [5, 6, 10, 14, 18, 26, 32])
    func `Type 5 format of the largest accepted message reads back for any block size`(blockSize: Int) throws {
        for blockCount in [3, 40, 256] {
            // The largest message buildType5Blocks accepts for this geometry.
            var length = blockCount * blockSize
            var built: [Data]?
            while length >= 0, built == nil {
                built = try? NDEFTagMapping.buildType5Blocks(
                    message: Data(repeating: 0x5A, count: length),
                    blockSize: blockSize,
                    blockCount: blockCount
                )
                if built == nil { length -= 1 }
            }
            let blocks = try #require(built)
            let area = blocks.reduce(Data(), +)
            let ccLength = area[2] == 0x00 ? 8 : 4
            // before: with 10-, 14-, 18- or 26-byte blocks the TLV started at the next block
            // boundary while readers stop at CC + MLEN × 8, so a full message was cut off.
            #expect(area[ccLength] == 0x03)
            #expect(NDEFTagMapping.extractType5Message(
                from: blocks.enumerated().map { .init(number: $0.offset, data: $0.element) }
            ) == Data(repeating: 0x5A, count: length), "bs=\(blockSize) bc=\(blockCount) n=\(length)")
        }
    }

    @Test
    func `Type 5 format write plan agrees with the formatted layout`() throws {
        let message = NDEFMessage.text("odd blocks").data
        for blockSize in [4, 8, 10, 14] {
            let blocks = try NDEFTagMapping.buildType5Blocks(message: message, blockSize: blockSize, blockCount: 40)
            let writes = try NDEFTagMapping.type5NDEFWrites(
                message: message,
                leadingBytes: blocks.reduce(Data(), +),
                blockSize: blockSize,
                blockCount: 40
            )
            #expect(writes.allSatisfy { blocks[$0.block] == $0.data })
        }
    }

    // MARK: - Data slices

    @Test
    func `Public TLV helpers accept Data slices`() throws {
        let full = Data([0xAA, 0xAA, 0xAA, 0x03, 0x02, 0xD0, 0x00, 0xFE])
        #expect(NDEFTagMapping.extractTLVNDEF(from: full[3...]) == Data([0xD0, 0x00]))
        #expect(NDEFTagMapping.extractType2TLVNDEF(from: full[3...], dataAreaOffset: 16) == Data([0xD0, 0x00]))
        let long = Data([0xAA, 0xAA, 0xFF, 0x01, 0x2C])
        #expect(NDEFTagMapping.parseTLVLength(long[2...], offset: 0)! == (0x012C, 3))
        #expect(NDEFTagMapping.parseTLVLength(long[2...], offset: 1)! == (0x01, 1))
        #expect(NDEFTagMapping.parseTLVLength(long[2...], offset: 3) == nil)

        let leading = Data([0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x03, 0xF0, 0x10, 0x04, 0x03, 0x00, 0xFE])
        let layout = try #require(try NDEFTagMapping.type2WriteLayout(leadingBytes: leading[4...], dataAreaOffset: 16, capacity: 48))
        #expect(layout.preservedPrefix == Data([0x01, 0x03, 0xF0, 0x10, 0x04]))

        let area = try NDEFTagMapping.buildType2Area(message: Data([0xD0, 0x00, 0x00]), capacity: 16, preservedPrefix: leading[4 ..< 9])
        #expect(area.startIndex == 0)
        #expect(area[5 ..< 7] == Data([0x03, 0x03]))

        let cc = Data([0x00, 0xE1, 0x40, 0x02, 0x00])
        #expect(NDEFTagMapping.type5FormattedCCLength(leadingBytes: cc[1...]) == 4)
        #expect(NDEFTagMapping.type5DataAreaLength(leadingBytes: cc[1...]) == 16)
        #expect(try NDEFTagMapping.type5ReadableCCLength(leadingBytes: cc[1...]) == 4)

        let message = NDEFMessage.text("slice").data
        #expect(try NDEFMessage(data: (Data([0xAA]) + message)[1...]) == .text("slice"))
    }

    // MARK: - Chunked records

    @Test
    func `Many chunks reassemble into one payload`() throws {
        // Initial chunk (MB, CF, SR, Unknown), 3000 middle chunks, terminating chunk (ME).
        var data = Data([0xB5, 0x00, 0x01, 0x00])
        for index in 0 ..< 3000 {
            data += Data([0x36, 0x00, 0x01, UInt8(truncatingIfNeeded: index + 1)])
        }
        data += Data([0x56, 0x00, 0x01, 0xFF])
        let records = try NDEFMessage(data: data).records
        #expect(records.count == 1)
        #expect(records[0].typeNameFormat == .unknown)
        #expect(records[0].payload.count == 3002)
        #expect(records[0].payload.first == 0x00)
        #expect(records[0].payload[1] == 0x01)
        #expect(records[0].payload.last == 0xFF)
    }
}

/// ISO 15693 tag memory with extended commands; records which blocks were read past 255.
private final class ExtendedMemoryISO15693Tag: ISO15693TagTransporting, @unchecked Sendable {
    let identifier = Data([0xE0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    let icManufacturerCode = 0x04
    let blockCount: Int
    var stored: [UInt8: Data]
    var extendedReads: [Int] = []

    init(blockCount: Int, stored: [UInt8: Data]) {
        self.blockCount = blockCount
        self.stored = stored
    }

    func extendedReadBlock(_ number: UInt16) async throws -> Data {
        extendedReads.append(Int(number))
        return Data(count: 4)
    }

    func extendedWriteBlock(_: UInt16, data _: Data) async throws {}

    func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("unused")
    }

    func sendAPDU(_: CommandAPDU) async throws -> ResponseAPDU {
        throw NFCError.unsupportedOperation("unused")
    }

    func readBlock(_ number: UInt8) async throws -> Data {
        stored[number] ?? Data(count: 4)
    }

    func writeBlock(_ number: UInt8, data: Data) async throws {
        stored[number] = data
    }

    func readBlocks(range _: NSRange) async throws -> [Data] {
        throw NFCError.unsupportedOperation("unused")
    }

    func getSystemInfo() async throws -> ISO15693SystemInfo {
        ISO15693SystemInfo(uid: identifier, dsfid: 0x00, afi: 0x00, blockSize: 4, blockCount: blockCount, icReference: 0x01)
    }

    func getBlockSecurityStatus(range _: NSRange) async throws -> [Bool] {
        []
    }
}
