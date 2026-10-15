// Hex/byte/parity utility test suite.
//
// ## References
// - libnfc nfc-utils.c: hex conversion and parity utilities
//   https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-utils.c
// - DES odd parity: each byte must have odd number of 1-bits (FIPS 46-3)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct HexUtilsTests {
    @Test
    func `Data to hex string`() {
        let data = Data([0x0A, 0x1B, 0x2C])
        #expect(data.hexString == "0A1B2C")
    }

    @Test
    func `Data to hex dump with spaces`() {
        let data = Data([0x0A, 0x1B, 0x2C])
        #expect(data.hexDump == "0A 1B 2C")
    }

    @Test
    func `Empty data to hex`() {
        let data = Data()
        #expect(data.hexString == "")
        #expect(data.hexDump == "")
    }

    @Test
    func `Hex string to data`() {
        let data = Data(hexString: "0A1B2C")
        #expect(data == Data([0x0A, 0x1B, 0x2C]))
    }

    @Test
    func `Hex string with spaces to data`() {
        let data = Data(hexString: "0A 1B 2C")
        #expect(data == Data([0x0A, 0x1B, 0x2C]))
    }

    @Test
    func `Invalid hex string returns nil`() {
        #expect(Data(hexString: "ZZ") == nil)
        #expect(Data(hexString: "0A1") == nil) // odd length
    }

    @Test
    func `Round-trip hex conversion`() {
        let original = Data([0x00, 0xFF, 0x80, 0x7F, 0x01])
        let hex = original.hexString
        let restored = Data(hexString: hex)
        #expect(restored == original)
    }

    @Test
    func `Formatted hex dump has offsets`() {
        let data = Data(repeating: 0xAA, count: 20)
        let formatted = data.hexDumpFormatted
        #expect(formatted.contains("0000:"))
        #expect(formatted.contains("0010:"))
    }
}

struct ByteUtilsTests {
    @Test
    func `UInt16 big-endian`() {
        let data = Data([0x01, 0x02])
        #expect(data.uint16BE == 0x0102)
    }

    @Test
    func `UInt16 little-endian`() {
        let data = Data([0x01, 0x02])
        #expect(data.uint16LE == 0x0201)
    }

    @Test
    func `UInt32 big-endian`() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        #expect(data.uint32BE == 0x0102_0304)
    }

    @Test
    func `UInt32 little-endian`() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        #expect(data.uint32LE == 0x0403_0201)
    }

    @Test
    func `Short data returns 0`() {
        let data = Data([0x01])
        #expect(data.uint16BE == 0)
        #expect(data.uint32BE == 0)
    }
}

struct ParityTests {
    @Test
    func `Odd parity of 0x00 is 1 (0 bits set, need 1 to make odd)`() {
        #expect(Parity.odd(0x00) == 1)
    }

    @Test
    func `Odd parity of 0x01 is 0 (1 bit set, already odd)`() {
        #expect(Parity.odd(0x01) == 0)
    }

    @Test
    func `Odd parity of 0xFF is 1 (8 bits set, need 1 to make odd)`() {
        #expect(Parity.odd(0xFF) == 1)
    }

    @Test
    func `Odd parity of 0x03 is 1 (2 bits set, need 1 to make odd)`() {
        #expect(Parity.odd(0x03) == 1)
    }

    @Test
    func `Odd parity bytes`() {
        let data = Data([0x00, 0x01, 0xFF])
        let result = Parity.oddBytes(data)
        #expect(result[0] == 1) // 0 bits → parity 1
        #expect(result[1] == 0) // 1 bit → parity 0
        #expect(result[2] == 1) // 8 bits → parity 1
    }
}

struct HexUtilsHardeningTests {
    @Test
    func `hexDumpFormatted works on sliced Data`() {
        #expect(Data([0, 1, 2, 3]).dropFirst(2).hexDumpFormatted == "0000: 02 03")
        let sliced = Data(0 ..< 20).dropFirst(3) // bytes 03…13
        #expect(sliced.hexDumpFormatted == "0000: 03 04 05 06 07 08 09 0A\n0008: 0B 0C 0D 0E 0F 10 11 12\n0010: 13")
    }

    @Test
    func `Hex string rejects sign characters`() {
        #expect(Data(hexString: "+1-0") == nil)
        #expect(Data(hexString: "+1") == nil)
        #expect(Data(hexString: "-1") == nil)
        #expect(Data(hexString: "0x0A") == nil)
    }

    @Test
    func `Hex string ignores all whitespace`() {
        #expect(Data(hexString: "0A\t1B\n2c ") == Data([0x0A, 0x1B, 0x2C]))
        #expect(Data(hexString: "") == Data())
    }

    @Test
    func `Hex string rejects non-ASCII digits`() {
        #expect(Data(hexString: "０１") == nil) // full-width digits
    }
}
