// MIFARE Classic access bits test suite.
//
// ## References
// - NXP MF1S50YYX (MIFARE Classic 1K) datasheet: Section 8.7 Access conditions
//   https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
// - Default ACL: 0xFF 0x07 0x80 0x69 (transport configuration)
// - libnfc nfc-mfclassic.c:
//   https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-mfclassic.c
@testable import CoreExtendedNFC
import Foundation
import Testing

struct AccessBitsTests {
    @Test
    func `Decode default access bits (0xFF 0x07 0x80)`() {
        // Default: 0xFF 0x07 0x80 0x69
        // C1=0x0, C2=0x0, C3=0x0 for blocks 0-2 (data blocks, full access)
        // C1=0, C2=0, C3=1 for block 3 (trailer: key A never readable, key B readable)
        let bytes = Data([0xFF, 0x07, 0x80, 0x69])
        let result = AccessBits.decode(bytes)
        #expect(result != nil)
        #expect(result?.count == 4)

        // Data blocks 0,1,2: all bits 0 → condition 0
        #expect(result?[0].condition == 0)
        #expect(result?[1].condition == 0)
        #expect(result?[2].condition == 0)

        // Trailer block 3: C1=0, C2=0, C3=1 → condition 4
        #expect(result?[3].c3 == true)
        #expect(result?[3].condition == 4)
    }

    @Test
    func `Invalid complement bits returns nil`() {
        // Corrupt the complement: byte 6 should be complement of C1/C2, make it wrong
        let bytes = Data([0x00, 0x00, 0x00])
        let result = AccessBits.decode(bytes)
        #expect(result == nil)
    }

    @Test
    func `Too-short data returns nil`() {
        let result = AccessBits.decode(Data([0xFF, 0x07]))
        #expect(result == nil)
    }

    @Test
    func `Transport configuration access bits`() {
        // Transport configuration: C1C2C3 = 001 for trailer
        // Byte6: ~C2_b1~C2_b0 | ~C1_b3~C1_b2~C1_b1~C1_b0
        // All data blocks: C1=0,C2=0,C3=0
        let bytes = AccessBits.defaultBytes
        let result = AccessBits.decode(bytes)
        #expect(result != nil)
    }
}
