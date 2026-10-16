// ISO 14443 CRC and protocol test suite.
//
// ## References
// - ISO/IEC 14443-3:2018 Section 6.2.4: CRC_A (ISO 14443-3A) initial value 0x6363
// - ISO/IEC 14443-3:2018 Section 7.2.5: CRC_B (ISO 14443-3B) initial value 0xFFFF
// - libnfc iso14443-subr.c: CRC computation reference
//   https://github.com/nfc-tools/libnfc/blob/master/libnfc/iso14443-subr.c
@testable import CoreExtendedNFC
import Foundation
import Testing

struct ISO14443Tests {
    // MARK: - CRC_A

    @Test
    func `CRC_A of single byte — verified against libnfc iso14443a_crc`() {
        let (lo, hi) = ISO14443.crcA(Data([0x00]))
        #expect(lo == 0xFE)
        #expect(hi == 0x51)
    }

    @Test
    func `CRC_A of READ command — verified against libnfc iso14443a_crc`() {
        // READ page 4: the most common Ultralight command
        let (lo, hi) = ISO14443.crcA(Data([0x30, 0x04]))
        #expect(lo == 0x26)
        #expect(hi == 0xEE)
    }

    @Test
    func `CRC_A of AUTH command — verified against libnfc iso14443a_crc`() {
        let (lo, hi) = ISO14443.crcA(Data([0x60, 0x00]))
        #expect(lo == 0xF5)
        #expect(hi == 0x7B)
    }

    @Test
    func `CRC_A of HALT command — verified against libnfc iso14443a_crc`() {
        let (lo, hi) = ISO14443.crcA(Data([0x50, 0x00]))
        #expect(lo == 0x57)
        #expect(hi == 0xCD)
    }

    @Test
    func `CRC_A append`() {
        var data = Data([0x30, 0x04])
        ISO14443.appendCrcA(&data)
        #expect(data.count == 4)
        #expect(data[2] == 0x26)
        #expect(data[3] == 0xEE)
    }

    // MARK: - CRC_B

    @Test
    func `CRC_B — verified against libnfc iso14443b_crc`() {
        let (lo, hi) = ISO14443.crcB(Data([0x05, 0x00]))
        #expect(lo == 0xFF)
        #expect(hi == 0x71)
    }

    @Test
    func `CRC_B of multi-byte — verified against libnfc iso14443b_crc`() {
        let (lo, hi) = ISO14443.crcB(Data([0x01, 0x02, 0x03]))
        #expect(lo == 0x3B)
        #expect(hi == 0x9D)
    }

    @Test
    func `CRC_B append`() {
        var data = Data([0x05, 0x00])
        ISO14443.appendCrcB(&data)
        #expect(data.count == 4)
        #expect(data[2] == 0xFF)
        #expect(data[3] == 0x71)
    }

    // MARK: - UID Cascade

    @Test
    func `4-byte UID has no cascade`() {
        let uid = Data([0x01, 0x02, 0x03, 0x04])
        let result = ISO14443.cascadeUID(uid)
        #expect(result == uid)
    }

    @Test
    func `7-byte UID gets single cascade tag`() {
        let uid = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        let result = ISO14443.cascadeUID(uid)
        #expect(result.count == 8)
        #expect(result[0] == 0x88) // cascade tag
        #expect(Data(result[1...]) == uid)
    }

    @Test
    func `10-byte UID gets double cascade tags`() {
        let uid = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A])
        let result = ISO14443.cascadeUID(uid)
        #expect(result.count == 12)
        #expect(result[0] == 0x88)
        #expect(result[1] == 0x01)
        #expect(result[2] == 0x02)
        #expect(result[3] == 0x03)
        #expect(result[4] == 0x88)
        #expect(Data(result[5...]) == Data([0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]))
    }

    // MARK: - ATS Parsing

    @Test
    func `Parse ATS with all optional bytes`() {
        // T0: FSCI=8, TA present (0x10), TB present (0x20), TC present (0x40) → 0x78
        let ats = Data([0x78, 0x77, 0x81, 0x02, 0xAB, 0xCD])
        let info = ISO14443.parseATS(ats)
        #expect(info.fsci == 8)
        #expect(info.ta == 0x77)
        #expect(info.tb == 0x81)
        #expect(info.tc == 0x02)
        #expect(info.historicalBytes == Data([0xAB, 0xCD]))
        #expect(info.maxFrameSize == 256)
    }

    @Test
    func `Parse ATS with no optional bytes`() {
        let ats = Data([0x05]) // FSCI=5, no TA/TB/TC
        let info = ISO14443.parseATS(ats)
        #expect(info.fsci == 5)
        #expect(info.ta == nil)
        #expect(info.tb == nil)
        #expect(info.tc == nil)
        #expect(info.historicalBytes.isEmpty)
        #expect(info.maxFrameSize == 64)
    }

    @Test
    func `Parse empty ATS`() {
        let info = ISO14443.parseATS(Data())
        #expect(info.fsci == 0)
        #expect(info.ta == nil)
        #expect(info.historicalBytes.isEmpty)
    }

    @Test
    func `FSCI to max frame size mapping`() {
        let expected = [16, 24, 32, 40, 48, 64, 96, 128, 256]
        for (fsci, size) in expected.enumerated() {
            let ats = Data([UInt8(fsci)])
            let info = ISO14443.parseATS(ats)
            #expect(info.maxFrameSize == size)
        }
    }
}
