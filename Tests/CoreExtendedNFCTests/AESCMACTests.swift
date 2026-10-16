// AES-CMAC input-handling tests. Vectors: RFC 4493 §4 Example 3 (40-byte
// message), https://www.rfc-editor.org/rfc/rfc4493#section-4
@testable import CoreExtendedNFC
import Foundation
import Testing

struct AESCMACTests {
    private static let key = Data([
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    ])

    private static let message40 = Data([
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
        0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    ])

    private static let mac40 = Data([
        0xDF, 0xA6, 0x67, 0x47, 0xDE, 0x9A, 0xE6, 0x30,
        0x30, 0xCA, 0x32, 0x61, 0x14, 0x97, 0xC8, 0x27,
    ])

    @Test
    func `AES-CMAC accepts a message slice with a non-zero start index`() throws {
        let framed = Data([0xAA, 0xBB, 0xCC]) + Self.message40 + Data([0xDD])
        let slice = framed[3 ..< 43]
        #expect(slice.startIndex == 3)
        #expect(try AESCMAC.mac(key: Self.key, message: slice) == Self.mac40)
    }

    @Test
    func `AES-CMAC accepts a block-aligned message slice`() throws {
        // First 32 bytes of the RFC message, complete-block path (K1).
        let reference = try AESCMAC.mac(key: Self.key, message: Data(Self.message40.prefix(32)))
        let framed = Data([0x00]) + Self.message40
        #expect(try AESCMAC.mac(key: Self.key, message: framed[1 ..< 33]) == reference)
    }

    @Test
    func `AES-CMAC accepts a key slice with a non-zero start index`() throws {
        let framed = Data([0x01, 0x02]) + Self.key
        #expect(try AESCMAC.mac(key: framed.dropFirst(2), message: Self.message40) == Self.mac40)
    }

    @Test
    func `AES-CMAC helpers accept slices`() {
        let a = Data([0xFF, 0x80, 0x01])
        #expect(AESCMAC.shiftLeft(a.dropFirst()) == Data([0x00, 0x02]))
        #expect(AESCMAC.xor(a.dropFirst(), Data([0x0F, 0x0F])) == Data([0x8F, 0x0E]))
    }
}
