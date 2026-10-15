// BAC (Basic Access Control) test suite.
//
// ## References
// - ICAO Doc 9303 Part 11, Section 9.7 & Appendix D: BAC protocol and test vectors
//   https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
// - ICAO Doc 9303 Part 11, Appendix D.1: Document number L898902C<, DOB 690806, DOE 940623
// - ISO/IEC 11770-2: Key Establishment mechanism 6 (mutual authenticate)
// - JMRTD BACProtocol.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/protocol/BACProtocol.java
// - Android AOSP NFCPassportReader (reference for BAC flow):
//   https://github.com/nicholasng1998/NFCPassportReader (community implementation)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct BACTests {
    // MARK: - Full BAC Flow with Mock Transport

    // ICAO 9303 Part 11, Section 9.7.2: GET CHALLENGE → MUTUAL AUTHENTICATE

    @Test
    func `BAC authentication succeeds with ICAO Appendix D.1 MRZ keys`() async throws {
        let mock = MockTransport()

        // ICAO 9303 Part 11 Appendix D.1 MRZ key
        let mrzKey = "L898902C<369080619406236"

        // Pre-computed values for deterministic testing
        let rndIFD = Data([
            0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26,
        ])
        let kIFD = Data([
            0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0,
            0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B,
        ])

        // Derive keys to compute expected chip response
        let kseed = KeyDerivation.generateKseed(mrzKey: mrzKey)
        let kenc = KeyDerivation.deriveKey(keySeed: kseed, mode: .enc)
        let kmac = KeyDerivation.deriveKey(keySeed: kseed, mode: .mac)

        // Mock chip random
        let rndICC = Data([
            0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12,
        ])

        // Compute what the chip would respond with:
        // Chip creates: S_chip = rndICC || rndIFD || kICC
        let kICC = Data([
            0x0B, 0x4F, 0x80, 0x32, 0x3E, 0xB3, 0x19, 0x1C,
            0xB0, 0x49, 0x70, 0xCB, 0x40, 0x52, 0x79, 0x0B,
        ])
        var sChip = Data()
        sChip.append(rndICC)
        sChip.append(rndIFD)
        sChip.append(kICC)

        let eICC = try CryptoUtils.tripleDESEncrypt(key: kenc, message: sChip)
        let paddedEICC = ISO9797Padding.pad(eICC, blockSize: 8)
        let mICC = try ISO9797MAC.mac(key: kmac, message: paddedEICC)
        var authResponse = eICC
        authResponse.append(mICC)

        // Set up mock responses:
        // 1. GET CHALLENGE → rndICC
        // 2. MUTUAL AUTHENTICATE → encrypted response
        mock.apduResponses = [
            ResponseAPDU(data: rndICC, sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: authResponse, sw1: 0x90, sw2: 0x00),
        ]

        let smTransport = try await BACHandler.performBAC(
            mrzKey: mrzKey,
            transport: mock,
            rndIFD: rndIFD,
            kIFD: kIFD
        )

        // Verify the transport was created
        #expect(smTransport.identifier == mock.identifier)

        // Verify correct APDUs were sent
        #expect(mock.sentAPDUs.count == 2)

        // First APDU: GET CHALLENGE
        #expect(mock.sentAPDUs[0].ins == 0x84)
        #expect(mock.sentAPDUs[0].le == 0x08)

        // Second APDU: MUTUAL AUTHENTICATE
        #expect(mock.sentAPDUs[1].ins == 0x82)
        // ICAO 9303-11 Appendix D.3: E_IFD || M_IFD
        #expect(mock.sentAPDUs[1].data == Data(hexString:
            "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7"))
    }

    @Test
    func `BAC fails when GET CHALLENGE returns wrong length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data([0x01, 0x02, 0x03]), sw1: 0x90, sw2: 0x00), // 3 bytes instead of 8
        ]

        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(mrzKey: "test", transport: mock)
        }
    }

    @Test
    func `BAC fails when GET CHALLENGE returns error status`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(), sw1: 0x6A, sw2: 0x82), // File not found
        ]

        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(mrzKey: "test", transport: mock)
        }
    }

    @Test
    func `BAC fails when MUTUAL AUTHENTICATE returns error status`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(repeating: 0xAA, count: 8), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(), sw1: 0x69, sw2: 0x82), // Security status not satisfied
        ]

        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(mrzKey: "test", transport: mock)
        }
    }

    @Test
    func `BAC fails when MUTUAL AUTHENTICATE returns wrong length`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            ResponseAPDU(data: Data(repeating: 0xAA, count: 8), sw1: 0x90, sw2: 0x00),
            ResponseAPDU(data: Data(repeating: 0xBB, count: 20), sw1: 0x90, sw2: 0x00), // 20 instead of 40
        ]

        await #expect(throws: NFCError.self) {
            _ = try await BACHandler.performBAC(mrzKey: "test", transport: mock)
        }
    }
}
