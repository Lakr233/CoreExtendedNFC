// AES Secure Messaging test suite (post-PACE/CA).
//
// ## References
// - ICAO Doc 9303 Part 11, Section 9.8: Secure Messaging
// - BSI TR-03110 Part 3, Section A.3: AES-based Secure Messaging conventions
//   https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html
// - BSI TR-03110 Part 3: SSC is always 8 bytes; AES IV = AES-ECB(KSenc, 0x00^8 || SSC)
// - BSI TR-03110 Part 3: MAC truncated to 8 bytes for DO'8E
// - JMRTD AESSecureMessagingWrapper.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/AESSecureMessagingWrapper.java
@testable import CoreExtendedNFC
import Foundation
import Testing

struct AESSecureMessagingTests {
    // MARK: - SSC Convention

    // BSI TR-03110 Part 3, Section A.3: SSC is always 8 bytes

    @Test
    func `SSC is always 8 bytes regardless of mode`() {
        #expect(SMEncryptionMode.tripleDES.sscLength == 8)
        #expect(SMEncryptionMode.aes128.sscLength == 8)
        #expect(SMEncryptionMode.aes192.sscLength == 8)
        #expect(SMEncryptionMode.aes256.sscLength == 8)
    }

    @Test
    func `AES block size is 16, 3DES block size is 8`() {
        #expect(SMEncryptionMode.tripleDES.blockSize == 8)
        #expect(SMEncryptionMode.aes128.blockSize == 16)
        #expect(SMEncryptionMode.aes192.blockSize == 16)
        #expect(SMEncryptionMode.aes256.blockSize == 16)
    }

    @Test
    func `MAC output is always truncated to 8 bytes`() {
        #expect(SMEncryptionMode.tripleDES.macLength == 8)
        #expect(SMEncryptionMode.aes128.macLength == 8)
        #expect(SMEncryptionMode.aes192.macLength == 8)
        #expect(SMEncryptionMode.aes256.macLength == 8)
    }

    // MARK: - AES IV Computation Convention

    @Test
    func `AES IV is computed from paddedSSC = [0x00]*8 || SSC`() throws {
        // Given an 8-byte SSC
        let ssc = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
        let paddedSSC = Data(repeating: 0x00, count: 8) + ssc

        #expect(paddedSSC.count == 16, "Padded SSC should be 16 bytes (AES block size)")
        #expect(paddedSSC[0 ..< 8] == Data(repeating: 0x00, count: 8), "First 8 bytes should be zeros")
        #expect(paddedSSC[8 ..< 16] == ssc, "Last 8 bytes should be the SSC")

        // The IV = AES-ECB(KSenc, paddedSSC) — verify dimensions
        let ksEnc = Data(repeating: 0x01, count: 16)
        let iv = try CryptoUtils.aesECBEncrypt(key: ksEnc, message: paddedSSC)
        #expect(iv.count == 16, "AES IV should be 16 bytes (one AES block)")
    }

    // MARK: - CMAC Input Convention

    @Test
    func `AES-CMAC is computed over padded input and truncated to 8 bytes`() throws {
        let key = Data(repeating: 0x42, count: 16)
        let message = ISO9797Padding.pad(Data([0x01, 0x02, 0x03, 0x04]), blockSize: 16)

        let fullMAC = try AESCMAC.mac(key: key, message: message)
        #expect(fullMAC.count == 16, "Full AES-CMAC should be 16 bytes")

        let truncatedMAC = Data(fullMAC.prefix(8))
        #expect(truncatedMAC.count == 8, "Truncated MAC should be 8 bytes")
    }

    // 3DES (ICAO 9303-11 Appendix D.4) and AES-128 end-to-end SM vectors live in
    // PassportConformanceTests.

    // MARK: - AES SM Transport Construction

    @Test
    func `AES-128 SM transport with 8-byte SSC`() {
        let ksEnc = Data(repeating: 0x01, count: 16)
        let ksMac = Data(repeating: 0x02, count: 16)
        let ssc = Data(repeating: 0x00, count: 8) // 8-byte SSC

        let mock = MockTransport()
        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc,
            mode: .aes128
        )
        #expect(sm.identifier == mock.identifier)
    }

    @Test
    func `AES-256 SM transport with 8-byte SSC`() {
        let ksEnc = Data(repeating: 0x01, count: 32)
        let ksMac = Data(repeating: 0x02, count: 32)
        let ssc = Data(repeating: 0x00, count: 8) // 8-byte SSC

        let mock = MockTransport()
        let sm = SecureMessagingTransport(
            transport: mock,
            ksEnc: ksEnc,
            ksMac: ksMac,
            ssc: ssc,
            mode: .aes256
        )
        #expect(sm.identifier == mock.identifier)
    }
}

// MARK: - Data hex initializer for test vectors

private extension Data {
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
