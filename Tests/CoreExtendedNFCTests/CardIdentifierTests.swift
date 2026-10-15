// Card identifier (ATQA+SAK) test suite.
//
// ## References
// - ISO/IEC 14443-3A: ATQA (Answer to Request Type A) format
// - NXP AN10833: MIFARE type identification by ATQA + SAK
//   https://www.nxp.com/docs/en/application-note/AN10833.pdf
// - libnfc target-subr.c: ATQA+SAK→card type lookup table
//   https://github.com/nfc-tools/libnfc/blob/master/libnfc/target-subr.c
@testable import CoreExtendedNFC
import Foundation
import Testing

struct CardIdentifierTests {
    @Test
    func `MIFARE Ultralight: ATQA 0x0044, SAK 0x00`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x44]), sak: 0x00)
        #expect(type == .mifareUltralight)
        #expect(type.family == .mifareUltralight)
    }

    @Test
    func `MIFARE Classic 1K: ATQA 0x0004, SAK 0x08`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x04]), sak: 0x08)
        #expect(type == .mifareClassic1K)
        #expect(type.family == .mifareClassic)
        #expect(type.isOperableOnIOS == false)
    }

    @Test
    func `MIFARE Classic 4K: ATQA 0x0002, SAK 0x18`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x02]), sak: 0x18)
        #expect(type == .mifareClassic4K)
        #expect(type.isOperableOnIOS == false)
    }

    @Test
    func `MIFARE Mini: ATQA 0x0004, SAK 0x09`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x04]), sak: 0x09)
        #expect(type == .mifareMini)
    }

    @Test
    func `MIFARE DESFire: ATQA 0x0344, SAK 0x20`() {
        let type = CardIdentifier.identify(atqa: Data([0x03, 0x44]), sak: 0x20)
        #expect(type == .mifareDesfire)
        #expect(type.family == .mifareDesfire)
        #expect(type.isOperableOnIOS == true)
    }

    @Test
    func `MIFARE Plus SL2 2K: ATQA 0x0004, SAK 0x10`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x04]), sak: 0x10)
        #expect(type == .mifarePlusSL2_2K)
        #expect(type.family == .mifarePlus)
    }

    @Test
    func `MIFARE Plus SL2 4K: ATQA 0x0002, SAK 0x11`() {
        let type = CardIdentifier.identify(atqa: Data([0x00, 0x02]), sak: 0x11)
        #expect(type == .mifarePlusSL2_4K)
    }

    @Test
    func `Unknown card returns unknown with ATQA/SAK`() {
        let type = CardIdentifier.identify(atqa: Data([0xFF, 0xFF]), sak: 0x55)
        if case let .unknown(atqa, sak) = type {
            #expect(atqa == Data([0xFF, 0xFF]))
            #expect(sak == 0x55)
        } else {
            #expect(Bool(false), "Expected unknown card type")
        }
    }

    @Test
    func `Card type descriptions are non-empty`() {
        let types: [CardType] = [
            .mifareUltralight, .mifareClassic1K, .mifareDesfire,
            .ntag213, .felicaLite, .iso15693_generic,
        ]
        for type in types {
            #expect(!type.description.isEmpty)
        }
    }
}

/// ATQA byte-order convention: AN10833 notation (MSB first, `00 44`), with an explicit
/// converter for ISO/IEC 14443-3 transmission order (LSB first, `44 00`).
struct CardIdentifierATQAOrderTests {
    @Test
    func `16-bit ATQA values match AN10833 table`() {
        #expect(CardIdentifier.identify(atqaValue: 0x0044, sak: 0x00) == .mifareUltralight)
        #expect(CardIdentifier.identify(atqaValue: 0x0004, sak: 0x08) == .mifareClassic1K)
        #expect(CardIdentifier.identify(atqaValue: 0x0002, sak: 0x18) == .mifareClassic4K)
        #expect(CardIdentifier.identify(atqaValue: 0x0344, sak: 0x20) == .mifareDesfire)
    }

    @Test
    func `Wire-order ATQA converts to the AN10833 value`() {
        #expect(CardIdentifier.atqaValue(wireOrder: Data([0x44, 0x00])) == 0x0044)
        #expect(CardIdentifier.atqaValue(wireOrder: Data([0x44, 0x03])) == 0x0344)
        #expect(CardIdentifier.atqaValue(wireOrder: Data([0x44])) == nil)
        let sliced = Data([0xFF, 0x44, 0x03]).dropFirst()
        #expect(CardIdentifier.atqaValue(wireOrder: sliced) == 0x0344)
    }

    @Test
    func `Data and value forms agree`() {
        #expect(CardIdentifier.identify(atqa: Data([0x03, 0x44]), sak: 0x20)
            == CardIdentifier.identify(atqaValue: 0x0344, sak: 0x20))
        #expect(CardIdentifier.identify(atqaValue: 0x1234, sak: 0xAB) == .unknown(atqa: Data([0x12, 0x34]), sak: 0xAB))
    }
}
