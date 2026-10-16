import Foundation
import Testing

// MRZ document number parsing, including long document numbers.
//
// ## References
// - ICAO 9303-5 §4.2.2 Note j and §4.2.4 (TD1 long document number)
// - ICAO 9303-6 §4.2.2 Note j and §4.2.4 (TD2 long document number)
@testable import CoreExtendedNFC

struct MRZDataTests {
    // Document number D23145890734: principal D23145890, overflow 734, check digit 9.

    @Test
    func `TD1 long document number is reassembled from optional data`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOD23145890<7349<XYZ<<<<<<<"
                + "7408122F1204159UTO<<<<<<<<<<<4"
                + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        )

        #expect(mrz.format == .td1)
        #expect(mrz.documentNumber == "D23145890734")
        #expect(mrz.optionalData1 == "XYZ")
        #expect(mrz.dateOfBirth == "740812")
        #expect(mrz.dateOfExpiry == "120415")
        #expect(MRZKeyGenerator.checkDigit("D23145890734") == "9")
        #expect(
            MRZKeyGenerator.computeMRZKey(
                documentNumber: mrz.documentNumber,
                dateOfBirth: mrz.dateOfBirth,
                dateOfExpiry: mrz.dateOfExpiry
            ) == "D2314589073497408122120415" + "9"
        )
    }

    @Test
    func `TD1 long document number filling the optional data leaves it empty`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOD23145890<7349<<<<<<<<<<<"
                + "7408122F1204159UTO<<<<<<<<<<<6"
                + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        )

        #expect(mrz.documentNumber == "D23145890734")
        #expect(mrz.optionalData1 == "")
    }

    @Test
    func `TD1 standard document number keeps optional data intact`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOD231458907ABC<<<<<<<<<<<<"
                + "7408122F1204159UTO<<<<<<<<<<<6"
                + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        )

        #expect(mrz.documentNumber == "D23145890")
        #expect(mrz.optionalData1 == "ABC")
    }

    @Test
    func `TD2 long document number is reassembled from optional data`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                + "D23145890<UTO7408122F12041597349<<<2"
        )

        #expect(mrz.format == .td2)
        #expect(mrz.documentNumber == "D23145890734")
        #expect(mrz.optionalData1 == "")
        #expect(mrz.nationality == "UTO")
        #expect(mrz.dateOfBirth == "740812")
        #expect(mrz.sex == "F")
        #expect(mrz.dateOfExpiry == "120415")
    }

    @Test
    func `TD2 standard document number keeps optional data intact`() throws {
        let mrz = try MRZData(
            mrzString: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
                + "D231458907UTO7408122F1204159AB<<<<<6"
        )

        #expect(mrz.documentNumber == "D23145890")
        #expect(mrz.optionalData1 == "AB")
    }
}
