// MRZ key generation test suite.
//
// ## References
// - ICAO Doc 9303 Part 3, Section 4.9: Check digit calculation (weights 7,3,1)
//   https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
// - ICAO Doc 9303 Part 11, Appendix D.1: MRZ key = docNum+CD+DOB+CD+DOE+CD
//   Official worked example: L898902C<3 + 6908061 + 9406236 = "L898902C<369080619406236"
// - JMRTD MRZInfo.java:
//   https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/lds/icao/MRZInfo.java
// - Character values: 0-9→0-9, A-Z→10-35, <→0 (ICAO 9303 Part 3, Table 9)
@testable import CoreExtendedNFC
import Foundation
import Testing

struct MRZKeyGeneratorTests {
    // MARK: - Check Digit

    // ICAO 9303 Part 3, Section 4.9: weighted sum mod 10

    @Test
    func `ICAO check digit for numeric input`() {
        // Known: check digit of "520727" = 3 (weight sum mod 10)
        // 5*7 + 2*3 + 0*1 + 7*7 + 2*3 + 7*1 = 35 + 6 + 0 + 49 + 6 + 7 = 103 → 103 mod 10 = 3
        let digit = MRZKeyGenerator.checkDigit("520727")
        #expect(digit == "3")
    }

    @Test
    func `ICAO check digit for alphanumeric input`() {
        // L898902C< : L=21, 8=8, 9=9, 8=8, 9=9, 0=0, 2=2, C=12, <=0
        // 21*7 + 8*3 + 9*1 + 8*7 + 9*3 + 0*1 + 2*7 + 12*3 + 0*1
        // = 147 + 24 + 9 + 56 + 27 + 0 + 14 + 36 + 0 = 313 → 313 mod 10 = 3
        let digit = MRZKeyGenerator.checkDigit("L898902C<")
        #expect(digit == "3")
    }

    @Test
    func `ICAO check digit for date 640812`() {
        // 6*7 + 4*3 + 0*1 + 8*7 + 1*3 + 2*1 = 42 + 12 + 0 + 56 + 3 + 2 = 115 → 5
        let digit = MRZKeyGenerator.checkDigit("640812")
        #expect(digit == "5")
    }

    @Test
    func `ICAO check digit for date 120415`() {
        // 1*7 + 2*3 + 0*1 + 4*7 + 1*3 + 5*1 = 7 + 6 + 0 + 28 + 3 + 5 = 49 → 9
        let digit = MRZKeyGenerator.checkDigit("120415")
        #expect(digit == "9")
    }

    @Test
    func `Check digit with all filler characters`() {
        let digit = MRZKeyGenerator.checkDigit("<<<")
        #expect(digit == "0") // All zeros → sum = 0 → 0 mod 10 = 0
    }

    // MARK: - MRZ Key Generation

    @Test
    func `ICAO 9303 Appendix D.1 MRZ key`() {
        // ICAO Doc 9303 Part 11, Appendix D.1
        // Document number: L898902C<, DOB: 690806, DOE: 940623
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "L898902C<",
            dateOfBirth: "690806",
            dateOfExpiry: "940623"
        )
        // Expected: L898902C< (9 chars, no padding needed) + check(3) + 690806 + check(1) + 940623 + check(6)
        // = "L898902C<369080619406236"
        #expect(mrzKey == "L898902C<369080619406236")
        #expect(mrzKey.count == 24) // 9 + 1 + 6 + 1 + 6 + 1
    }

    @Test
    func `Short document number is padded with fillers`() {
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "AB1234",
            dateOfBirth: "900101",
            dateOfExpiry: "300101"
        )
        // "AB1234" padded to "AB1234<<<" (9 chars)
        #expect(mrzKey.hasPrefix("AB1234<<<"))
    }

    @Test
    func `Full-length document number is not truncated`() {
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "123456789",
            dateOfBirth: "900101",
            dateOfExpiry: "300101"
        )
        #expect(mrzKey.hasPrefix("123456789"))
    }

    @Test
    func `MRZ key has correct total length`() {
        let mrzKey = MRZKeyGenerator.computeMRZKey(
            documentNumber: "ABCDEF",
            dateOfBirth: "850315",
            dateOfExpiry: "250315"
        )
        // 9 (padded doc#) + 1 (check) + 6 (DOB) + 1 (check) + 6 (DOE) + 1 (check) = 24
        #expect(mrzKey.count == 24)
    }
}
