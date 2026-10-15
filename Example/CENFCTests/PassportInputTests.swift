@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing

struct PassportInputTests {
    @Test
    func `MRZ dates use Gregorian years regardless of the device calendar`() throws {
        var components = DateComponents()
        components.year = 1990
        components.month = 5
        components.day = 12
        components.timeZone = TimeZone(identifier: "UTC")
        let date = try #require(Calendar(identifier: .gregorian).date(from: components))

        // A Thai (Buddhist) or Japanese device calendar printed 330512 / 020512 before.
        #expect(PassportMRZInputViewController.mrzDate(date, timeZone: TimeZone(identifier: "UTC")!) == "900512")

        let buddhist = DateFormatter()
        buddhist.locale = Locale(identifier: "th_TH@calendar=buddhist")
        buddhist.timeZone = TimeZone(identifier: "UTC")
        buddhist.dateFormat = "yyMMdd"
        #expect(buddhist.string(from: date) != "900512")
    }

    @Test
    func `Typed document numbers are uppercased and stripped of spaces`() {
        #expect(PassportMRZInputViewController.mrzDocumentNumber(" l898 902c3 ") == "L898902C3")
    }

    @Test
    func `Normalised document number yields the ICAO 9303 Appendix D MRZ key`() {
        // ICAO 9303 Part 11 Appendix D.2: L898902C<3 / 690806 / 940623 -> "L898902C<369080619406236"
        let key = MRZKeyGenerator.computeMRZKey(
            documentNumber: PassportMRZInputViewController.mrzDocumentNumber("l898902c<"),
            dateOfBirth: "690806",
            dateOfExpiry: "940623"
        )
        #expect(key == "L898902C<369080619406236")
    }
}
