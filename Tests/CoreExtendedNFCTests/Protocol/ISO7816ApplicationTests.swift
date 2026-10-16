@testable import CoreExtendedNFC
import Foundation
import Testing

struct ISO7816ApplicationTests {
    @Test
    func `Match standard ePassport AID`() {
        let application = ISO7816Application.match(aid: "A0000002471001")
        #expect(application == .eMRTDLDS)
        #expect(application?.hintedCardType == .ePassport)
    }

    @Test
    func `Match Type 4 NDEF AID`() {
        let application = ISO7816Application.match(aid: "D2760000850101")
        #expect(application == .ndefTagApplication)
        #expect(application?.hintedCardType == .type4NDEF)
    }

    @Test
    func `Normalize and match observed payment and document AIDs`() {
        #expect(ISO7816Application.match(aid: "315041592E5359532E4444463031") == .paymentSystemEnvironment)
        #expect(ISO7816Application.match(aid: "F049442E43484E") == .chinaDocument)
        #expect(ISO7816Application.match(aid: "<A00000000386980701>") == .unionPayPayment)
    }

    @Test
    func `Match My Number AIDs`() {
        #expect(ISO7816Application.match(aid: "D392F000260100000001") == .myNumberJPKI)
        #expect(ISO7816Application.match(aid: "D3921000310001010408") == .myNumberCardInfoInputSupport)
        #expect(ISO7816Application.match(aid: "D3921000310001010100") == .myNumberIndividualNumber)
        #expect(ISO7816Application.match(aid: "D3921000310001010401") == .myNumberCardInfoInputCheck)
        #expect(ISO7816Application.match(aid: "D392F000260100000001")?.hintedCardType == .myNumberCard)
    }

    @Test
    func `CardInfo exposes known ISO 7816 application hint`() {
        let info = CardInfo(
            type: .smartMX,
            uid: Data([0x01, 0x02, 0x03, 0x04]),
            initialSelectedAID: "315041592E5359532E4444463031"
        )

        #expect(info.knownISO7816Application == .paymentSystemEnvironment)
        #expect(info.knownISO7816Application?.hintedCardType == nil)
    }
}
