// NFCError presentation tests.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NFCErrorTests {
    @Test
    func `localizedDescription is not the generic bridged text`() {
        // Before LocalizedError: "The operation couldn't be completed. (CoreExtendedNFC.NFCError error 13.)"
        let errors: [NFCError] = [
            .nfcNotAvailable, .sessionTimeout, .tagConnectionLost, .tagNotSupported,
            .sessionInvalidated("x"), .userCanceled, .systemBusy, .crcMismatch,
            .invalidResponse(Data([0x01])), .unexpectedStatusWord(0x6A, 0x82),
            .responseChainTooLong(maxFrames: 4), .authenticationFailed, .writeFailed(page: 4),
            .tagLocked, .desfireError(.permissionDenied), .felicaBlockReadFailed(statusFlag: 0xA1),
            .felicaBlockWriteFailed(statusFlag: 0xA1), .bacFailed("x"), .secureMessagingError("x"),
            .dataGroupNotAvailable("DG3"), .dataGroupParseFailed("x"), .cryptoError("x"),
            .notOperableOnIOS(.mifareClassic1K), .unsupportedOperation("x"),
            .sessionInvalidatedByCaller, .scanInProgress, .checksumMismatch,
            .applicationNotFound(aid: Data([0xA0, 0x00])), .iso15693Error(code: 0x0F),
            .pinRequired(.cardInfoInputSupport), .irreversibleWriteRefused(page: 2),
            .tagNotNDEFFormatted, .ndefMessageNotFound, .ndefCapacityExceeded(required: 10, capacity: 8),
            .invalidParameter("x"), .malformedDump("x"),
        ]
        for error in errors {
            let text = error.localizedDescription
            #expect(!text.contains("NFCError error"), "\(error)")
            #expect(!text.isEmpty)
        }
    }

    @Test
    func `Descriptions carry the useful details`() {
        #expect(NFCError.unexpectedStatusWord(0x6A, 0x82).localizedDescription.contains("6A82"))
        #expect(NFCError.desfireError(.permissionDenied).localizedDescription.contains("Permission denied"))
        #expect(NFCError.notOperableOnIOS(.mifareClassic1K).localizedDescription.contains("MIFARE Classic"))
        #expect(NFCError.dataGroupNotAvailable("DG3").localizedDescription.contains("DG3"))
        #expect(NFCError.applicationNotFound(aid: Data([0xA0, 0x00, 0x06])).localizedDescription.contains("A00006"))
        #expect(NFCError.iso15693Error(code: 0x0F).localizedDescription.contains("0F"))
        #expect(NFCError.irreversibleWriteRefused(page: 2).localizedDescription.contains("2"))
        let capacity = NFCError.ndefCapacityExceeded(required: 503, capacity: 496).localizedDescription
        #expect(capacity.contains("503") && capacity.contains("496"))
        #expect(NFCError.pinRequired(.cardInfoInputSupport).localizedDescription.contains("PIN"))
        #expect(NFCError.invalidParameter("AID must be 3 bytes").localizedDescription.contains("AID must be 3 bytes"))
        #expect(NFCError.malformedDump("Page 3").localizedDescription.contains("Page 3"))
    }

    @Test
    func `NFCError is Equatable including associated values`() {
        #expect(NFCError.tagNotNDEFFormatted == .tagNotNDEFFormatted)
        #expect(NFCError.ndefCapacityExceeded(required: 1, capacity: 2) == .ndefCapacityExceeded(required: 1, capacity: 2))
        #expect(NFCError.ndefCapacityExceeded(required: 1, capacity: 2) != .ndefCapacityExceeded(required: 1, capacity: 3))
        #expect(NFCError.desfireError(.permissionDenied) != .desfireError(.lengthError))
        #expect(NFCError.notOperableOnIOS(.mifareClassic1K) == .notOperableOnIOS(.mifareClassic1K))
        #expect(NFCError.tagNotNDEFFormatted != .unsupportedOperation("The tag is not NDEF formatted"))
    }

    @Test
    func `isNFCCancellation covers every way an operation is cancelled`() {
        #expect(NFCError.userCanceled.isNFCCancellation)
        #expect(NFCError.sessionInvalidatedByCaller.isNFCCancellation)
        #expect(CancellationError().isNFCCancellation)
        let erased: any Error = NFCError.userCanceled
        #expect(erased.isNFCCancellation)

        #expect(!NFCError.sessionTimeout.isNFCCancellation)
        #expect(!NFCError.sessionInvalidated("Session ended").isNFCCancellation)
        #expect(!NFCError.tagConnectionLost.isNFCCancellation)
        #expect(!NSError(domain: "x", code: 1).isNFCCancellation)
        // The narrower check stays limited to the sheet being dismissed.
        #expect(!NFCError.sessionInvalidatedByCaller.isUserCancellation)
    }

    @Test
    func `Caller-ended sessions count as session loss`() {
        #expect(isSessionTerminating(NFCError.sessionInvalidatedByCaller))
        #expect(!isSessionTerminating(NFCError.scanInProgress))
    }

    @Test
    func `Card values in logs follow the payload flag`() {
        #expect(NFCLog.cardValue(1234, logPayloads: false) == "<redacted>")
        #expect(NFCLog.cardValue(1234, logPayloads: true) == "1234")
        #expect(NFCLog.cardValue("Shinjuku", logPayloads: false) == "<redacted>")
    }

    @Test
    func `New error cases are translated to Simplified Chinese`() throws {
        let bundle = try #require(Bundle.module.path(forResource: "zh-Hans", ofType: "lproj").flatMap(Bundle.init(path:)))
        for key in [
            "The tag is not NDEF formatted. Format it first.",
            "No NDEF message was found on the tag.",
            "The NDEF message needs %lld bytes, but the tag holds only %lld.",
            "Writing page %lld would permanently change the tag, so it was refused.",
            "The card does not have application %@.",
            "The tag reported ISO 15693 error %@.",
            "A PIN is required: %@.",
            "An NFC scan is already in progress.",
            "The NFC session was ended by the app.",
            "The card data failed its checksum.",
            "Invalid parameter: %@",
            "The dump is malformed: %@",
            "Hold your iPhone near your My Number card",
            "Detected %@",
        ] {
            let translated = bundle.localizedString(forKey: key, value: "<missing>", table: nil)
            #expect(translated != "<missing>" && translated != key, "\(key)")
        }
    }

    @Test
    func `User cancellation is distinguishable`() {
        #expect(NFCError.userCanceled.isUserCancellation)
        #expect(!NFCError.sessionTimeout.isUserCancellation)
        #expect(!NFCError.sessionInvalidated("Session invalidated by user").isUserCancellation)
    }
}
