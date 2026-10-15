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
    }

    @Test
    func `User cancellation is distinguishable`() {
        #expect(NFCError.userCanceled.isUserCancellation)
        #expect(!NFCError.sessionTimeout.isUserCancellation)
        #expect(!NFCError.sessionInvalidated("Session invalidated by user").isUserCancellation)
    }
}
