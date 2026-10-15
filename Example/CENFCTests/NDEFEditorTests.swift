@testable import CENFC
import CoreExtendedNFC
import Foundation
import Testing

@MainActor
struct NDEFEditorTests {
    @Test
    func `Opening and leaving a binary MIME record does not rewrite it`() {
        let original = NDEFDataRecord(
            name: "m",
            messageData: NDEFMessage(records: [
                .mime(type: "application/octet-stream", data: Data([0xFF, 0x00, 0x01])),
            ]).data
        )
        let editor = NDEFMIMEEditorViewController()
        editor.existingRecord = original
        var saved: NDEFDataRecord?
        editor.onSave = { saved = $0 }

        editor.loadViewIfNeeded()
        editor.save()

        #expect(saved == nil)
    }

    @Test
    func `Opening and leaving an External record with a CRLF payload keeps its bytes`() {
        let payload = Data("BEGIN:VCARD\r\nEND:VCARD\r\n".utf8)
        let original = NDEFDataRecord(
            name: "e",
            messageData: NDEFMessage(records: [.external(type: "example.com:card", data: payload)]).data
        )
        let editor = NDEFExternalEditorViewController()
        editor.existingRecord = original
        var saved: NDEFDataRecord?
        editor.onSave = { saved = $0 }

        editor.loadViewIfNeeded()
        editor.save()

        #expect(saved == nil)
    }

    @Test
    func `Binary payloads are shown as hex and parsed back from edited hex`() {
        let text = NDEFPayloadText(data: Data([0xFF, 0x00, 0x01]))
        #expect(text.isHex)
        #expect(text.displayedText == "FF 00 01")
        #expect(text.data(from: "FF 00 01") == Data([0xFF, 0x00, 0x01]))
        #expect(text.data(from: "aa bb\ncc") == Data([0xAA, 0xBB, 0xCC]))
        #expect(text.data(from: "ABC") == nil)
        #expect(text.data(from: "ZZ") == nil)
    }

    @Test
    func `Plain UTF-8 payloads stay editable as text and keep surrounding whitespace`() {
        let text = NDEFPayloadText(data: Data("hello\n".utf8))
        #expect(!text.isHex)
        #expect(text.data(from: "hello\n") == Data("hello\n".utf8))
        #expect(text.data(from: " hi ") == Data(" hi ".utf8))
    }

    @Test
    func `URI editor picks the longest matching abbreviation`() {
        // NFC Forum URI RTD: 0x02 "https://www." must win over 0x04 "https://".
        let prefixes = NDEFURIEditorViewController.uriPrefixes
        let httpsWWW = NDEFURIEditorViewController.longestPrefixIndex(for: "https://www.example.com")
        #expect(prefixes[httpsWWW].code == 0x02)
        let https = NDEFURIEditorViewController.longestPrefixIndex(for: "https://example.com")
        #expect(prefixes[https].code == 0x04)
        let none = NDEFURIEditorViewController.longestPrefixIndex(for: "urn:nfc:sn:1")
        #expect(prefixes[none].code == 0x00)
    }
}
