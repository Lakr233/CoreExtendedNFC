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
    func `Opening and leaving a Smart Poster with an action record keeps it`() {
        // NFC Forum Smart Poster RTD: URI + title + "act" (action) record.
        let action = NDEFRecord(typeNameFormat: .wellKnown, type: Data("act".utf8), payload: Data([0x00]))
        let poster = NDEFRecord(
            typeNameFormat: .wellKnown,
            type: Data([0x53, 0x70]),
            payload: NDEFMessage(records: [.uri("https://example.com"), .text("Title", languageCode: "de"), action]).data
        )
        let original = NDEFDataRecord(name: "p", messageData: NDEFMessage(records: [poster]).data)
        let editor = NDEFSmartPosterEditorViewController()
        editor.existingRecord = original
        var saved: NDEFDataRecord?
        editor.onSave = { saved = $0 }

        editor.loadViewIfNeeded()
        editor.save()

        #expect(saved == nil)
        #expect(editor.currentMessage()?.data == original.messageData)
    }

    @Test
    func `Opening and leaving a Text record that ends in a newline keeps it`() {
        let original = NDEFDataRecord(name: "t", messageData: NDEFMessage.text("hello\n").data)
        let editor = NDEFTextEditorViewController()
        editor.existingRecord = original
        var saved: NDEFDataRecord?
        editor.onSave = { saved = $0 }

        editor.loadViewIfNeeded()
        editor.save()

        #expect(saved == nil)
    }

    @Test
    func `Opening and leaving a multi-record message keeps every record and writes all of them`() {
        let identified = NDEFRecord(typeNameFormat: .wellKnown, type: Data([0x55]), identifier: Data("id1".utf8), payload: Data([0x00]) + Data("urn:nfc:sn:1".utf8))
        let message = NDEFMessage(records: [identified, .text("second")])
        let original = NDEFDataRecord(name: "u", messageData: message.data)
        let editor = NDEFURIEditorViewController()
        editor.existingRecord = original
        var saved: NDEFDataRecord?
        editor.onSave = { saved = $0 }

        editor.loadViewIfNeeded()
        editor.save()

        #expect(saved == nil)
        #expect(editor.currentMessage()?.data == message.data)
    }

    @Test
    func `Backing out of a new, empty editor creates no record`() {
        // The "+" menu opens an editor without a stored record; nothing exists until it saves.
        let editor = NDEFViewController.makeCreateEditor(for: .text)
        #expect(editor.existingRecord == nil)
        var saved: [NDEFDataRecord] = []
        editor.onSave = { saved.append($0) }

        editor.loadViewIfNeeded()
        editor.save()
        #expect(saved.isEmpty)
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
