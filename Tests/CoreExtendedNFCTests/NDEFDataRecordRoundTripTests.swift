// Round-trip tests for NDEFDataRecord (the .cndef file format used by the Example app).
//
// These tests duplicate the minimal Codable structure from the Example app to verify
// that PropertyList encode → decode preserves all fields, and that NDEFMessage
// serialization ↔ deserialization round-trips through the record.
@testable import CoreExtendedNFC
import Foundation
import Testing

// MARK: - Mirror type (matching Example/CENFC/Backend/NDEF/NDEFDataRecord.swift)

private struct TestNDEFDataRecord: Codable, Equatable {
    let id: UUID
    let date: Date
    var name: String
    let messageData: Data
}

// MARK: - Fixtures

/// Build a real NDEFMessage and return its serialized bytes.
private func textMessageData(_ text: String, languageCode: String = "en") -> Data {
    NDEFMessage.text(text, languageCode: languageCode).data
}

private func uriMessageData(_ uri: String) -> Data {
    NDEFMessage.uri(uri).data
}

private let fixtureText = TestNDEFDataRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000010")!,
    date: Date(timeIntervalSince1970: 1_700_000_000),
    name: "Hello World",
    messageData: textMessageData("Hello, NDEF!")
)

private let fixtureURI = TestNDEFDataRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000011")!,
    date: Date(timeIntervalSince1970: 1_700_000_000),
    name: "Example Site",
    messageData: uriMessageData("https://example.com")
)

private let fixtureEmpty = TestNDEFDataRecord(
    id: UUID(uuidString: "00000000-0000-0000-0000-000000000012")!,
    date: Date(timeIntervalSince1970: 1_700_000_000),
    name: "Empty",
    messageData: Data()
)

// MARK: - Tests

struct NDEFDataRecordRoundTripTests {
    @Test
    func `Text NDEF record round-trips through PropertyList`() throws {
        let data = try PropertyListEncoder().encode(fixtureText)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        #expect(decoded == fixtureText)
        #expect(decoded.name == "Hello World")
        #expect(decoded.messageData == fixtureText.messageData)
    }

    @Test
    func `URI NDEF record round-trips through PropertyList`() throws {
        let data = try PropertyListEncoder().encode(fixtureURI)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        #expect(decoded == fixtureURI)
        #expect(decoded.name == "Example Site")
    }

    @Test
    func `Empty messageData round-trips without error`() throws {
        let data = try PropertyListEncoder().encode(fixtureEmpty)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        #expect(decoded == fixtureEmpty)
        #expect(decoded.messageData.isEmpty)
    }

    @Test
    func `NDEFMessage data survives encode → decode → parse`() throws {
        let data = try PropertyListEncoder().encode(fixtureText)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        let message = try NDEFMessage(data: decoded.messageData)
        #expect(message.records.count == 1)

        let record = message.records[0]
        if case let .text(lang, text) = record.parsedPayload {
            #expect(lang == "en")
            #expect(text == "Hello, NDEF!")
        } else {
            Issue.record("Expected text payload, got \(record.parsedPayload)")
        }
    }

    @Test
    func `URI NDEFMessage data survives encode → decode → parse`() throws {
        let data = try PropertyListEncoder().encode(fixtureURI)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        let message = try NDEFMessage(data: decoded.messageData)
        #expect(message.records.count == 1)

        let record = message.records[0]
        if case let .uri(uri) = record.parsedPayload {
            #expect(uri == "https://example.com")
        } else {
            Issue.record("Expected URI payload, got \(record.parsedPayload)")
        }
    }

    @Test
    func `File-based round-trip writes and reads back identical record`() throws {
        let original = fixtureText
        let encoded = try PropertyListEncoder().encode(original)

        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test-ndef-roundtrip-\(UUID().uuidString).cndef")
        try encoded.write(to: tmpURL, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tmpURL) }

        let readBack = try Data(contentsOf: tmpURL)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: readBack)

        #expect(decoded == original)
    }

    @Test
    func `JSON-encoded record round-trips (NDEFStore uses JSON)`() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let original = fixtureURI
        let data = try encoder.encode(original)
        let decoded = try decoder.decode(TestNDEFDataRecord.self, from: data)

        #expect(decoded.id == original.id)
        #expect(decoded.name == original.name)
        #expect(decoded.messageData == original.messageData)
        // Date comparison with tolerance for iso8601 second-level precision
        #expect(abs(decoded.date.timeIntervalSince(original.date)) < 1)
    }

    @Test
    func `Multi-record NDEFMessage round-trips through the record model`() throws {
        let records: [NDEFRecord] = [
            .uri("https://example.com"),
            .text("Hello", languageCode: "en"),
        ]
        let message = NDEFMessage(records: records)
        let ndefRecord = TestNDEFDataRecord(
            id: UUID(), date: Date(), name: "Multi", messageData: message.data
        )

        let data = try PropertyListEncoder().encode(ndefRecord)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)

        let parsedMessage = try NDEFMessage(data: decoded.messageData)
        #expect(parsedMessage.records.count == 2)

        if case let .uri(uri) = parsedMessage.records[0].parsedPayload {
            #expect(uri == "https://example.com")
        }
        if case let .text(lang, text) = parsedMessage.records[1].parsedPayload {
            #expect(lang == "en")
            #expect(text == "Hello")
        }
    }

    @Test
    func `Smart Poster NDEFMessage round-trips`() throws {
        let record = NDEFRecord.smartPoster(uri: "https://example.com", title: "Example")
        let message = NDEFMessage(records: [record])

        let ndefRecord = TestNDEFDataRecord(
            id: UUID(), date: Date(), name: "Poster", messageData: message.data
        )

        let data = try PropertyListEncoder().encode(ndefRecord)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)
        let parsedMessage = try NDEFMessage(data: decoded.messageData)

        #expect(parsedMessage.records.count == 1)
        if case let .smartPoster(uri, title) = parsedMessage.records[0].parsedPayload {
            #expect(uri == "https://example.com")
            #expect(title == "Example")
        } else {
            Issue.record("Expected Smart Poster payload")
        }
    }

    @Test
    func `MIME record round-trips`() throws {
        let record = NDEFRecord.mime(type: "application/json", data: Data("{\"key\":1}".utf8))
        let message = NDEFMessage(records: [record])

        let ndefRecord = TestNDEFDataRecord(
            id: UUID(), date: Date(), name: "JSON MIME", messageData: message.data
        )

        let data = try PropertyListEncoder().encode(ndefRecord)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)
        let parsedMessage = try NDEFMessage(data: decoded.messageData)

        if case let .mime(type, payload) = parsedMessage.records[0].parsedPayload {
            #expect(type == "application/json")
            #expect(String(data: payload, encoding: .utf8) == "{\"key\":1}")
        } else {
            Issue.record("Expected MIME payload")
        }
    }

    @Test
    func `External type record round-trips`() throws {
        let record = NDEFRecord.external(type: "example.com:mytype", data: Data([0xAA, 0xBB, 0xCC]))
        let message = NDEFMessage(records: [record])

        let ndefRecord = TestNDEFDataRecord(
            id: UUID(), date: Date(), name: "External", messageData: message.data
        )

        let data = try PropertyListEncoder().encode(ndefRecord)
        let decoded = try PropertyListDecoder().decode(TestNDEFDataRecord.self, from: data)
        let parsedMessage = try NDEFMessage(data: decoded.messageData)

        if case let .external(type, payload) = parsedMessage.records[0].parsedPayload {
            #expect(type == "example.com:mytype")
            #expect(payload == Data([0xAA, 0xBB, 0xCC]))
        } else {
            Issue.record("Expected External payload")
        }
    }

    @Test
    func `Array of records round-trips through JSON (simulates NDEFStore)`() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let records = [fixtureText, fixtureURI, fixtureEmpty]
        let data = try encoder.encode(records)
        let decoded = try decoder.decode([TestNDEFDataRecord].self, from: data)

        #expect(decoded.count == 3)
        #expect(decoded[0].name == "Hello World")
        #expect(decoded[1].name == "Example Site")
        #expect(decoded[2].messageData.isEmpty)
    }
}
