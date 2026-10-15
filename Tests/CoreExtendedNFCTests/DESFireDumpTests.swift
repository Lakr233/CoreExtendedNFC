// DESFire dump orchestration tests (hand-built transcripts, not card captures).
//
// Native status words follow the DESFire 0x91xx class: 91 00 OK, 91 AE
// authentication error. File type 0x05 is the EV2/EV3 Transaction MAC file
// (NXP MF3D(H)x2 / MF3D(H)x3 datasheets).
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DESFireDumpTests {
    private static func ok(_ bytes: [UInt8] = []) -> ResponseAPDU {
        ResponseAPDU(data: Data(bytes), sw1: 0x91, sw2: 0x00)
    }

    private static let authError = ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0xAE)

    @Test
    func `Files with the same ID in different applications get distinct identifiers`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            Self.ok([0x01, 0x00, 0x00, 0x02, 0x00, 0x00]), // GetApplicationIDs
            Self.ok(), // Select app 1
            Self.ok([0x01]), // GetFileIDs
            Self.ok([0x00, 0x00, 0xEE, 0xEE, 0x04, 0x00, 0x00]), // Standard file, 4 bytes
            Self.ok([0xA1, 0xA2, 0xA3, 0xA4]), // ReadData
            Self.ok(), // Select app 2
            Self.ok([0x01]),
            Self.ok([0x00, 0x00, 0xEE, 0xEE, 0x04, 0x00, 0x00]),
            Self.ok([0xB1, 0xB2, 0xB3, 0xB4]),
        ]

        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .mifareDesfireEV1, uid: mock.identifier),
            transport: mock
        )

        #expect(dump.files.map(\.identifier) == [
            Data([0x01, 0x00, 0x00, 0x01]),
            Data([0x02, 0x00, 0x00, 0x01]),
        ])
        #expect(dump.files.map(\.data) == [Data([0xA1, 0xA2, 0xA3, 0xA4]), Data([0xB1, 0xB2, 0xB3, 0xB4])])
        #expect(dump.files.first?.name == "App 010000 / File 01")
    }

    @Test
    func `Application refusing GetFileIDs is skipped and the dump continues`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            Self.ok([0x01, 0x00, 0x00, 0x02, 0x00, 0x00]),
            Self.ok(), // Select app 1
            Self.authError, // GetFileIDs -> 91 AE
            Self.ok(), // Select app 2
            Self.ok([0x01]),
            Self.ok([0x00, 0x00, 0xEE, 0xEE, 0x02, 0x00, 0x00]),
            Self.ok([0xCA, 0xFE]),
        ]

        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .mifareDesfireEV1, uid: mock.identifier),
            transport: mock
        )

        #expect(dump.files.count == 1)
        #expect(dump.files.first?.identifier == Data([0x02, 0x00, 0x00, 0x01]))
        #expect(dump.facts.contains(.init(key: "Locked Applications", value: "1")))
    }

    @Test
    func `Transaction MAC and unknown file types do not abort the dump`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [
            Self.ok([0x01, 0x00, 0x00]),
            Self.ok(), // Select
            Self.ok([0x0F, 0x1E, 0x01]), // GetFileIDs
            Self.ok([0x05, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0x00]), // TMAC file, not read
            Self.ok([0x77, 0x00, 0xF0, 0xFF, 0x00, 0x00, 0x00]), // Unknown type
            Self.ok([0x00, 0x00, 0xEE, 0xEE, 0x01, 0x00, 0x00]),
            Self.ok([0x42]),
        ]

        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .mifareDesfireEV2, uid: mock.identifier),
            transport: mock
        )

        #expect(dump.files.map(\.identifier) == [Data([0x01, 0x00, 0x00, 0x01])])
        #expect(dump.facts.contains(.init(key: "Skipped Files", value: "2")))
        // GetVersion is never re-sent and the TMAC file is never read.
        #expect(mock.sentAPDUs.map(\.ins) == [0x6A, 0x5A, 0x6F, 0xF5, 0xF5, 0xF5, 0xBD])
    }

    @Test
    func `Locked application directory yields an empty dump instead of an error`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [Self.authError]

        let dump = try await CoreExtendedNFC.dumpCard(
            info: CardInfo(type: .mifareDesfireEV1, uid: mock.identifier),
            transport: mock
        )

        #expect(dump.files.isEmpty)
        #expect(dump.capabilities.contains(.authenticationRequired))
    }

    @Test
    func `Transport failures still propagate`() async {
        let mock = MockTransport()
        mock.apduResponses = [Self.ok([0x01, 0x00, 0x00]), Self.ok()]
        mock.apduFailures = [2: .tagConnectionLost]

        await #expect(throws: NFCError.self) {
            _ = try await CoreExtendedNFC.dumpCard(
                info: CardInfo(type: .mifareDesfireEV1, uid: mock.identifier),
                transport: mock
            )
        }
    }

    @Test
    func `Dump honours task cancellation`() async {
        let mock = MockTransport()
        mock.apduResponses = [Self.ok([0x01, 0x00, 0x00])] + Array(repeating: Self.ok(), count: 10)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await DESFireDump(commands: DESFireCommands(transport: mock))
                .dumpAll(cardInfo: CardInfo(type: .mifareDesfireEV1, uid: mock.identifier))
        }
        await #expect(throws: CancellationError.self) {
            _ = try await task.value
        }
        // Only GetApplicationIDs went out before the per-application check.
        #expect(mock.sentAPDUs.count == 1)
    }
}
