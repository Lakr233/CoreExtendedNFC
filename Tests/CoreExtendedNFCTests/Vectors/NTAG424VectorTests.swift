// Published NTAG 424 DNA vectors for GetFileSettings and plain WriteData, run as executable tests.
//
// ## Sources
// - NXP AN12196 Rev. 2.0 (4 March 2025), "NTAG 424 DNA and NTAG 424 DNA TagTamper
//   features and hints": https://www.nxp.com/docs/en/application-note/AN12196.pdf
//   - Table 7: CommMode.MAC GetFileSettings of file 02h. Step 13 gives the plain
//     response data `0040EEEE000100D1FE001F00004400004400002000006A0000` (the leading
//     `00` is the response code; the 8-byte MACt of step 12 is not part of it).
//   - Tables 10 and 11: GetFileSettings C-APDU `90F50000010200` and a response the
//     note itself labels illustrative ("does not reflect default ... configuration").
//   - Table 18: ChangeFileSettings CmdData `4000E0C1F121200000430000430000`, whose
//     SDMAccessRights `F121h` the note decodes as RFU Fh, SDMCtrRet 1h, SDMMetaRead 2h,
//     SDMFileRead 1h.
//   - Table 24: plain WriteData of the CC file,
//     C-APDU `908D000019010E0000120000FF0506E1050080828300000000000000000000`.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct NTAG424VectorTests {
    private static func hex(_ string: String) -> Data {
        Data(hexString: string)!
    }

    @Test
    func `AN12196 Table 7 GetFileSettings response with encrypted PICC and file data`() throws {
        let settings = try NTAG424FileSettings(
            data: Self.hex("0040EEEE000100D1FE001F00004400004400002000006A0000")
        )
        let sdm = try #require(settings.sdm)

        #expect(settings.fileType == 0x00)
        #expect(settings.communicationMode == .plain)
        #expect(settings.accessRights.rawValue == 0xEEEE)
        #expect(settings.fileSize == 256)
        // D1h: UID, SDMReadCtr, SDMENCFileData, ASCII.
        #expect(sdm.options == [.uid, .readCounter, .encryptedFileData, .asciiEncoding])
        // FE00h, least significant byte first: SDMMetaRead 0h, SDMFileRead 0h,
        // RFU Fh, SDMCtrRet Eh.
        #expect(sdm.accessRights.rawValue == 0x00FE)
        #expect(sdm.accessRights.metaRead == 0x00)
        #expect(sdm.accessRights.fileRead == 0x00)
        #expect(sdm.accessRights.reserved == 0x0F)
        #expect(sdm.accessRights.counterRetrieval == 0x0E)
        #expect(sdm.uidOffset == nil)
        #expect(sdm.readCounterOffset == nil)
        #expect(sdm.piccDataOffset == 0x1F)
        #expect(sdm.macInputOffset == 0x44)
        #expect(sdm.encryptedDataOffset == 0x44)
        #expect(sdm.encryptedDataLength == 0x20)
        #expect(sdm.macOffset == 0x6A)
        #expect(sdm.readCounterLimit == nil)
    }

    @Test
    func `AN12196 Table 18 SDM settings read back through GetFileSettings`() throws {
        // FileType 00h ‖ size 256 around the Table 18 ChangeFileSettings CmdData.
        let settings = try NTAG424FileSettings(
            data: Self.hex("00" + "4000E0" + "000100" + "C1F121200000430000430000")
        )
        let sdm = try #require(settings.sdm)

        #expect(settings.accessRights.readCondition == .free)
        #expect(settings.accessRights.writeCondition == .key(0))
        #expect(settings.accessRights.readWriteCondition == .key(0))
        #expect(settings.accessRights.changeCondition == .key(0))
        #expect(sdm.options == [.uid, .readCounter, .asciiEncoding])
        #expect(sdm.accessRights.reserved == 0x0F)
        #expect(sdm.accessRights.counterRetrieval == 0x01)
        #expect(sdm.accessRights.metaRead == 0x02)
        #expect(sdm.accessRights.fileRead == 0x01)
        #expect(sdm.uidOffset == nil)
        #expect(sdm.readCounterOffset == nil)
        #expect(sdm.piccDataOffset == 0x20)
        #expect(sdm.macInputOffset == 0x43)
        #expect(sdm.macOffset == 0x43)
    }

    @Test
    func `AN12196 Table 10 illustrative response is rejected as truncated`() async {
        // Table 11 decodes SDMAccessRights F121h as SDMMetaRead 2h and SDMFileRead 1h,
        // which makes PICCDataOffset, SDMMACInputOffset and SDMMACOffset present, but the
        // published response carries only two 3-byte offsets.
        let mock = MockTransport()
        let payload = Self.hex("004300E0000100C1F121200000430000")
        mock.apduResponses = [ResponseAPDU(data: payload, sw1: 0x91, sw2: 0x00)]

        await #expect(throws: NFCError.invalidResponse(payload)) {
            _ = try await NTAG424Commands(transport: mock).getFileSettings(fileID: 0x02)
        }
        #expect(mock.sentAPDUs.map(\.bytes) == [Self.hex("90F50000010200")])
    }

    @Test
    func `NTAG 424 DNA TT TagTamper status offset sits before the MAC offsets`() throws {
        // NT4H2421Tx Rev. 3.0 Table 73: TTStatusOffset is present if SDMOptions bit 3
        // is set, between PICCDataOffset and SDMMACInputOffset. SDMOptions 89h (UID,
        // TT status, ASCII); SDMAccessRights E1FFh: MetaRead Eh, FileRead 1h.
        let settings = try NTAG424FileSettings(
            data: Self.hex("004000E0000100" + "89FFE1" + "200000" + "2E0000" + "340000" + "450000")
        )
        let sdm = try #require(settings.sdm)

        #expect(sdm.options == [.uid, .tagTamperStatus, .asciiEncoding])
        #expect(sdm.uidOffset == 0x20)
        #expect(sdm.piccDataOffset == nil)
        #expect(sdm.tagTamperStatusOffset == 0x2E)
        #expect(sdm.macInputOffset == 0x34)
        #expect(sdm.macOffset == 0x45)
    }

    @Test
    func `NTAG 424 DNA TT status offset after encrypted PICC data`() throws {
        // SDMOptions 08h (TT status); SDMAccessRights 2FFFh: MetaRead 2h, FileRead Fh.
        let sdm = try #require(
            try NTAG424FileSettings(data: Self.hex("004000E0000100" + "08FF2F" + "200000" + "400000")).sdm
        )

        #expect(sdm.piccDataOffset == 0x20)
        #expect(sdm.tagTamperStatusOffset == 0x40)
        #expect(sdm.macInputOffset == nil)
    }

    @Test
    func `AN12196 Table 24 plain WriteData of the CC file`() async throws {
        let mock = MockTransport()
        mock.apduResponses = [ResponseAPDU(data: Data(), sw1: 0x91, sw2: 0x00)]

        try await NTAG424Commands(transport: mock).writeDataPlain(
            fileID: 0x01,
            offset: 0x0E,
            data: Self.hex("FF0506E10500808283000000000000000000")
        )

        #expect(mock.sentAPDUs.map(\.bytes) == [
            Self.hex("908D000019010E0000120000FF0506E1050080828300000000000000000000"),
        ])
    }
}
