import Foundation

/// Passport/eMRTD APDU helpers.
///
/// References: ICAO Doc 9303 Part 10 section 4.4 and ISO/IEC 7816-4.
/// Cross-reference: JMRTD `PassportApduService.java`.
/// https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
/// https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/PassportApduService.java
public extension CommandAPDU {
    /// SELECT the Master File (MF) so transparent EFs outside the eMRTD applet can be read.
    static func selectMasterFile() -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x00,
            p2: 0x0C,
            data: Data([0x3F, 0x00])
        )
    }

    /// SELECT the eMRTD application.
    /// AID: A0 00 00 02 47 10 01 (ICAO LDS1 eMRTD Application)
    static func selectPassportApplication() -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
        )
    }

    /// SELECT an Elementary File (EF) by short file identifier.
    /// P1=0x02 (select EF under current DF), P2=0x0C (no response data).
    static func selectEF(id: Data) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x02,
            p2: 0x0C,
            data: id
        )
    }

    /// GET CHALLENGE for the 8-byte BAC nonce.
    static func getChallenge() -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0x84,
            p1: 0x00,
            p2: 0x00,
            le: 0x08
        )
    }

    /// EXTERNAL AUTHENTICATE / MUTUAL AUTHENTICATE for BAC.
    /// Data: 40 bytes (eifd || mifd).
    static func mutualAuthenticate(data: Data) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0x82,
            p1: 0x00,
            p2: 0x00,
            data: data,
            le: 0x28
        )
    }

    /// INTERNAL AUTHENTICATE for Active Authentication.
    /// Data is the 8-byte challenge; the response is the signature.
    static func internalAuthenticate(data: Data) -> CommandAPDU {
        CommandAPDU(
            cla: 0x00,
            ins: 0x88,
            p1: 0x00,
            p2: 0x00,
            data: data,
            le: 0x00
        )
    }

    /// MSE:Set AT for PACE or Chip Authentication setup.
    static func mseSetAT(oid: Data, keyRef: UInt8? = nil, privateKeyRef: UInt8? = nil) -> CommandAPDU {
        var data = Data()
        data.append(0x80)
        data.append(contentsOf: ASN1Parser.encodeLength(oid.count))
        data.append(oid)

        if let keyRef {
            data.append(0x83)
            data.append(0x01)
            data.append(keyRef)
        }

        if let privateKeyRef {
            data.append(0x84)
            data.append(0x01)
            data.append(privateKeyRef)
        }

        return CommandAPDU(
            cla: 0x00,
            ins: 0x22,
            p1: 0xC1,
            p2: 0xA4,
            data: data
        )
    }

    /// General Authenticate for PACE or Chip Authentication steps.
    static func generalAuthenticate(data: Data, isLast: Bool = false) -> CommandAPDU {
        CommandAPDU(
            cla: isLast ? 0x00 : 0x10,
            ins: 0x86,
            p1: 0x00,
            p2: 0x00,
            data: data,
            le: 0x00
        )
    }

    /// READ BINARY of up to `length` bytes (clamped to `1 ... 255`; `0` or less asks for 256).
    ///
    /// Offsets up to `0x7FFF` are encoded in `P1 || P2` with INS `B0`. Larger offsets
    /// (DG2/DG3 files beyond 32 KB) use INS `B1` with offset DO `54`, per ISO/IEC 7816-4
    /// §11.2.3; unwrap the reply with ``ResponseAPDU/binaryData(for:)``, and advance by
    /// the number of content bytes actually returned. Negative offsets are treated as `0`.
    static func readBinaryChunk(offset: Int, length: Int) -> CommandAPDU {
        binaryRead(offset: offset, expectedLength: length <= 0 ? 256 : min(length, 0xFF))
    }
}
