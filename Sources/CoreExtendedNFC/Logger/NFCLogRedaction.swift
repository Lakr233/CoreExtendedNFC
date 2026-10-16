import Foundation

/// Builds the log lines for RF traffic, keeping secrets out of logs.
///
/// Three tiers apply, from strongest to weakest:
/// 1. **Sensitive commands** (PIN / password / authentication exchanges) log the
///    command header and `<redacted n bytes>` for both the command data and the
///    response data, even when ``NFCLogConfiguration/logPayloads`` is `true`.
/// 2. **Secure-messaging APDUs** (CLA indicates SM) log the header and status word only.
/// 3. **Everything else** logs header, lengths and status word; raw payload bytes
///    appear only when ``NFCLogConfiguration/logPayloads`` is `true`.
///
/// A `GET RESPONSE` (INS C0h) that continues a command's response inherits that
/// command's tier through ``getResponseInheritedClass``, which
/// ``APDUExchange/transmit(_:maxGetResponseFrames:retryOnWrongLength:using:)`` sets.
public enum NFCLogRedaction {
    /// Redaction tier of an APDU exchange, from weakest to strongest.
    public enum RedactionClass: Int, Comparable, Sendable {
        case plain
        case secureMessaging
        case sensitive

        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    /// Tier of the command whose response a `GET RESPONSE` sent in this task continues.
    @TaskLocal public static var getResponseInheritedClass: RedactionClass = .plain

    /// Set while the second frame of a COMPATIBILITY_WRITE to a secret page is sent:
    /// that frame carries only data bytes, so it cannot be classified on its own.
    @TaskLocal public static var redactRawFrames = false

    /// Frame families whose raw (non-APDU) commands may carry secrets.
    public enum RawFamily: Sendable {
        /// NFC-A native commands (MIFARE Ultralight / NTAG).
        case mifare
        /// FeliCa frames (`LEN CMD IDm ...`); never carry secrets but carry the IDm.
        case felica
        /// ISO 15693 requests; never carry secrets in this library but carry block data.
        case iso15693
    }

    // MARK: Classification

    /// ISO/IEC 7816-4 instructions whose command or response carries a PIN,
    /// password or authentication cryptogram.
    public static let sensitiveISOInstructions: Set<UInt8> = [
        0x20, // VERIFY
        0x21, // VERIFY (odd INS)
        0x24, // CHANGE REFERENCE DATA
        0x26, // DISABLE VERIFICATION REQUIREMENT (may carry the PIN)
        0x28, // ENABLE VERIFICATION REQUIREMENT (may carry the PIN)
        0x2C, // RESET RETRY COUNTER
        0x82, // EXTERNAL / MUTUAL AUTHENTICATE
        0x84, // GET CHALLENGE
        0x86, // GENERAL AUTHENTICATE
        0x87, // GENERAL AUTHENTICATE (odd INS)
        0x88, // INTERNAL AUTHENTICATE
    ]

    /// DESFire native commands carrying key material: the authentication commands
    /// (`AuthenticateLegacy`, `AuthenticateISO`, `AuthenticateAES`,
    /// `AuthenticateEV2First`, `AuthenticateEV2NonFirst`) and `ChangeKey` (0xC4).
    public static let desfireSensitiveCommands: Set<UInt8> = [0x0A, 0x1A, 0xAA, 0x71, 0x77, 0xC4]

    /// DESFire `ADDITIONAL FRAME`.
    public static let desfireAdditionalFrame: UInt8 = 0xAF

    /// MIFARE Ultralight / NTAG native commands carrying secrets:
    /// `PWD_AUTH` (0x1B, response is PACK), Ultralight C `AUTHENTICATE` (0x1A)
    /// and its second step (0xAF).
    public static let sensitiveMiFareCommands: Set<UInt8> = [0x1B, 0x1A, 0xAF]

    /// Ultralight / NTAG WRITE (A2h) and COMPATIBILITY_WRITE (A0h).
    public static let mifareWriteCommands: Set<UInt8> = [0xA2, 0xA0]

    /// Pages that hold a password, PACK or 3DES key on some Ultralight / NTAG
    /// product. Without the tag's memory map every candidate is redacted, so a
    /// user page with the same address on a larger tag is redacted too.
    /// - MF0UL11 / NTAG210: PWD 12h, PACK 13h
    /// - MF0UL21 / NTAG212: PWD 27h, PACK 28h
    /// - NTAG213: PWD 2Bh, PACK 2Ch
    /// - MF0ICU2 (Ultralight C): 3DES key 2Ch-2Fh
    /// - NTAG215: PWD 85h, PACK 86h
    /// - NTAG216: PWD E5h, PACK E6h
    public static let mifareSecretPages: Set<UInt8> = [
        0x12, 0x13, 0x27, 0x28, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x85, 0x86, 0xE5, 0xE6,
    ]

    /// NXP ICODE custom commands (ICODE SLIX2 datasheet, "Custom commands") that
    /// carry a password, an XOR-ed password or the random number used to XOR it:
    /// GET RANDOM NUMBER (B2h), SET PASSWORD (B3h), WRITE PASSWORD (B4h),
    /// DESTROY (B9h) and ENABLE PRIVACY (BAh).
    public static let sensitiveISO15693Commands: Set<UInt8> = [0xB2, 0xB3, 0xB4, 0xB9, 0xBA]

    /// Whether a WRITE / COMPATIBILITY_WRITE to `page` must not be logged.
    public static func isSecretMiFarePage(_ page: UInt8) -> Bool {
        mifareSecretPages.contains(page)
    }

    /// GET RESPONSE (ISO/IEC 7816-4 §11.5.6).
    public static let getResponseInstruction: UInt8 = 0xC0

    /// Redaction tier of `apdu`, before inheritance.
    public static func ownClass(_ apdu: CommandAPDU) -> RedactionClass {
        if isOwnSensitive(apdu) { return .sensitive }
        if isOwnSecureMessaging(apdu) { return .secureMessaging }
        return .plain
    }

    /// Redaction tier of `apdu`; a GET RESPONSE inherits the tier of the command
    /// it continues.
    public static func redactionClass(_ apdu: CommandAPDU) -> RedactionClass {
        let own = ownClass(apdu)
        guard apdu.ins == getResponseInstruction else { return own }
        return max(own, getResponseInheritedClass)
    }

    /// Whether `apdu` belongs to a PIN / password / authentication exchange,
    /// including a GET RESPONSE that continues one.
    public static func isSensitive(_ apdu: CommandAPDU) -> Bool {
        redactionClass(apdu) == .sensitive
    }

    public static func isOwnSensitive(_ apdu: CommandAPDU) -> Bool {
        if sensitiveISOInstructions.contains(apdu.ins) { return true }
        if apdu.cla == 0x90 {
            if desfireSensitiveCommands.contains(apdu.ins) { return true }
            // An AF frame that carries data continues an authentication exchange;
            // read chaining always sends AF without data.
            if apdu.ins == desfireAdditionalFrame, !(apdu.data ?? Data()).isEmpty { return true }
        }
        return false
    }

    /// Whether the DESFire native command `command` (unwrapped) carries secrets
    /// when sent with `data`.
    public static func isSensitiveDESFireCommand(_ command: UInt8, data: Data?) -> Bool {
        if desfireSensitiveCommands.contains(command) { return true }
        return command == desfireAdditionalFrame && !(data ?? Data()).isEmpty
    }

    /// Whether `apdu` is protected by secure messaging (ISO/IEC 7816-4 §5.4.1:
    /// CLA bits b4-b3 non-zero for interindustry classes, `11` otherwise), or is a
    /// GET RESPONSE continuing such a command.
    public static func isSecureMessaging(_ apdu: CommandAPDU) -> Bool {
        redactionClass(apdu) == .secureMessaging
    }

    public static func isOwnSecureMessaging(_ apdu: CommandAPDU) -> Bool {
        if apdu.cla & 0x80 == 0 {
            return apdu.cla & 0x0C != 0
        }
        return apdu.cla & 0x0C == 0x0C
    }

    public static func isSensitiveRaw(_ frame: Data, family: RawFamily) -> Bool {
        if redactRawFrames { return true }
        guard let command = frame.first else { return false }
        switch family {
        case .mifare:
            if sensitiveMiFareCommands.contains(command) { return true }
            if mifareWriteCommands.contains(command), frame.count >= 2 {
                return isSecretMiFarePage(frame[frame.index(after: frame.startIndex)])
            }
            return false
        case .iso15693:
            return sensitiveISO15693Commands.contains(command)
        case .felica:
            return false
        }
    }

    // MARK: Formatting

    public static func header(_ apdu: CommandAPDU) -> String {
        Data([apdu.cla, apdu.ins, apdu.p1, apdu.p2]).hexDump
    }

    public static func redacted(_ count: Int) -> String {
        "<redacted \(count) bytes>"
    }

    public static func statusWord(_ sw1: UInt8, _ sw2: UInt8) -> String {
        String(format: "%02X%02X", sw1, sw2)
    }

    public static func describeCommand(_ apdu: CommandAPDU, logPayloads: Bool) -> String {
        let dataCount = apdu.data?.count ?? 0
        var line = "→ APDU \(header(apdu))"
        if isSensitive(apdu) {
            if dataCount > 0 { line += " \(redacted(dataCount))" }
        } else if isSecureMessaging(apdu) {
            // Header only: the SM payload is ciphertext of possibly personal data.
        } else if logPayloads {
            if let data = apdu.data, !data.isEmpty { line += " \(data.hexDump)" }
        } else if dataCount > 0 {
            line += " Lc=\(dataCount)"
        }
        if let ne = apdu.expectedResponseLength {
            line += " Le=\(ne)"
        }
        return line
    }

    public static func describeResponse(
        data: Data,
        sw1: UInt8,
        sw2: UInt8,
        for apdu: CommandAPDU,
        logPayloads: Bool
    ) -> String {
        let line = "← SW:\(statusWord(sw1, sw2))"
        if isSensitive(apdu) {
            return data.isEmpty ? line : "\(line) \(redacted(data.count))"
        }
        if isSecureMessaging(apdu) {
            return line
        }
        if logPayloads {
            return data.isEmpty ? line : "\(line) \(data.hexDump)"
        }
        return data.isEmpty ? line : "\(line) (\(data.count) bytes)"
    }

    public static func describeRawCommand(_ frame: Data, family: RawFamily, logPayloads: Bool) -> String {
        guard let command = frame.first else { return "→ SEND (empty)" }
        let commandHex = String(format: "%02X", command)
        let parameterCount = frame.count - 1
        if isSensitiveRaw(frame, family: family) {
            return parameterCount > 0 ? "→ SEND \(commandHex) \(redacted(parameterCount))" : "→ SEND \(commandHex)"
        }
        if logPayloads {
            return "→ SEND \(frame.hexDump)"
        }
        switch family {
        case .felica:
            // FeliCa frames start with a length byte; the command code follows.
            let code = frame.count > 1 ? String(format: "%02X", frame[frame.index(after: frame.startIndex)]) : "??"
            return "→ SEND cmd=\(code) (\(frame.count) bytes)"
        case .mifare, .iso15693:
            return "→ SEND \(commandHex) (\(frame.count) bytes)"
        }
    }

    public static func describeRawResponse(
        _ response: Data,
        command frame: Data,
        family: RawFamily,
        logPayloads: Bool
    ) -> String {
        if isSensitiveRaw(frame, family: family) {
            return "← RECV \(redacted(response.count))"
        }
        if logPayloads {
            return "← RECV \(response.hexDump)"
        }
        return "← RECV (\(response.count) bytes)"
    }

    /// Payload bytes (block contents, UIDs, ...) shown only when payload logging is on.
    public static func payload(_ data: Data, logPayloads: Bool) -> String {
        logPayloads ? data.hexDump : "<\(data.count) bytes>"
    }
}

public extension NFCLog {
    static func apduCommand(
        _ apdu: CommandAPDU,
        source: String,
        logger: (any NFCLogger)? = NFCLogConfiguration.logger,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) {
        guard let logger else { return }
        logger.log(.debug, NFCLogRedaction.describeCommand(apdu, logPayloads: logPayloads), source: source)
    }

    static func apduResponse(
        data: Data,
        sw1: UInt8,
        sw2: UInt8,
        for apdu: CommandAPDU,
        source: String,
        logger: (any NFCLogger)? = NFCLogConfiguration.logger,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) {
        guard let logger else { return }
        let line = NFCLogRedaction.describeResponse(
            data: data,
            sw1: sw1,
            sw2: sw2,
            for: apdu,
            logPayloads: logPayloads
        )
        logger.log(.debug, line, source: source)
    }

    static func rawCommand(
        _ frame: Data,
        family: NFCLogRedaction.RawFamily,
        source: String,
        logger: (any NFCLogger)? = NFCLogConfiguration.logger,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) {
        guard let logger else { return }
        let line = NFCLogRedaction.describeRawCommand(frame, family: family, logPayloads: logPayloads)
        logger.log(.debug, line, source: source)
    }

    static func rawResponse(
        _ response: Data,
        command frame: Data,
        family: NFCLogRedaction.RawFamily,
        source: String,
        logger: (any NFCLogger)? = NFCLogConfiguration.logger,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) {
        guard let logger else { return }
        let line = NFCLogRedaction.describeRawResponse(
            response,
            command: frame,
            family: family,
            logPayloads: logPayloads
        )
        logger.log(.debug, line, source: source)
    }

    /// `data` as hex when payload logging is on, otherwise its length only.
    static func payload(_ data: Data) -> String {
        NFCLogRedaction.payload(data, logPayloads: NFCLogConfiguration.logPayloads)
    }

    /// DESFire native command line for ``DESFireCommands/sendWithChaining(_:data:)``.
    static func desfireCommand(
        _ command: UInt8,
        data: Data?,
        source: String,
        logger: (any NFCLogger)? = NFCLogConfiguration.logger,
        logPayloads: Bool = NFCLogConfiguration.logPayloads
    ) {
        guard let logger else { return }
        var line = "DESFire CMD \(String(format: "0x%02X", command))"
        if let data, !data.isEmpty {
            if NFCLogRedaction.isSensitiveDESFireCommand(command, data: data) {
                line += " data=\(NFCLogRedaction.redacted(data.count))"
            } else if logPayloads {
                line += " data=\(data.hexDump)"
            } else {
                line += " data=<\(data.count) bytes>"
            }
        }
        logger.log(.debug, line, source: source)
    }
}
