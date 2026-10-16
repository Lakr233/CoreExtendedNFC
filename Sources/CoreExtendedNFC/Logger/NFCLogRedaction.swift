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
enum NFCLogRedaction {
    /// Frame families whose raw (non-APDU) commands may carry secrets.
    enum RawFamily {
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
    static let sensitiveISOInstructions: Set<UInt8> = [
        0x20, // VERIFY
        0x21, // VERIFY (odd INS)
        0x24, // CHANGE REFERENCE DATA
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
    static let desfireSensitiveCommands: Set<UInt8> = [0x0A, 0x1A, 0xAA, 0x71, 0x77, 0xC4]

    /// DESFire `ADDITIONAL FRAME`.
    static let desfireAdditionalFrame: UInt8 = 0xAF

    /// MIFARE Ultralight / NTAG native commands carrying secrets:
    /// `PWD_AUTH` (0x1B, response is PACK), Ultralight C `AUTHENTICATE` (0x1A)
    /// and its second step (0xAF).
    static let sensitiveMiFareCommands: Set<UInt8> = [0x1B, 0x1A, 0xAF]

    /// Whether `apdu` belongs to a PIN / password / authentication exchange.
    static func isSensitive(_ apdu: CommandAPDU) -> Bool {
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
    static func isSensitiveDESFireCommand(_ command: UInt8, data: Data?) -> Bool {
        if desfireSensitiveCommands.contains(command) { return true }
        return command == desfireAdditionalFrame && !(data ?? Data()).isEmpty
    }

    /// Whether `apdu` is protected by secure messaging (ISO/IEC 7816-4 §5.4.1:
    /// CLA bits b4-b3 non-zero for interindustry classes, `11` otherwise).
    static func isSecureMessaging(_ apdu: CommandAPDU) -> Bool {
        if apdu.cla & 0x80 == 0 {
            return apdu.cla & 0x0C != 0
        }
        return apdu.cla & 0x0C == 0x0C
    }

    static func isSensitiveRaw(_ frame: Data, family: RawFamily) -> Bool {
        guard family == .mifare, let command = frame.first else { return false }
        return sensitiveMiFareCommands.contains(command)
    }

    // MARK: Formatting

    static func header(_ apdu: CommandAPDU) -> String {
        Data([apdu.cla, apdu.ins, apdu.p1, apdu.p2]).hexDump
    }

    static func redacted(_ count: Int) -> String {
        "<redacted \(count) bytes>"
    }

    static func statusWord(_ sw1: UInt8, _ sw2: UInt8) -> String {
        String(format: "%02X%02X", sw1, sw2)
    }

    static func describeCommand(_ apdu: CommandAPDU, logPayloads: Bool) -> String {
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

    static func describeResponse(
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

    static func describeRawCommand(_ frame: Data, family: RawFamily, logPayloads: Bool) -> String {
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

    static func describeRawResponse(
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
    static func payload(_ data: Data, logPayloads: Bool) -> String {
        logPayloads ? data.hexDump : "<\(data.count) bytes>"
    }
}

extension NFCLog {
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
