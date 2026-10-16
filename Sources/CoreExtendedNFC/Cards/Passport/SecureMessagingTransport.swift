import Foundation

/// Encryption mode for Secure Messaging sessions.
///
/// - `tripleDES`: Used after BAC authentication. 8-byte SSC, Retail MAC, 3DES-CBC.
/// - `aes128/192/256`: Used after PACE or Chip Authentication. AES-CBC + AES-CMAC.
///
/// ## SSC and IV Conventions
///
/// The Send Sequence Counter (SSC) is always an 8-byte big-endian counter,
/// incremented by 1 before each protect and unprotect operation.
///
/// For AES modes, the SSC is padded to 16 bytes by prepending 8 zero bytes:
///   `paddedSSC = [0x00]*8 || SSC`
///
/// The AES IV is computed as: `IV = AES-ECB-Encrypt(KSenc, paddedSSC)`
///
/// MAC computation uses AES-CMAC over `pad(paddedSSC || cmdHeader || DO'87 || DO'97)`,
/// truncated to 8 bytes.
///
/// References:
/// - ICAO Doc 9303 Part 11, Section 9.8 (Secure Messaging)
/// - ICAO Doc 9303 Part 11, Section 9.8.6.1 (AES Secure Messaging — SSC padding, IV derivation)
/// - BSI TR-03110 Part 3, Section D.3 (AES Secure Messaging with AES-CMAC)
/// - NIST SP 800-38B (AES-CMAC specification)
/// - ISO/IEC 9797-1, MAC Algorithm 3 (Retail MAC for 3DES mode)
/// - JMRTD source: AESSecureMessagingWrapper.java, DESedeSecureMessagingWrapper.java
public enum SMEncryptionMode: Sendable {
    case tripleDES
    case aes128
    case aes192
    case aes256

    /// Block size for the cipher.
    var blockSize: Int {
        switch self {
        case .tripleDES: 8
        case .aes128, .aes192, .aes256: 16
        }
    }

    /// SSC (Send Sequence Counter) length in bytes.
    /// Always 8 bytes — for AES, the SSC is zero-padded to 16 bytes when used.
    var sscLength: Int {
        8
    }

    /// MAC length in bytes (truncated output).
    var macLength: Int {
        8
    }
}

/// ICAO 9303 Secure Messaging transport wrapper.
///
/// Wraps an existing `NFCTagTransport` and automatically encrypts/MACs
/// all outgoing APDUs and verifies/decrypts all incoming responses
/// per ICAO Doc 9303 Part 11.
///
/// Supports both 3DES mode (after BAC) and AES mode (after PACE/CA).
///
/// Conforms to `NFCTagTransport` so it can be used transparently
/// in place of the original transport after authentication.
public final class SecureMessagingTransport: NFCTagTransport, @unchecked Sendable {
    private let underlying: any NFCTagTransport
    private let ksEnc: Data
    private let ksMac: Data
    /// Send Sequence Counter. Only read or mutated while `exchangeGate` is held.
    private var ssc: Data
    private let mode: SMEncryptionMode
    /// Serializes command/response pairs so concurrent callers cannot desynchronize the SSC.
    private let exchangeGate = AsyncExchangeGate()
    /// Set once an exchange failed in a way that leaves the SSC out of step with the chip
    /// (transport error, cancellation mid-exchange, unauthenticated response). Only read
    /// or mutated while `exchangeGate` is held.
    private var sessionEndReason: String?
    /// The plain (unprotected) status word that answered the previous exchange, or `nil`
    /// when that exchange was protected. Only read or mutated while `exchangeGate` is held.
    private var previousPlainStatusWord: UInt16?

    /// Whether an earlier failed exchange ended this secure messaging session.
    var isSessionEnded: Bool {
        get async {
            await sessionEndedReason != nil
        }
    }

    /// Why this secure messaging session ended, or `nil` while it is still usable.
    var sessionEndedReason: String? {
        get async {
            await exchangeGate.acquire()
            defer { exchangeGate.release() }
            return sessionEndReason
        }
    }

    public var identifier: Data {
        underlying.identifier
    }

    public init(
        transport: any NFCTagTransport,
        ksEnc: Data,
        ksMac: Data,
        ssc: Data,
        mode: SMEncryptionMode = .tripleDES
    ) {
        underlying = transport
        self.ksEnc = Data(ksEnc)
        self.ksMac = Data(ksMac)
        self.ssc = Data(ssc)
        self.mode = mode
    }

    public func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Use sendAPDU for Secure Messaging")
    }

    /// Protect the APDU, send via underlying transport (with GET RESPONSE chaining),
    /// then unprotect the response.
    ///
    /// Concurrent calls are serialized: each protected command and its response
    /// consume two consecutive SSC values.
    ///
    /// - Throws: `NFCError.unexpectedStatusWord` when the chip answers with a plain
    ///   status word (no secure messaging data objects). Both SSC steps are still
    ///   consumed, so the caller may try another command; ICAO-strict chips end the
    ///   session there (ICAO 9303-11 §9.8), and the next command then fails.
    ///   `NFCError.secureMessagingError` when the response cannot be authenticated, or
    ///   when an earlier exchange ended the session.
    ///   Any other failure (transport loss, `CancellationError` between `61xx`
    ///   GET RESPONSE frames) also ends the session: the chip may have consumed an SSC
    ///   value this side did not, so every later MAC would be wrong.
    public func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        await exchangeGate.acquire()
        defer { exchangeGate.release() }

        if let sessionEndReason {
            throw NFCError.secureMessagingError("Secure messaging session ended: \(sessionEndReason)")
        }

        do {
            incrementSSC()
            let protectedAPDU = try protect(apdu)

            // Send with bounded GET RESPONSE (61xx) chaining at the raw level. The protected
            // command is not re-issued on 6Cxx: that would consume a second SSC on the chip.
            let underlying = underlying
            let assembledResponse = try await APDUExchange.transmit(
                protectedAPDU,
                retryOnWrongLength: false
            ) { command in
                try await underlying.sendAPDU(command)
            }

            incrementSSC()
            let response = try unprotect(assembledResponse)
            previousPlainStatusWord = nil
            return response
        } catch let NFCError.unexpectedStatusWord(sw1, sw2) {
            // Plain status word: both SSC steps were consumed in step with the chip.
            // 6987/6988 (SM data objects missing/incorrect) mean the chip no longer
            // runs secure messaging at all (ISO/IEC 7816-4 §5.6).
            if sw1 == 0x69, sw2 == 0x87 || sw2 == 0x88 {
                sessionEndReason = String(format: "chip reported a secure messaging error (SW=%02X%02X)", sw1, sw2)
            } else if sw1 == 0x69, sw2 == 0x82,
                      let previous = previousPlainStatusWord, previous != 0x6982
            {
                // ICAO 9303-11 §9.8: a chip may delete its session keys after any plain
                // reply. Some then answer every protected command with a plain 6982
                // instead of 6988, so a plain 6982 straight after a different plain
                // error (e.g. 6A82 for an absent file) is taken as the end of the
                // session, not as a protected file.
                //
                // A 6982 after another 6982 is not: consecutive EAC-protected files
                // (DG3 then DG4 under BAC/PACE) are each refused with a plain 6982 by
                // chips that keep the session. On a strict chip the second 6982 is
                // ambiguous, and reporting that file as unavailable is accurate either
                // way; the reader reads EAC data groups last for this reason.
                sessionEndReason = "chip answered with a plain 6982 right after another unprotected error; "
                    + "it has most likely ended secure messaging"
            }
            previousPlainStatusWord = UInt16(sw1) << 8 | UInt16(sw2)
            throw NFCError.unexpectedStatusWord(sw1, sw2)
        } catch {
            sessionEndReason = error is CancellationError
                ? "an exchange was cancelled before its response was complete"
                : error.localizedDescription
            throw error
        }
    }

    // MARK: - Protect (Encrypt + MAC outgoing APDU)

    /// Build a protected APDU with DO'87/DO'85 (encrypted data), DO'97 (Le), and DO'8E (MAC).
    ///
    /// Even INS codes carry the cryptogram in DO'87 with a padding-content indicator;
    /// odd INS codes (BER-TLV data field, e.g. READ BINARY `B1`) use DO'85 without it
    /// (ISO/IEC 7816-4 §10.2, ICAO 9303-11 §9.8).
    private func protect(_ apdu: CommandAPDU) throws -> CommandAPDU {
        let blockSize = mode.blockSize

        // Masked CLA: set SM bits
        let maskedCLA = apdu.cla | 0x0C

        // Command header for MAC calculation: maskedCLA || INS || P1 || P2
        let cmdHeader = ISO9797Padding.pad(Data([maskedCLA, apdu.ins, apdu.p1, apdu.p2]), blockSize: blockSize)

        var cryptogramDO = Data()
        var do97 = Data()

        if let inputData = apdu.data, !inputData.isEmpty {
            let paddedData = ISO9797Padding.pad(inputData, blockSize: blockSize)

            let encrypted: Data
            switch mode {
            case .tripleDES:
                encrypted = try CryptoUtils.tripleDESEncrypt(key: ksEnc, message: paddedData)
            case .aes128, .aes192, .aes256:
                // AES-CBC with IV = AES-ECB(KSenc, paddedSSC)
                let iv = try computeAESIV()
                encrypted = try CryptoUtils.aesEncrypt(key: ksEnc, message: paddedData, iv: iv)
            }

            if apdu.ins & 0x01 == 0x01 {
                // DO'85': cryptogram of BER-TLV data, no padding-content indicator
                cryptogramDO = ASN1Parser.encodeTLV(tag: 0x85, value: encrypted)
            } else {
                // DO'87': padding-content indicator 0x01 || cryptogram
                cryptogramDO = ASN1Parser.encodeTLV(tag: 0x87, value: Data([0x01]) + encrypted)
            }
        }

        // DO'97: expected response length (if Le is present). Short Ne uses one byte
        // (00 = 256); extended Ne uses two bytes (0000 = 65 536).
        if let ne = apdu.expectedResponseLength {
            if ne <= 256 {
                do97 = Data([0x97, 0x01, UInt8(ne & 0xFF)])
            } else {
                do97 = Data([0x97, 0x02, UInt8((ne >> 8) & 0xFF), UInt8(ne & 0xFF)])
            }
        }

        // MAC over pad(paddedSSC || pad(header) || DO'87/85 || DO'97)
        var macInput = paddedSSC()
        macInput.append(cmdHeader)
        macInput.append(cryptogramDO)
        macInput.append(do97)
        let cc = try computeMAC(ISO9797Padding.pad(macInput, blockSize: blockSize))

        // Assemble protected APDU data: DO'87/85 || DO'97 || DO'8E
        var protectedData = cryptogramDO
        protectedData.append(do97)
        protectedData.append(contentsOf: [0x8E, UInt8(mode.macLength)])
        protectedData.append(cc)

        // Outer Le covers the protected response: 256 for short commands, 65 536
        // (extended Le 0000) when the plain command asked for more than 256 bytes.
        let extended = (apdu.expectedResponseLength ?? 0) > 256
        return CommandAPDU(
            cla: maskedCLA,
            ins: apdu.ins,
            p1: apdu.p1,
            p2: apdu.p2,
            data: protectedData,
            expectedResponseLength: extended ? CommandAPDU.maxExpectedResponseLength : 256
        )
    }

    // MARK: - Unprotect (Verify MAC + Decrypt incoming response)

    /// Unprotect a secure messaging response: verify DO'8E MAC, then decrypt DO'87/DO'85.
    ///
    /// ICAO 9303-11 §9.8 makes DO'99 and DO'8E mandatory in every protected response, and
    /// ISO/IEC 7816-4 §10.2 requires verifying the checksum before using any data object.
    /// The MAC covers every odd-tag data object preceding DO'8E exactly as received.
    private func unprotect(_ response: ResponseAPDU) throws -> ResponseAPDU {
        let data = Data(response.data)

        // A response without data objects is a plain status word: the chip reports an
        // error (typically aborting secure messaging) without protecting it.
        guard !data.isEmpty else {
            if response.isSuccess {
                throw NFCError.secureMessagingError("Response is missing secure messaging data objects")
            }
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }

        var authenticatedBytes = Data()
        var cryptogram: (value: Data, hasPaddingIndicator: Bool)?
        var do99Value: Data?
        var do8eValue: Data?
        var offset = 0

        while offset < data.count {
            let objectStart = offset
            let tag = data[offset]
            offset += 1

            guard offset < data.count else {
                throw NFCError.secureMessagingError("Truncated secure messaging data object")
            }
            let (length, lengthBytes) = try ASN1Parser.parseLength(data, at: offset)
            offset += lengthBytes

            guard length >= 0, length <= data.count - offset else {
                throw NFCError.secureMessagingError("Secure messaging data object length exceeds response")
            }
            let value = Data(data[offset ..< offset + length])
            offset += length

            if tag == 0x8E {
                // Nothing may follow the checksum: trailing bytes would be unauthenticated.
                guard offset == data.count else {
                    throw NFCError.secureMessagingError("Unexpected data after DO'8E")
                }
                do8eValue = value
                break
            }

            // ISO/IEC 7816-4 §10.2.3: data objects with an odd tag are included in the MAC.
            if tag & 0x01 == 0x01 {
                authenticatedBytes.append(data[objectStart ..< offset])
            }

            switch tag {
            case 0x87, 0x85:
                guard cryptogram == nil else {
                    throw NFCError.secureMessagingError("Duplicate cryptogram data object")
                }
                cryptogram = (value, tag == 0x87)
            case 0x99:
                guard do99Value == nil else {
                    throw NFCError.secureMessagingError("Duplicate DO'99")
                }
                do99Value = value
            default:
                break
            }
        }

        guard let do8eValue, do8eValue.count == mode.macLength else {
            throw NFCError.secureMessagingError("Missing or invalid DO'8E (cryptographic checksum)")
        }
        guard let do99Value, do99Value.count == 2 else {
            throw NFCError.secureMessagingError("Missing or invalid DO'99 (status word)")
        }

        var macInput = paddedSSC()
        macInput.append(authenticatedBytes)
        let computedMAC = try computeMAC(ISO9797Padding.pad(macInput, blockSize: mode.blockSize))
        guard CryptoUtils.constantTimeEquals(computedMAC, do8eValue) else {
            throw NFCError.secureMessagingError("MAC verification failed")
        }

        var plaintext = Data()
        if let cryptogram {
            let encrypted: Data
            if cryptogram.hasPaddingIndicator {
                guard cryptogram.value.count > 1, cryptogram.value[0] == 0x01 else {
                    throw NFCError.secureMessagingError("Invalid DO'87: missing padding content indicator")
                }
                encrypted = Data(cryptogram.value.dropFirst())
            } else {
                encrypted = cryptogram.value
            }
            guard !encrypted.isEmpty, encrypted.count % mode.blockSize == 0 else {
                throw NFCError.secureMessagingError("Cryptogram length is not a multiple of the cipher block size")
            }

            let decrypted: Data
            switch mode {
            case .tripleDES:
                decrypted = try CryptoUtils.tripleDESDecrypt(key: ksEnc, message: encrypted)
            case .aes128, .aes192, .aes256:
                let iv = try computeAESIV()
                decrypted = try CryptoUtils.aesDecrypt(key: ksEnc, message: encrypted, iv: iv)
            }
            plaintext = try ISO9797Padding.strictUnpad(decrypted, blockSize: mode.blockSize)
        }

        return ResponseAPDU(data: plaintext, sw1: do99Value[0], sw2: do99Value[1])
    }

    // MARK: - MAC Computation

    /// SSC as used in MAC input: 8 bytes for 3DES, zero-extended to 16 bytes for AES.
    private func paddedSSC() -> Data {
        switch mode {
        case .tripleDES:
            ssc
        case .aes128, .aes192, .aes256:
            Data(repeating: 0x00, count: 8) + ssc
        }
    }

    /// Compute MAC using the appropriate algorithm for the current mode.
    private func computeMAC(_ paddedData: Data) throws -> Data {
        switch mode {
        case .tripleDES:
            return try ISO9797MAC.mac(key: ksMac, message: paddedData)
        case .aes128, .aes192, .aes256:
            // AES-CMAC returns 16 bytes, truncate to 8 for Secure Messaging
            let fullMAC = try AESCMAC.mac(key: ksMac, message: paddedData)
            return Data(fullMAC.prefix(8))
        }
    }

    /// Compute AES IV = AES-ECB(KSenc, paddedSSC).
    /// paddedSSC = [0x00]*8 || SSC (8 bytes → 16 bytes for AES block size)
    private func computeAESIV() throws -> Data {
        let paddedSSC = Data(repeating: 0x00, count: 8) + ssc
        return try CryptoUtils.aesECBEncrypt(key: ksEnc, message: paddedSSC)
    }

    // MARK: - SSC

    /// Increment the Send Sequence Counter by 1 (big-endian, wrapping).
    private func incrementSSC() {
        var index = ssc.endIndex
        while index > ssc.startIndex {
            index -= 1
            let (sum, overflow) = ssc[index].addingReportingOverflow(1)
            ssc[index] = sum
            if !overflow { break }
        }
    }
}

extension SecureMessagingTransport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Names the cipher mode only: session keys and the SSC are never printed.
    public var description: String {
        "SecureMessagingTransport(mode: \(mode), ksEnc: \(SecretRedaction.redacted(ksEnc)), "
            + "ksMac: \(SecretRedaction.redacted(ksMac)))"
    }

    public var debugDescription: String {
        description
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "mode": mode,
            "ksEnc": SecretRedaction.redacted(ksEnc),
            "ksMac": SecretRedaction.redacted(ksMac),
        ], displayStyle: .class)
    }
}

/// FIFO async mutual exclusion used to keep secure messaging exchanges strictly sequential.
///
/// Unlike an actor, the gate stays held across suspension points, so a second
/// `sendAPDU` cannot interleave between protect/send/unprotect of the first.
final class AsyncExchangeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let acquired: Bool = lock.withLock {
                if isHeld {
                    waiters.append(continuation)
                    return false
                }
                isHeld = true
                return true
            }
            if acquired {
                continuation.resume()
            }
        }
    }

    func release() {
        let next: CheckedContinuation<Void, Never>? = lock.withLock {
            if waiters.isEmpty {
                isHeld = false
                return nil
            }
            return waiters.removeFirst()
        }
        next?.resume()
    }
}
