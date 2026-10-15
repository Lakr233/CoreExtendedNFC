import Foundation

/// Reader for Japanese My Number cards over ISO 7816 APDU.
///
/// Flow reference mirrored from deployed iOS readers:
/// - Token info: SELECT JPKI AP -> SELECT EF 0006 -> READ BINARY(20)
/// - Individual number: SELECT card-info-input-support AP -> SELECT EF 0011
///   -> VERIFY(PIN) -> SELECT EF 0001 -> READ BINARY(17)
public struct MyNumberCardReader: Sendable {
    let transport: any ISO7816TagTransporting

    public init(transport: any ISO7816TagTransporting) {
        self.transport = transport
    }

    /// Read one or more fields from a My Number card.
    public func read(
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil
    ) async throws -> MyNumberCardData {
        guard !items.isEmpty else {
            throw NFCError.unsupportedOperation("No My Number card fields were requested")
        }

        var tokenInfo: String?
        var individualNumber: String?

        // Each field is read once even if requested twice, so the PIN VERIFY
        // (which costs a retry on failure) is sent at most once.
        var seen = Set<MyNumberCardItem>()
        let uniqueItems = items.filter { seen.insert($0).inserted }

        for item in uniqueItems {
            switch item {
            case .tokenInfo:
                tokenInfo = try await readTokenInfo()
            case .individualNumber:
                guard let pin = cardInfoInputSupportPIN else {
                    throw NFCError.unsupportedOperation("Reading My Number requires `cardInfoInputSupportPIN`")
                }
                individualNumber = try await readIndividualNumber(cardInfoInputSupportPIN: pin)
            }
        }

        return MyNumberCardData(tokenInfo: tokenInfo, individualNumber: individualNumber)
    }

    /// Read JPKI token info (`EF 0006`).
    public func readTokenInfo() async throws -> String {
        try await selectDF(MyNumberCardConstants.jpkiAID)
        try await selectEF(MyNumberCardConstants.jpkiTokenEFID)
        let response = try await readBinary(length: MyNumberCardConstants.tokenLength)

        let raw = String(decoding: response.data, as: UTF8.self)
        let normalized = raw.filter { !$0.isWhitespace }
        guard !normalized.isEmpty else {
            throw NFCError.invalidResponse(response.data)
        }

        return normalized
    }

    /// Read the 12-digit individual number.
    ///
    /// Requires the 4-digit card-info-input-support PIN.
    ///
    /// Before the PIN is sent, an empty VERIFY (ISO/IEC 7816-4 §11.5.6, `Lc`
    /// absent) reads the retry counter. When the PIN is already blocked
    /// (`63C0`, `6983`, `6984`) the PIN is never transmitted and
    /// ``NFCError/pinVerificationFailed(remainingAttempts:)`` is thrown with `0`.
    /// A wrong PIN throws the same error with the counter the card reports.
    ///
    /// Official EF 0001 payload layout:
    /// `[0x10, 0x01, 0x0C, 12 ASCII digits, trailer(2 bytes)]` (17 bytes total).
    public func readIndividualNumber(cardInfoInputSupportPIN: String) async throws -> String {
        let pinData = try validateCardInfoInputSupportPIN(cardInfoInputSupportPIN)

        try await selectDF(MyNumberCardConstants.cardInfoInputSupportAID)
        try await selectEF(MyNumberCardConstants.cardInfoInputSupportPINEFID)

        let statusResponse = try await verify(Data())
        if Self.isPINBlocked(statusResponse) {
            throw NFCError.pinVerificationFailed(remainingAttempts: 0)
        }
        // 9000 on the empty VERIFY means the PIN is already verified in this
        // session, so there is nothing to send.
        if !statusResponse.isSuccess {
            let verifyResponse = try await verify(pinData)
            if !verifyResponse.isSuccess {
                throw Self.verificationError(for: verifyResponse)
            }
        }

        try await selectEF(MyNumberCardConstants.individualNumberEFID)
        let numberResponse = try await readBinary(length: MyNumberCardConstants.individualNumberLength)

        guard let number = Self.parseIndividualNumber(numberResponse.data) else {
            throw NFCError.invalidResponse(numberResponse.data)
        }

        return number
    }

    /// Query remaining PIN attempts for a specific PIN domain.
    ///
    /// The card returns `63Cx` for empty VERIFY in this flow, where `x` is remaining attempts.
    public func lookupRemainingPINAttempts(for pinType: MyNumberPINType) async throws -> Int {
        let (aid, efid) = pinAttemptSelector(for: pinType)

        try await selectDF(aid)
        try await selectEF(efid)

        let response = try await verify(Data())
        if Self.isPINBlocked(response) {
            return 0
        }
        guard let remaining = Self.retryCounter(response) else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
        return remaining
    }

    /// Retry counter from a `63Cx` status (ISO/IEC 7816-4 §5.6: `63Cx` = counter
    /// `x`). `6300` and other `63xx` warnings carry no counter.
    static func retryCounter(_ response: ResponseAPDU) -> Int? {
        guard response.sw1 == 0x63, response.sw2 & 0xF0 == 0xC0 else { return nil }
        return Int(response.sw2 & 0x0F)
    }

    /// `63C0` (no tries left), `6983` (authentication method blocked) or
    /// `6984` (reference data not usable).
    static func isPINBlocked(_ response: ResponseAPDU) -> Bool {
        if retryCounter(response) == 0 { return true }
        return response.sw1 == 0x69 && (response.sw2 == 0x83 || response.sw2 == 0x84)
    }

    static func verificationError(for response: ResponseAPDU) -> NFCError {
        if isPINBlocked(response) {
            return .pinVerificationFailed(remainingAttempts: 0)
        }
        if let remaining = retryCounter(response) {
            return .pinVerificationFailed(remainingAttempts: remaining)
        }
        if response.sw1 == 0x63 {
            return .pinVerificationFailed(remainingAttempts: nil)
        }
        return .unexpectedStatusWord(response.sw1, response.sw2)
    }

    // MARK: - Private

    private func selectDF(_ aid: Data) async throws {
        let response = try await transport.sendAPDUWithChaining(CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: aid
        ))
        try requireSuccess(response)
    }

    private func selectEF(_ fileID: Data) async throws {
        let response = try await transport.sendAPDUWithChaining(.selectEF(id: fileID))
        try requireSuccess(response)
    }

    private func verify(_ pinData: Data) async throws -> ResponseAPDU {
        try await transport.sendAPDUWithChaining(CommandAPDU(
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x80,
            data: pinData
        ))
    }

    private func readBinary(length: UInt8) async throws -> ResponseAPDU {
        let response = try await transport.sendAPDUWithChaining(.readBinary(offset: 0, length: length))
        try requireSuccess(response)
        return response
    }

    private func requireSuccess(_ response: ResponseAPDU) throws {
        guard response.isSuccess else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }
    }

    private func validateCardInfoInputSupportPIN(_ pin: String) throws -> Data {
        let bytes = Data(pin.utf8)
        guard bytes.count == 4, bytes.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
            throw NFCError.unsupportedOperation("`cardInfoInputSupportPIN` must be exactly 4 digits")
        }
        return bytes
    }

    private func pinAttemptSelector(for pinType: MyNumberPINType) -> (Data, Data) {
        switch pinType {
        case .digitalSignature:
            (MyNumberCardConstants.jpkiAID, MyNumberCardConstants.remainingDigitalSignaturePINEFID)
        case .userAuthentication:
            (MyNumberCardConstants.jpkiAID, MyNumberCardConstants.remainingUserAuthenticationPINEFID)
        case .cardInfoInputSupport:
            (MyNumberCardConstants.cardInfoInputSupportAID, MyNumberCardConstants.remainingCardInfoInputSupportPINEFID)
        case .individualNumber:
            (MyNumberCardConstants.individualNumberAID, MyNumberCardConstants.remainingIndividualNumberPINEFID)
        }
    }

    private static func parseIndividualNumber(_ data: Data) -> String? {
        if data.count == Int(MyNumberCardConstants.individualNumberLength),
           data.first == MyNumberCardConstants.individualNumberHeaderByte
        {
            return parseOfficialIndividualNumberPayload(data)
        }

        // Otherwise accept only the same layout with a different trailer
        // length: header 0x10, then TLV `01 0C` holding 12 ASCII digits. No
        // free-text search for "any 12 digits", which could return garbage.
        guard data.count > 1, data.first == MyNumberCardConstants.individualNumberHeaderByte else {
            return nil
        }
        if let nodes = try? ASN1Parser.parseTLV(Data(data.dropFirst())),
           let first = nodes.first,
           first.tag == UInt(MyNumberCardConstants.individualNumberTag),
           first.value.count == MyNumberCardConstants.individualNumberDigitsCount,
           first.value.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 })
        {
            return String(decoding: first.value, as: UTF8.self)
        }

        return nil
    }

    private static func parseOfficialIndividualNumberPayload(_ data: Data) -> String? {
        let bytes = [UInt8](data)
        let requiredCount = 1 + 1 + 1 + MyNumberCardConstants.individualNumberDigitsCount + MyNumberCardConstants.individualNumberTrailerCount
        guard bytes.count == requiredCount else { return nil }
        guard bytes[0] == MyNumberCardConstants.individualNumberHeaderByte else { return nil }
        guard bytes[1] == MyNumberCardConstants.individualNumberTag else { return nil }
        guard bytes[2] == MyNumberCardConstants.individualNumberDigitsLength else { return nil }

        let digitsStart = 3
        let digitsEnd = digitsStart + MyNumberCardConstants.individualNumberDigitsCount
        let digitsBytes = bytes[digitsStart ..< digitsEnd]
        guard digitsBytes.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }

        return String(decoding: digitsBytes, as: UTF8.self)
    }
}
