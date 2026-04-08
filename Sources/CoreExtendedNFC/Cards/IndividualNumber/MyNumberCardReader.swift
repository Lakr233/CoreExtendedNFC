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

        for item in items {
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
    public func readIndividualNumber(cardInfoInputSupportPIN: String) async throws -> String {
        let pinData = try validateCardInfoInputSupportPIN(cardInfoInputSupportPIN)

        try await selectDF(MyNumberCardConstants.cardInfoInputSupportAID)
        try await selectEF(MyNumberCardConstants.cardInfoInputSupportPINEFID)

        let verifyResponse = try await verify(pinData)
        if verifyResponse.sw1 == 0x63 {
            let remaining = Int(verifyResponse.sw2 & 0x0F)
            throw NFCError.unsupportedOperation(
                "Card-info-input-support PIN verification failed (\(remaining) attempt(s) remaining)"
            )
        }
        try requireSuccess(verifyResponse)

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
        guard response.sw1 == 0x63 else {
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }

        return Int(response.sw2 & 0x0F)
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
        let response = try await transport.sendAPDUWithChaining(CommandAPDU(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x02,
            p2: 0x0C,
            data: fileID
        ))
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
        let response = try await transport.sendAPDUWithChaining(CommandAPDU(
            cla: 0x00,
            ins: 0xB0,
            p1: 0x00,
            p2: 0x00,
            le: length
        ))
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
        let tlvPayload = data.count > 1 ? Data(data.dropFirst()) : data

        if let nodes = try? ASN1Parser.parseTLV(tlvPayload),
           let firstValue = nodes.first?.value,
           let candidate = String(data: firstValue, encoding: .utf8),
           candidate.count == 12,
           candidate.allSatisfy(\.isNumber)
        {
            return candidate
        }

        let fallback = String(decoding: data, as: UTF8.self)
        if let matchRange = fallback.range(of: #"\d{12}"#, options: .regularExpression) {
            return String(fallback[matchRange])
        }

        return nil
    }
}
