import Foundation

/// Known ISO 7816 application identifiers seen in Core NFC workflows.
public enum ISO7816Application: String, Sendable, Codable, CaseIterable {
    case ndefTagApplication = "D2760000850101"
    case ndefCardManager = "D2760000850100"
    case eMRTDLDS = "A0000002471001"
    case eMRTDAuxiliary = "A0000002472001"
    case paymentSystemEnvironment = "315041592E5359532E4444463031"
    case unionPayPayment = "A00000000386980701"
    case chinaDocument = "F049442E43484E"
    case myNumberJPKI = "D392F000260100000001"
    case myNumberCardInfoInputSupport = "D3921000310001010408"
    case myNumberIndividualNumber = "D3921000310001010100"
    case myNumberCardInfoInputCheck = "D3921000310001010401"
    case issuerPlaceholder = "00000000000000"

    public static func match(aid: String?) -> ISO7816Application? {
        guard let normalized = normalize(aid) else { return nil }
        return ISO7816Application(rawValue: normalized)
    }

    public var displayName: String {
        switch self {
        case .ndefTagApplication:
            "NFC Forum Type 4 NDEF Application"
        case .ndefCardManager:
            "NFC Forum / DESFire Compatibility Application"
        case .eMRTDLDS:
            "ICAO eMRTD LDS Application"
        case .eMRTDAuxiliary:
            "ICAO eMRTD Auxiliary Application"
        case .paymentSystemEnvironment:
            "EMV Payment System Environment (1PAY.SYS.DDF01)"
        case .unionPayPayment:
            "UnionPay Payment Application"
        case .chinaDocument:
            "China Document Application (observed)"
        case .myNumberJPKI:
            "Japan My Number JPKI Application"
        case .myNumberCardInfoInputSupport:
            "Japan My Number Card-Info Input Support Application"
        case .myNumberIndividualNumber:
            "Japan My Number Individual Number Application"
        case .myNumberCardInfoInputCheck:
            "Japan My Number Card-Info Input Check Application"
        case .issuerPlaceholder:
            "Issuer Placeholder / Catch-All AID"
        }
    }

    public var note: String {
        switch self {
        case .ndefTagApplication:
            "Standard Type 4 Tag NDEF AID. Apple routes matching tags through the ISO 7816 interface when this AID is present in Info.plist."
        case .ndefCardManager:
            "Observed in public NFC app configurations. Often paired with DESFire or NFC Forum card-manager style flows."
        case .eMRTDLDS:
            "The standard ICAO LDS application used by ePassports and other eMRTD chips."
        case .eMRTDAuxiliary:
            "The ICAO auxiliary application used by some travel documents for hashes, signatures, or certificate-related data."
        case .paymentSystemEnvironment:
            "EMV payment directory selection AID. Payment-tag workflows on iOS use additional platform APIs and availability rules."
        case .unionPayPayment:
            "Observed in UnionPay-family app configurations. The exact payment flow remains issuer-specific after SELECT succeeds."
        case .chinaDocument:
            "Observed in public Chinese app packages. The label is inferred from the ASCII tail “ID.CHN”, not from a published standard."
        case .myNumberJPKI:
            "The Japanese public personal authentication (JPKI) applet used by My Number cards for token/certificate-related workflows."
        case .myNumberCardInfoInputSupport:
            "The Japanese card-info input support applet used to verify a PIN before reading protected My Number fields."
        case .myNumberIndividualNumber:
            "Observed in My Number card app configurations for individual-number / resident-registry related access control."
        case .myNumberCardInfoInputCheck:
            "Observed in My Number card app configurations as a companion card-info applet."
        case .issuerPlaceholder:
            "A broad fallback selector seen in some document-reading apps when the real applet responds from a proprietary root context."
        }
    }

    public var hintedCardType: CardType? {
        switch self {
        case .ndefTagApplication:
            .type4NDEF
        case .eMRTDLDS:
            .ePassport
        case .myNumberJPKI, .myNumberCardInfoInputSupport, .myNumberIndividualNumber, .myNumberCardInfoInputCheck:
            .myNumberCard
        default:
            nil
        }
    }

    private static func normalize(_ aid: String?) -> String? {
        let normalized = aid?
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "<", with: "")
            .replacingOccurrences(of: ">", with: "")
            .uppercased()

        guard let normalized, !normalized.isEmpty else { return nil }
        return normalized
    }
}

public extension CardInfo {
    /// The best-known ISO 7816 application selected by the system during discovery.
    var knownISO7816Application: ISO7816Application? {
        ISO7816Application.match(aid: initialSelectedAID)
    }
}
