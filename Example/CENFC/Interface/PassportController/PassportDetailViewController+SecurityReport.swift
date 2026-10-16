import CoreExtendedNFC
import UIKit

extension PassportDetailViewController {
    /// One line of the security report as shown on screen.
    nonisolated struct SecurityRow: Equatable, Sendable {
        let title: String
        let value: String
        let icon: String
        let isDestructive: Bool
        var isPassiveAuthentication = false
        var isActiveAuthentication = false
    }

    /// The security report rows for `record`.
    ///
    /// The rows for `record` with the stages re-derived by
    /// ``PassportRecord/reverifiedSecurity()`` (`nil` while that runs).
    static func securityRows(
        for record: PassportRecord,
        reverified: PassportRecord.ReverifiedSecurity?
    ) -> [SecurityRow] {
        securityRows(
            for: record,
            reverifiedPassiveAuthentication: reverified?.passiveAuthentication,
            reverifiedPassiveAuthStatus: reverified?.passiveAuthStatus,
            reverifiedActiveAuthentication: reverified?.activeAuthentication
        )
    }

    /// A record imported from a file carries whatever security results its
    /// author wrote. BAC, PACE and Chip Authentication can only be proven
    /// against the physical chip, so imported records show those stages as
    /// "not re-verified" instead of the stored result. Passive Authentication
    /// only needs the bytes, so for imported records it shows
    /// `reverifiedPassiveAuthentication`, or "Verifying" while that is still
    /// `nil`. Active Authentication shows the stored AA result re-judged against
    /// it (`reverifiedActiveAuthentication`), or "not re-verified" when there is
    /// none. The file's own PA and AA stages are never shown.
    static func securityRows(
        for record: PassportRecord,
        reverifiedPassiveAuthentication: PassportSecurityStageResult? = nil,
        reverifiedPassiveAuthStatus: PassiveAuthenticationStatus? = nil,
        reverifiedActiveAuthentication: PassportSecurityStageResult? = nil
    ) -> [SecurityRow] {
        let report = record.passport.securityReport
        let stages: [(title: String, stage: PassportSecurityStageResult, isPassiveAuthentication: Bool)] = [
            (String(localized: "Card Access"), report.cardAccess, false),
            (String(localized: "PACE"), report.pace, false),
            (String(localized: "BAC"), report.bac, false),
            (String(localized: "Chip Authentication"), report.chipAuthentication, false),
            (String(localized: "Passive Authentication"), report.passiveAuthentication, true),
            (String(localized: "Active Authentication"), report.activeAuthentication, false),
        ]
        let activeTitle = String(localized: "Active Authentication")
        return stages.map { title, stage, isPassiveAuthentication in
            let isActiveAuthentication = title == activeTitle
            if record.isImported, isActiveAuthentication, let reverified = reverifiedActiveAuthentication {
                let (icon, isDestructive) = securityIcon(for: reverified.status)
                return SecurityRow(
                    title: title,
                    value: securityValue(for: reverified, isPassiveAuthentication: false),
                    icon: icon,
                    isDestructive: isDestructive,
                    isActiveAuthentication: true
                )
            }
            if record.isImported, isPassiveAuthentication {
                guard let reverified = reverifiedPassiveAuthentication else {
                    return SecurityRow(
                        title: title,
                        value: String(localized: "Verifying…"),
                        icon: "circle.dotted",
                        isDestructive: false,
                        isPassiveAuthentication: true
                    )
                }
                let (icon, isDestructive) = securityIcon(for: reverified.status)
                return SecurityRow(
                    title: title,
                    value: securityValue(
                        for: reverified,
                        isPassiveAuthentication: true,
                        passiveAuthStatus: reverifiedPassiveAuthStatus
                    ),
                    icon: icon,
                    isDestructive: isDestructive,
                    isPassiveAuthentication: true
                )
            }
            if record.isImported {
                return SecurityRow(
                    title: title,
                    value: String(localized: "Imported, not re-verified"),
                    icon: "questionmark.circle",
                    isDestructive: false,
                    isActiveAuthentication: isActiveAuthentication
                )
            }
            let (icon, isDestructive) = securityIcon(for: stage.status)
            return SecurityRow(
                title: title,
                value: securityValue(
                    for: stage,
                    isPassiveAuthentication: isPassiveAuthentication,
                    passiveAuthStatus: isPassiveAuthentication ? record.passport.passiveAuthResult?.status : nil
                ),
                icon: icon,
                isDestructive: isDestructive,
                isPassiveAuthentication: isPassiveAuthentication,
                isActiveAuthentication: isActiveAuthentication
            )
        }
    }

    private static func securityIcon(for status: PassportSecurityStageStatus) -> (String, Bool) {
        switch status {
        case .succeeded: ("checkmark.circle.fill", false)
        case .failed: ("xmark.circle.fill", true)
        case .fallback: ("exclamationmark.triangle.fill", false)
        case .skipped, .notAdvertised, .notSupported: ("minus.circle", false)
        case .pending: ("circle.dotted", false)
        }
    }

    /// The localized text shown for a security stage.
    ///
    /// The library's `detail` strings are English diagnostics, so the row shows
    /// app text derived from the stage status instead. For passive
    /// authentication, `passiveAuthStatus` (from the chip read) gives a more
    /// specific reason; without it the status of the stage decides.
    static func securityValue(
        for stage: PassportSecurityStageResult,
        isPassiveAuthentication: Bool,
        passiveAuthStatus: PassiveAuthenticationStatus? = nil
    ) -> String {
        guard isPassiveAuthentication else {
            return statusTitle(stage.status)
        }
        switch stage.status {
        case .succeeded, .fallback, .failed:
            if let passiveAuthStatus {
                return passiveAuthenticationText(passiveAuthStatus)
            }
        default:
            break
        }
        switch stage.status {
        case .succeeded:
            return String(localized: "Verified against a trusted CSCA")
        case .fallback:
            return String(localized: "Hashes match; Document Signer certificate not validated to a trusted CSCA")
        case .notSupported:
            return String(localized: "No SOD available")
        default:
            return statusTitle(stage.status)
        }
    }

    static func passiveAuthenticationText(_ status: PassiveAuthenticationStatus) -> String {
        switch status {
        case .fullyVerified:
            String(localized: "Verified against a trusted CSCA")
        case .signatureVerified:
            String(localized: "Hashes and signature valid; Document Signer certificate not validated to a trusted CSCA")
        case .dataGroupHashesVerified, .signatureNotVerified:
            String(localized: "Hashes match; signature not verified")
        case .hashMismatch:
            String(localized: "Data group hash mismatch")
        case .sodParseFailed:
            String(localized: "SOD could not be parsed")
        case .sodNotAvailable:
            String(localized: "No SOD available")
        case .unsupportedHashAlgorithm:
            String(localized: "Unsupported hash algorithm")
        case .signatureInvalid:
            String(localized: "SOD signature invalid")
        case .trustChainInvalid:
            String(localized: "Document Signer certificate not trusted")
        }
    }

    static func statusTitle(_ status: PassportSecurityStageStatus) -> String {
        switch status {
        case .pending: String(localized: "Pending")
        case .succeeded: String(localized: "Succeeded")
        case .failed: String(localized: "Failed")
        case .fallback: String(localized: "Fallback")
        case .skipped: String(localized: "Skipped")
        case .notAdvertised: String(localized: "Not Advertised")
        case .notSupported: String(localized: "Not Supported")
        }
    }
}
