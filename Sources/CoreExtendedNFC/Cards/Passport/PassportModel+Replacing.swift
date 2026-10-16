import Foundation

public extension PassportModel {
    /// A copy with a new Active Authentication result and security report.
    func replacing(
        activeAuthResult: ActiveAuthenticationResult?,
        securityReport: PassportSecurityReport
    ) -> PassportModel {
        PassportModel(
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            ldsVersion: ldsVersion,
            unicodeVersion: unicodeVersion,
            availableDataGroups: availableDataGroups,
            mrz: mrz,
            faceImageData: faceImageData,
            signatureImageData: signatureImageData,
            additionalPersonalDetails: additionalPersonalDetails,
            additionalDocumentDetails: additionalDocumentDetails,
            securityInfos: securityInfos,
            securityInfoRaw: securityInfoRaw,
            activeAuthPublicKey: activeAuthPublicKey,
            activeAuthPublicKeyRaw: activeAuthPublicKeyRaw,
            sod: sod,
            sodRaw: sodRaw,
            passiveAuthResult: passiveAuthResult,
            activeAuthResult: activeAuthResult,
            rawDataGroups: rawDataGroups,
            securityReport: securityReport,
            dataGroupReadStatus: dataGroupReadStatus
        )
    }
}
