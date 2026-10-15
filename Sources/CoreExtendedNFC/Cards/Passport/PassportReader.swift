import Foundation

/// Orchestrates the full eMRTD reading workflow:
/// SELECT application → BAC authentication → read DataGroups → parse → verify.
public struct PassportReader: Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    /// Read passport data groups after performing BAC authentication.
    ///
    /// - Parameters:
    ///   - mrzKey: The MRZ key string for BAC authentication.
    ///   - dataGroups: Which data groups to read (default: COM, DG1, DG2, SOD).
    ///   - performActiveAuth: Whether to attempt Active Authentication if DG15 is available.
    ///   - onProgress: Optional callback for progress messages.
    /// - Returns: A `PassportModel` with all parsed data.
    public func readPassport(
        mrzKey: String,
        dataGroups: [DataGroupId] = [.com, .dg1, .dg2, .sod],
        performActiveAuth: Bool = true,
        trustAnchorsDER: [Data] = [],
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> PassportModel {
        NFCLog.info("Starting passport read: DGs=\(dataGroups.map(\.name).joined(separator: ","))", source: "Passport")
        var cardAccessRaw: Data?
        var cardAccess: SecurityInfos?
        var cardAccessStage = PassportSecurityStageResult(
            status: .notSupported,
            detail: "EF.CardAccess was not read."
        )
        var paceStage = PassportSecurityStageResult(
            status: .notSupported,
            detail: "PACE was not negotiated."
        )
        var bacStage = PassportSecurityStageResult(
            status: .pending,
            detail: "BAC has not run yet."
        )

        onProgress?("Reading CardAccess...")
        do {
            let rawCardAccess = try await readCardAccess(transport: transport)
            let parsedCardAccess = try CardAccessParser.parse(rawCardAccess)
            cardAccessRaw = rawCardAccess
            cardAccess = parsedCardAccess
            cardAccessStage = PassportSecurityStageResult(
                status: .succeeded,
                detail: parsedCardAccess.supportsPACE
                    ? "EF.CardAccess was read and advertises PACE."
                    : "EF.CardAccess was read."
            )
            paceStage = PassportSecurityStageResult(
                status: parsedCardAccess.supportsPACE ? .pending : .notAdvertised,
                detail: parsedCardAccess.supportsPACE
                    ? "PACE parameters were advertised in EF.CardAccess."
                    : "EF.CardAccess does not advertise PACE."
            )
        } catch {
            // A missing or malformed EF.CardAccess only means "no PACE"; a lost tag or a
            // cancelled task ends the whole read.
            if isSessionTerminating(error) { throw error }
            cardAccessStage = PassportSecurityStageResult(
                status: .notSupported,
                detail: "EF.CardAccess unavailable: \(error.localizedDescription)"
            )
            paceStage = PassportSecurityStageResult(
                status: .notSupported,
                detail: "PACE advertisement could not be determined because EF.CardAccess was unavailable."
            )
        }

        // Step 1: SELECT eMRTD application
        onProgress?("Selecting application...")
        NFCLog.debug("SELECT eMRTD application", source: "Passport")
        let selectAPDU = CommandAPDU.selectPassportApplication()
        let selectResponse = try await transport.sendAPDU(selectAPDU)

        guard selectResponse.isSuccess else {
            throw NFCError.bacFailed("SELECT eMRTD failed: SW=\(String(format: "%04X", selectResponse.statusWord))")
        }

        // Step 2: Prefer PACE when EF.CardAccess advertises it, otherwise fall back to BAC.
        var smTransport: SecureMessagingTransport?
        if let paceInfo = cardAccess?.paceInfos.first {
            onProgress?("Attempting PACE...")
            do {
                smTransport = try await PACEHandler.performPACE(
                    paceInfo: paceInfo,
                    mrzKey: mrzKey,
                    transport: transport
                )
                paceStage = PassportSecurityStageResult(
                    status: .succeeded,
                    detail: "PACE completed and established secure messaging."
                )
                bacStage = PassportSecurityStageResult(
                    status: .skipped,
                    detail: "BAC was skipped because PACE succeeded."
                )
            } catch {
                if isSessionTerminating(error) { throw error }
                paceStage = PassportSecurityStageResult(
                    status: .fallback,
                    detail: "PACE could not complete: \(error.localizedDescription). Falling back to BAC."
                )
            }
        }

        if smTransport == nil {
            onProgress?("Authenticating with BAC...")
            smTransport = try await BACHandler.performBAC(
                mrzKey: mrzKey,
                transport: transport
            )
            bacStage = PassportSecurityStageResult(
                status: .succeeded,
                detail: "BAC established secure messaging."
            )
        }

        guard let smTransport else {
            throw NFCError.secureMessagingError("No secure messaging transport was established")
        }

        // Step 3: Read each requested DataGroup.
        //
        // EF.COM is read first and, once parsed, only the data groups it lists are
        // selected: selecting an absent file draws a plain 6A82, and ICAO 9303-11 §9.8
        // lets the chip end secure messaging on any unprotected reply. DG1 follows COM,
        // and EAC-protected DG3/DG4 (likely a plain 6982 under BAC/PACE) go last, so
        // an ICAO-strict chip ending the session there cannot cost DG1/DG2/SOD.
        var session = DataGroupReadSession(transport: smTransport)
        let readOrder = Self.readOrder(for: dataGroups)

        for (index, dgId) in readOrder.enumerated() {
            try Task.checkCancellation()
            guard session.shouldSelect(dgId) else { continue }
            onProgress?("Reading \(dgId.name) (\(index + 1)/\(readOrder.count))...")
            try await session.read(dgId) { try await readDataGroup(dgId, transport: smTransport) }
        }

        // Step 4: If AA was requested but DG15 wasn't in the list, read it when present.
        if performActiveAuth, !readOrder.contains(.dg15), session.isListedInCOM(.dg15) ?? true,
           session.secureMessagingEnded == nil
        {
            try Task.checkCancellation()
            onProgress?("Reading DG15 (Active Auth Key)...")
            try await session.read(.dg15) { try await readDataGroup(.dg15, transport: smTransport) }
        }

        // A read that could not even deliver DG1 (or anything at all) is a failed read,
        // not a partial one.
        if let failure = session.firstFailure,
           session.rawDataGroups.isEmpty || (readOrder.contains(.dg1) && session.rawDataGroups[.dg1] == nil)
        {
            throw failure
        }
        let rawDataGroups = session.rawDataGroups

        // Step 5: Parse and assemble
        onProgress?("Processing...")
        var model = assemblePassportModel(
            rawDataGroups: rawDataGroups,
            trustAnchorsDER: trustAnchorsDER,
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            securityReport: PassportSecurityReport(
                cardAccess: cardAccessStage,
                pace: paceStage,
                bac: bacStage,
                chipAuthentication: .init(),
                passiveAuthentication: .init(),
                activeAuthentication: .init()
            ),
            dataGroupReadStatus: session.status
        )

        let chipAuthenticationStage = buildChipAuthenticationStage(model.securityInfos)
        let passiveAuthenticationStage = buildPassiveAuthenticationStage(
            passiveAuthResult: model.passiveAuthResult,
            sodPresent: rawDataGroups[.sod] != nil
        )

        // Step 6: Perform Active Authentication if possible
        var activeAuthenticationStage = buildActiveAuthenticationStage(
            requested: performActiveAuth,
            publicKey: model.activeAuthPublicKey,
            result: nil
        )
        if performActiveAuth, model.activeAuthPublicKey != nil, let reason = session.secureMessagingEnded {
            activeAuthenticationStage = PassportSecurityStageResult(
                status: .skipped,
                detail: "Active Authentication was not attempted because secure messaging ended: \(reason)"
            )
        }
        if performActiveAuth, session.secureMessagingEnded == nil, let publicKey = model.activeAuthPublicKey {
            onProgress?("Verifying chip authenticity...")
            let aaResult: ActiveAuthenticationResult
            do {
                aaResult = try await performActiveAuthentication(
                    publicKey: publicKey,
                    subjectPublicKeyInfo: rawDataGroups[.dg15].flatMap(DG15Parser.subjectPublicKeyInfo),
                    securityInfos: model.securityInfos,
                    transport: smTransport
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                aaResult = ActiveAuthenticationResult(
                    success: false,
                    details: "Active Authentication transport failed: \(error.localizedDescription)",
                    status: .commandFailed
                )
            }
            activeAuthenticationStage = buildActiveAuthenticationStage(
                requested: performActiveAuth,
                publicKey: publicKey,
                result: aaResult
            )
            // Re-assemble model with AA result
            model = PassportModel(
                cardAccess: model.cardAccess,
                cardAccessRaw: model.cardAccessRaw,
                ldsVersion: model.ldsVersion,
                unicodeVersion: model.unicodeVersion,
                availableDataGroups: model.availableDataGroups,
                mrz: model.mrz,
                faceImageData: model.faceImageData,
                signatureImageData: model.signatureImageData,
                additionalPersonalDetails: model.additionalPersonalDetails,
                additionalDocumentDetails: model.additionalDocumentDetails,
                securityInfos: model.securityInfos,
                securityInfoRaw: model.securityInfoRaw,
                activeAuthPublicKey: model.activeAuthPublicKey,
                activeAuthPublicKeyRaw: model.activeAuthPublicKeyRaw,
                sod: model.sod,
                sodRaw: model.sodRaw,
                passiveAuthResult: model.passiveAuthResult,
                activeAuthResult: aaResult,
                rawDataGroups: model.rawDataGroups,
                securityReport: PassportSecurityReport(
                    cardAccess: cardAccessStage,
                    pace: paceStage,
                    bac: bacStage,
                    chipAuthentication: chipAuthenticationStage,
                    passiveAuthentication: passiveAuthenticationStage,
                    activeAuthentication: activeAuthenticationStage
                ),
                dataGroupReadStatus: model.dataGroupReadStatus
            )
        } else {
            model = PassportModel(
                cardAccess: model.cardAccess,
                cardAccessRaw: model.cardAccessRaw,
                ldsVersion: model.ldsVersion,
                unicodeVersion: model.unicodeVersion,
                availableDataGroups: model.availableDataGroups,
                mrz: model.mrz,
                faceImageData: model.faceImageData,
                signatureImageData: model.signatureImageData,
                additionalPersonalDetails: model.additionalPersonalDetails,
                additionalDocumentDetails: model.additionalDocumentDetails,
                securityInfos: model.securityInfos,
                securityInfoRaw: model.securityInfoRaw,
                activeAuthPublicKey: model.activeAuthPublicKey,
                activeAuthPublicKeyRaw: model.activeAuthPublicKeyRaw,
                sod: model.sod,
                sodRaw: model.sodRaw,
                passiveAuthResult: model.passiveAuthResult,
                activeAuthResult: model.activeAuthResult,
                rawDataGroups: model.rawDataGroups,
                securityReport: PassportSecurityReport(
                    cardAccess: cardAccessStage,
                    pace: paceStage,
                    bac: bacStage,
                    chipAuthentication: chipAuthenticationStage,
                    passiveAuthentication: passiveAuthenticationStage,
                    activeAuthentication: activeAuthenticationStage
                ),
                dataGroupReadStatus: model.dataGroupReadStatus
            )
        }

        return model
    }

    // MARK: - Private

    /// Select and read a complete DataGroup file.
    private func readDataGroup(_ dgId: DataGroupId, transport: SecureMessagingTransport) async throws -> Data {
        // SELECT EF
        let selectAPDU = CommandAPDU.selectEF(id: dgId.fileID)
        let selectResponse = try await sendMappingUnavailable(selectAPDU, transport: transport, context: "SELECT \(dgId.name)")

        guard selectResponse.isSuccess else {
            throw NFCError.dataGroupNotAvailable(
                "SELECT \(dgId.name): SW=\(String(format: "%04X", selectResponse.statusWord))"
            )
        }

        // Read the full file contents
        return try await readBinaryAll(transport: transport, maxLength: Self.maxFileLength(for: dgId))
    }

    /// Status words meaning "this file is absent or protected", not a broken session:
    /// 6A82 file not found, 6982 security status not satisfied (EAC DG3/DG4),
    /// 6A88 referenced data not found, 6986 command not allowed (no current EF).
    static let fileUnavailableStatusWords: Set<UInt16> = [0x6A82, 0x6982, 0x6A88, 0x6986]

    /// Send `apdu`, turning a plain (unprotected) "file unavailable" status word into
    /// ``NFCError/dataGroupNotAvailable(_:)``. Chips commonly answer those errors without
    /// secure messaging.
    private func sendMappingUnavailable(
        _ apdu: CommandAPDU,
        transport: any NFCTagTransport,
        context: String
    ) async throws -> ResponseAPDU {
        do {
            return try await transport.sendAPDU(apdu)
        } catch let NFCError.unexpectedStatusWord(sw1, sw2)
            where Self.fileUnavailableStatusWords.contains(UInt16(sw1) << 8 | UInt16(sw2))
        {
            throw NFCError.dataGroupNotAvailable("\(context): plain SW=\(String(format: "%02X%02X", sw1, sw2))")
        }
    }

    /// Largest file this reader accepts for `dgId` (ICAO 9303-10 sizes, generous margins).
    /// Image data groups may be large; everything else is a few kilobytes at most, so a
    /// corrupt or hostile length field cannot make the reader allocate or read megabytes.
    static func maxFileLength(for dgId: DataGroupId) -> Int {
        switch dgId {
        case .dg2, .dg3, .dg4, .dg5, .dg6, .dg7:
            largeFileMaxLength
        default:
            smallFileMaxLength
        }
    }

    static let smallFileMaxLength = 64 * 1024
    static let largeFileMaxLength = 10 * 1024 * 1024

    /// Read the entire contents of the currently selected EF using READ BINARY.
    ///
    /// First reads the TLV header to determine the total length, then reads
    /// in chunks of `PassportConstants.maxReadLength` bytes.
    ///
    /// Handles multi-byte length fields (0x81, 0x82, 0x83) by reading additional
    /// header bytes if the initial 4-byte read doesn't contain the complete
    /// tag + length header.
    private func readBinaryAll(transport: any NFCTagTransport, maxLength: Int) async throws -> Data {
        // Read initial header bytes — 4 bytes covers tag (1-2) + short length (1)
        // but may not cover long-form lengths (0x82 = 3 bytes, 0x83 = 4 bytes)
        let headerAPDU = CommandAPDU.readBinaryChunk(offset: 0, length: 4)
        let headerResponse = try await sendMappingUnavailable(headerAPDU, transport: transport, context: "READ BINARY header")

        // 6282: end of file before Le bytes; a file shorter than 4 bytes still returns its data.
        guard headerResponse.isSuccess || headerResponse.statusWord == 0x6282 else {
            let statusWord = String(format: "%04X", headerResponse.statusWord)
            if Self.fileUnavailableStatusWords.contains(headerResponse.statusWord) {
                throw NFCError.dataGroupNotAvailable("READ BINARY header: SW=\(statusWord)")
            }
            throw NFCError.dataGroupParseFailed("READ BINARY header failed: SW=\(statusWord)")
        }

        var headerData = headerResponse.data
        guard !headerData.isEmpty else {
            throw NFCError.dataGroupParseFailed("READ BINARY returned empty data")
        }

        // Parse tag — may consume 1 or 2 bytes
        let (_, tagBytes) = try ASN1Parser.parseTag(headerData, at: 0)

        // Try to parse length — if we don't have enough bytes, read more
        var parsedLength: (content: Int, header: Int)?

        // Loop to ensure we have enough header data for the length field
        // Maximum header: 2 (tag) + 4 (0x83 length) = 6 bytes, so at most 2 extra reads
        for attempt in 0 ..< 3 {
            if tagBytes < headerData.count {
                do {
                    let (content, header) = try ASN1Parser.parseLength(headerData, at: tagBytes)
                    parsedLength = (content: content, header: header)
                    break
                } catch {
                    // Length field is incomplete — need more bytes
                }
            }

            // Read additional bytes to complete the header
            let currentLen = headerData.count
            let moreAPDU = CommandAPDU.readBinaryChunk(offset: currentLen, length: 8)
            let moreResponse = try await transport.sendAPDU(moreAPDU)
            guard moreResponse.isSuccess, !moreResponse.data.isEmpty else {
                throw NFCError.dataGroupParseFailed("Failed to read additional header bytes (attempt \(attempt + 1))")
            }
            headerData.append(moreResponse.data)
        }

        guard let parsedLength else {
            throw NFCError.dataGroupParseFailed("Could not parse TLV length after reading \(headerData.count) header bytes")
        }

        let headerSize = tagBytes + parsedLength.header
        let totalLength = headerSize + parsedLength.content

        // Reject lengths beyond this file's cap before reading or allocating anything.
        guard totalLength <= maxLength else {
            throw NFCError.dataGroupParseFailed(
                "TLV total length \(totalLength) exceeds the \(maxLength)-byte maximum for this file"
            )
        }

        // Now read the complete file. The result must contain exactly `totalLength` bytes:
        // a short or failed read is an error, never a silently truncated data group.
        var fileData = Data()
        fileData.reserveCapacity(min(totalLength, Self.smallFileMaxLength))
        var offset = 0
        let chunkSize = PassportConstants.maxReadLength

        while offset < totalLength {
            try Task.checkCancellation()
            let remaining = totalLength - offset
            let readLen = min(chunkSize, remaining)

            let chunk = try await readBinaryChunk(offset: offset, length: readLen, transport: transport)
            guard !chunk.isEmpty else {
                throw NFCError.dataGroupParseFailed(
                    "Short read: READ BINARY at offset \(offset) returned no data (expected \(totalLength) bytes)"
                )
            }
            guard chunk.count <= remaining else {
                throw NFCError.dataGroupParseFailed(
                    "READ BINARY at offset \(offset) returned \(chunk.count) bytes, only \(remaining) remain"
                )
            }

            fileData.append(chunk)
            offset += chunk.count
        }

        return fileData
    }

    /// Read one chunk of the current EF at `offset`.
    ///
    /// `CommandAPDU.readBinaryChunk` switches to READ BINARY `B1` (offset DO'54, response
    /// DO'53) above 0x7FFF so DG2/DG3 files larger than 32 KB never wrap (ISO/IEC 7816-4
    /// §11.2.3). A `B1` read may return a few bytes less than requested; the caller
    /// advances by the bytes actually returned.
    private func readBinaryChunk(
        offset: Int,
        length: Int,
        transport: any NFCTagTransport
    ) async throws -> Data {
        let apdu = CommandAPDU.readBinaryChunk(offset: offset, length: length)
        let response = try await transport.sendAPDU(apdu)

        // 6282: end of file reached before Le bytes — data is still returned.
        guard response.isSuccess || response.statusWord == 0x6282 else {
            throw NFCError.dataGroupParseFailed(
                "READ BINARY at offset \(offset) failed: SW=\(String(format: "%04X", response.statusWord))"
            )
        }
        return try response.binaryData(for: apdu)
    }

    /// Parse raw data group bytes and assemble a PassportModel.
    private func assemblePassportModel(
        rawDataGroups: [DataGroupId: Data],
        trustAnchorsDER: [Data],
        cardAccess: SecurityInfos?,
        cardAccessRaw: Data?,
        securityReport: PassportSecurityReport,
        dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]
    ) -> PassportModel {
        // COM
        var ldsVersion: String?
        var unicodeVersion: String?
        var availableDGs: [DataGroupId] = []
        if let comData = rawDataGroups[.com] {
            if let parsed = try? DataGroupParser.parseCOM(comData) {
                ldsVersion = parsed.ldsVersion
                unicodeVersion = parsed.unicodeVersion
                availableDGs = parsed.dataGroups
            }
        }

        // DG1 — MRZ
        var mrz: MRZData?
        if let dg1Data = rawDataGroups[.dg1] {
            mrz = try? DataGroupParser.parseDG1(dg1Data)
        }

        // DG2 — Face Image
        var faceImageData: Data?
        if let dg2Data = rawDataGroups[.dg2] {
            do {
                faceImageData = try DataGroupParser.parseDG2(dg2Data)
                if let faceImageData {
                    NFCLog.info("Parsed DG2 face image: \(faceImageData.count) bytes", source: "Passport")
                }
            } catch {
                NFCLog.error("DG2 parse failed: \(error.localizedDescription)", source: "Passport")
            }
        }

        // DG7 — Signature Image
        var signatureImageData: Data?
        if let dg7Data = rawDataGroups[.dg7] {
            do {
                signatureImageData = try DataGroupParser.parseDG7(dg7Data)
                if let signatureImageData {
                    NFCLog.info("Parsed DG7 signature image: \(signatureImageData.count) bytes", source: "Passport")
                } else {
                    NFCLog.info("DG7 present but did not contain an extractable signature image", source: "Passport")
                }
            } catch {
                NFCLog.error("DG7 parse failed: \(error.localizedDescription)", source: "Passport")
            }
        }

        // DG11 — Additional Personal Details
        var personalDetails: [String: String]?
        if let dg11Data = rawDataGroups[.dg11] {
            personalDetails = try? DataGroupParser.parseDG11(dg11Data)
        }

        // DG12 — Additional Document Details
        var documentDetails: [String: String]?
        if let dg12Data = rawDataGroups[.dg12] {
            documentDetails = try? DataGroupParser.parseDG12(dg12Data)
        }

        // DG14 — Security Info
        var securityInfos: SecurityInfos?
        if let dg14Data = rawDataGroups[.dg14] {
            securityInfos = try? DG14Parser.parse(dg14Data)
        }

        // DG15 — Active Auth Public Key
        var activeAuthPublicKey: ActiveAuthPublicKey?
        if let dg15Data = rawDataGroups[.dg15] {
            activeAuthPublicKey = try? DG15Parser.parse(dg15Data)
        }

        // SOD — Security Object Document
        var sodContent: SODContent?
        if let sodData = rawDataGroups[.sod] {
            sodContent = try? SODParser.parse(sodData)
        }

        // Passive Authentication — verify DG hashes against SOD
        var passiveAuthResult: PassiveAuthenticationResult?
        if let sod = sodContent {
            passiveAuthResult = SODParser.verifyPassiveAuthentication(
                sodContent: sod,
                rawDataGroups: rawDataGroups,
                trustAnchorsDER: trustAnchorsDER
            )
        }

        return PassportModel(
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            ldsVersion: ldsVersion,
            unicodeVersion: unicodeVersion,
            availableDataGroups: availableDGs,
            mrz: mrz,
            faceImageData: faceImageData,
            signatureImageData: signatureImageData,
            additionalPersonalDetails: personalDetails,
            additionalDocumentDetails: documentDetails,
            securityInfos: securityInfos,
            securityInfoRaw: rawDataGroups[.dg14],
            activeAuthPublicKey: activeAuthPublicKey,
            activeAuthPublicKeyRaw: rawDataGroups[.dg15],
            sod: sodContent,
            sodRaw: rawDataGroups[.sod],
            passiveAuthResult: passiveAuthResult,
            activeAuthResult: nil,
            rawDataGroups: rawDataGroups,
            securityReport: securityReport,
            dataGroupReadStatus: dataGroupReadStatus
        )
    }

    private func readCardAccess(transport: any NFCTagTransport) async throws -> Data {
        let selectMasterResponse = try await transport.sendAPDU(.selectMasterFile())
        guard selectMasterResponse.isSuccess else {
            throw NFCError.dataGroupNotAvailable(
                "SELECT MF failed: SW=\(String(format: "%04X", selectMasterResponse.statusWord))"
            )
        }

        let selectCardAccessResponse = try await transport.sendAPDU(.selectEF(id: CardAccessParser.fileID))
        guard selectCardAccessResponse.isSuccess else {
            throw NFCError.dataGroupNotAvailable(
                "SELECT EF.CardAccess failed: SW=\(String(format: "%04X", selectCardAccessResponse.statusWord))"
            )
        }

        return try await readBinaryAll(transport: transport, maxLength: Self.smallFileMaxLength)
    }

    private func buildChipAuthenticationStage(_ securityInfos: SecurityInfos?) -> PassportSecurityStageResult {
        guard let securityInfos else {
            return PassportSecurityStageResult(
                status: .notAdvertised,
                detail: "DG14 was not available, so Chip Authentication support could not be determined."
            )
        }

        guard securityInfos.supportsChipAuthentication else {
            return PassportSecurityStageResult(
                status: .notAdvertised,
                detail: "DG14 does not advertise Chip Authentication."
            )
        }

        return PassportSecurityStageResult(
            status: .notSupported,
            detail: "Chip Authentication is advertised, but session key transition is not implemented yet."
        )
    }

    private func buildPassiveAuthenticationStage(
        passiveAuthResult: PassiveAuthenticationResult?,
        sodPresent: Bool
    ) -> PassportSecurityStageResult {
        guard let passiveAuthResult else {
            return PassportSecurityStageResult(
                status: sodPresent ? .failed : .notSupported,
                detail: sodPresent
                    ? "SOD was read, but passive authentication did not complete."
                    : "SOD was not available, so passive authentication could not run."
            )
        }

        if passiveAuthResult.dataGroupHashResults.isEmpty, passiveAuthResult.status != .unsupportedHashAlgorithm {
            return PassportSecurityStageResult(
                status: .skipped,
                detail: "SOD was read, but no data group it covers was read, so no hashes were compared."
            )
        }

        return PassportSecurityStageResult(
            status: passiveAuthResult.allHashesValid ? .succeeded : .failed,
            detail: passiveAuthResult.allHashesValid
                ? "Passive Authentication status: \(passiveAuthResult.status.rawValue)."
                : "Passive Authentication status: \(passiveAuthResult.status.rawValue) with \(passiveAuthResult.failedDataGroups.count) failed data groups."
        )
    }

    private func buildActiveAuthenticationStage(
        requested: Bool,
        publicKey: ActiveAuthPublicKey?,
        result: ActiveAuthenticationResult?
    ) -> PassportSecurityStageResult {
        guard requested else {
            return PassportSecurityStageResult(
                status: .skipped,
                detail: "Active Authentication was disabled by configuration."
            )
        }

        guard publicKey != nil else {
            return PassportSecurityStageResult(
                status: .notAdvertised,
                detail: "DG15 did not provide an Active Authentication public key."
            )
        }

        guard let result else {
            return PassportSecurityStageResult(
                status: .pending,
                detail: "Active Authentication was requested but has not completed yet."
            )
        }

        let status: PassportSecurityStageStatus = switch result.status {
        case .verified:
            .succeeded
        case .notImplemented, .unsupportedKeyType:
            .notSupported
        case .failed, .commandFailed:
            .failed
        }

        return PassportSecurityStageResult(status: status, detail: result.details)
    }

    // MARK: - Active Authentication

    /// Perform Active Authentication using INTERNAL AUTHENTICATE.
    ///
    /// Protocol:
    /// 1. Generate 8-byte random challenge
    /// 2. Send INTERNAL AUTHENTICATE with the challenge
    /// 3. Verify the signature using the DG15 public key
    ///
    /// - Important: Full AA verification requires OpenSSL or equivalent:
    ///   - RSA AA uses ISO 9796-2 message recovery (not standard PKCS#1 verify)
    ///   - ECDSA AA uses plain (r||s) signatures (not DER-encoded)
    ///   Without these capabilities, AA returns `.notImplemented` status.
    ///
    /// References:
    /// - ICAO Doc 9303 Part 11, Section 6.1 (Active Authentication protocol)
    /// - ICAO Doc 9303 Part 11, Section 6.2 (AA public key in DG15, signature verification)
    /// - ISO/IEC 9796-2 (RSA message recovery scheme used by RSA-based AA)
    /// - BSI TR-03111, Section 4.2.1 (ECDSA plain signature format: r || s)
    private func performActiveAuthentication(
        publicKey: ActiveAuthPublicKey,
        subjectPublicKeyInfo: Data?,
        securityInfos: SecurityInfos?,
        transport: SecureMessagingTransport
    ) async throws -> ActiveAuthenticationResult {
        // Generate 8-byte random challenge (ICAO 9303-11 §6.1). A predictable challenge
        // would make the chip's signature replayable, so a generator failure aborts AA.
        let challenge = try CryptoUtils.secureRandomBytes(count: 8)

        // Send INTERNAL AUTHENTICATE
        let authAPDU = CommandAPDU.internalAuthenticate(data: challenge)
        let response = try await transport.sendAPDU(authAPDU)

        guard response.isSuccess else {
            return ActiveAuthenticationResult(
                success: false,
                details: "INTERNAL AUTHENTICATE failed: SW=\(String(format: "%04X", response.statusWord))",
                status: .commandFailed
            )
        }

        let signature = response.data
        guard !signature.isEmpty else {
            return ActiveAuthenticationResult(
                success: false,
                details: "Empty signature response",
                status: .commandFailed
            )
        }

        return ActiveAuthenticationVerifier.verify(
            challenge: challenge,
            signature: signature,
            publicKey: publicKey,
            subjectPublicKeyInfo: subjectPublicKeyInfo,
            securityInfos: securityInfos
        )
    }
}

// MARK: - Data group read loop

extension PassportReader {
    /// Order in which requested data groups are read: COM first (its list decides what
    /// is selected), then DG1, then the rest as requested, with the EAC-protected DG3/DG4
    /// last. Duplicates are dropped.
    static func readOrder(for requested: [DataGroupId]) -> [DataGroupId] {
        var seen = Set<DataGroupId>()
        let unique = requested.filter { seen.insert($0).inserted }

        func rank(_ dgId: DataGroupId) -> Int {
            switch dgId {
            case .com: 0
            case .dg1: 1
            case .dg3, .dg4: 3
            default: 2
            }
        }

        return unique.enumerated()
            .sorted { lhs, rhs in
                (rank(lhs.element), lhs.offset) < (rank(rhs.element), rhs.offset)
            }
            .map(\.element)
    }
}

/// Bookkeeping for the data group loop of `PassportReader.readPassport`.
///
/// A data group the chip reports as absent or protected is marked unavailable and the
/// loop goes on. When secure messaging ends (MAC failure, SM status word, interrupted
/// exchange), the remaining data groups are marked not read and everything read so far
/// is kept. Session loss and cancellation propagate.
struct DataGroupReadSession {
    let transport: SecureMessagingTransport
    private(set) var rawDataGroups: [DataGroupId: Data] = [:]
    private(set) var status: [DataGroupId: PassportDataGroupReadResult] = [:]
    /// Data groups listed in EF.COM, once COM was read and parsed.
    private(set) var listedInCOM: Set<DataGroupId>?
    /// Why secure messaging ended, once it has.
    private(set) var secureMessagingEnded: String?
    /// First error that cost a data group (anything but "not available").
    private(set) var firstFailure: (any Error)?

    init(transport: SecureMessagingTransport) {
        self.transport = transport
    }

    /// Whether EF.COM lists `dgId`; `nil` when COM was not read or could not be parsed.
    func isListedInCOM(_ dgId: DataGroupId) -> Bool? {
        listedInCOM.map { $0.contains(dgId) }
    }

    /// Whether `dgId` should be selected. Records why when it should not.
    mutating func shouldSelect(_ dgId: DataGroupId) -> Bool {
        if let secureMessagingEnded {
            status[dgId] = PassportDataGroupReadResult(
                state: .notRead,
                detail: "Secure messaging ended before this data group: \(secureMessagingEnded)"
            )
            return false
        }
        if dgId != .com, dgId != .sod, isListedInCOM(dgId) == false {
            status[dgId] = PassportDataGroupReadResult(
                state: .notPresent,
                detail: "EF.COM does not list \(dgId.name)."
            )
            return false
        }
        return true
    }

    /// Run `body` to read `dgId` and record the outcome.
    mutating func read(_ dgId: DataGroupId, _ body: () async throws -> Data) async throws {
        do {
            let data = try await body()
            rawDataGroups[dgId] = data
            status[dgId] = PassportDataGroupReadResult(state: .read, detail: "\(data.count) bytes")
            NFCLog.info("Read \(dgId.name): \(data.count) bytes", source: "Passport")
            if dgId == .com, let parsed = try? COMParser.parse(data) {
                listedInCOM = Set(parsed.dataGroups)
            }
        } catch let NFCError.dataGroupNotAvailable(reason) {
            status[dgId] = PassportDataGroupReadResult(state: .unavailable, detail: reason)
        } catch {
            if isSessionTerminating(error) { throw error }
            if firstFailure == nil { firstFailure = error }
            let reason = error.localizedDescription
            NFCLog.error("Reading \(dgId.name) failed: \(reason)", source: "Passport")
            if await transport.isSessionEnded {
                secureMessagingEnded = reason
                status[dgId] = PassportDataGroupReadResult(
                    state: .notRead,
                    detail: "Secure messaging ended while reading this data group: \(reason)"
                )
            } else {
                status[dgId] = PassportDataGroupReadResult(state: .failed, detail: reason)
            }
        }
    }
}
