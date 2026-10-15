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

        // Step 3: Read each requested DataGroup
        var rawDataGroups: [DataGroupId: Data] = [:]

        for (index, dgId) in dataGroups.enumerated() {
            try Task.checkCancellation()
            onProgress?("Reading \(dgId.name) (\(index + 1)/\(dataGroups.count))...")

            do {
                let dgData = try await readDataGroup(dgId, transport: smTransport)
                rawDataGroups[dgId] = dgData
                NFCLog.info("Read \(dgId.name): \(dgData.count) bytes", source: "Passport")
            } catch NFCError.dataGroupNotAvailable {
                // Only a data group the chip reports as absent/inaccessible is skipped.
                // Transport loss, secure messaging failures and short reads propagate:
                // after an SM error the chip has torn down the session (ICAO 9303-11 §9.8).
                continue
            }
        }

        // Step 4: If DG15 is available and AA was requested but DG15 wasn't in the list, read it
        if performActiveAuth, rawDataGroups[.dg15] == nil, !dataGroups.contains(.dg15) {
            onProgress?("Reading DG15 (Active Auth Key)...")
            do {
                let dg15Data = try await readDataGroup(.dg15, transport: smTransport)
                rawDataGroups[.dg15] = dg15Data
            } catch NFCError.dataGroupNotAvailable {
                // DG15 not available — AA not supported by this document
            }
        }

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
            )
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
        if performActiveAuth, let publicKey = model.activeAuthPublicKey {
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
                )
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
                )
            )
        }

        return model
    }

    // MARK: - Private

    /// Select and read a complete DataGroup file.
    private func readDataGroup(_ dgId: DataGroupId, transport: SecureMessagingTransport) async throws -> Data {
        // SELECT EF
        let selectAPDU = CommandAPDU.selectEF(id: dgId.fileID)
        let selectResponse: ResponseAPDU
        do {
            selectResponse = try await transport.sendAPDU(selectAPDU)
        } catch NFCError.unexpectedStatusWord(0x6A, 0x82) {
            // Some chips answer "file not found" with a plain, unprotected status word.
            throw NFCError.dataGroupNotAvailable(dgId.name)
        }

        guard selectResponse.isSuccess else {
            throw NFCError.dataGroupNotAvailable(dgId.name)
        }

        // Read the full file contents
        return try await readBinaryAll(transport: transport)
    }

    /// Read the entire contents of the currently selected EF using READ BINARY.
    ///
    /// First reads the TLV header to determine the total length, then reads
    /// in chunks of `PassportConstants.maxReadLength` bytes.
    ///
    /// Handles multi-byte length fields (0x81, 0x82, 0x83) by reading additional
    /// header bytes if the initial 4-byte read doesn't contain the complete
    /// tag + length header.
    private func readBinaryAll(transport: any NFCTagTransport) async throws -> Data {
        // Read initial header bytes — 4 bytes covers tag (1-2) + short length (1)
        // but may not cover long-form lengths (0x82 = 3 bytes, 0x83 = 4 bytes)
        let headerAPDU = CommandAPDU.readBinaryChunk(offset: 0, length: 4)
        let headerResponse = try await transport.sendAPDU(headerAPDU)

        guard headerResponse.isSuccess else {
            let statusWord = String(format: "%04X", headerResponse.statusWord)
            // 6982: access conditions not satisfied (e.g. EAC-protected DG3/DG4); 6A82: file not found.
            if headerResponse.statusWord == 0x6982 || headerResponse.statusWord == 0x6A82 {
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

        // Sanity check: reject absurdly large lengths (> 10 MB) to prevent memory issues
        guard totalLength <= 10 * 1024 * 1024 else {
            throw NFCError.dataGroupParseFailed("TLV total length \(totalLength) exceeds maximum allowed (10 MB)")
        }

        // Now read the complete file. The result must contain exactly `totalLength` bytes:
        // a short or failed read is an error, never a silently truncated data group.
        var fileData = Data()
        fileData.reserveCapacity(totalLength)
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
        securityReport: PassportSecurityReport
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
            securityReport: securityReport
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

        return try await readBinaryAll(transport: transport)
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
