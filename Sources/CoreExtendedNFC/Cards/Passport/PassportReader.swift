import Foundation

/// Orchestrates the full eMRTD reading workflow:
/// SELECT application → BAC authentication → read DataGroups → parse → verify.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class PassportReader: @unchecked Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    /// Read passport data groups after performing BAC authentication.
    ///
    /// - Parameters:
    ///   - mrzKey: The MRZ key string for BAC authentication.
    ///   - dataGroups: Which data groups to read (default: EF.COM, DG1, DG2, EF.SOD).
    ///   - performActiveAuth: Whether to attempt Active Authentication if DG15 is available.
    ///   - trustAnchorsDER: DER-encoded CSCA certificates. Without them Passive
    ///     Authentication can at best report `.fallback` (Document Signer certificate
    ///     not validated to a trusted CSCA).
    ///   - onProgress: Optional callback for localized progress messages (suitable for
    ///     the system NFC sheet).
    ///
    /// When `dataGroups` contains `.com` but not `.sod` and EF.COM omits a requested data
    /// group, the SOD is read as the authoritative index before that data group is
    /// skipped; the SOD is then part of the returned model and Passive Authentication
    /// runs on it.
    ///
    /// The returned `activeAuthResult` has status `.verified` only when the DG15 key is
    /// authenticated by fully verified Passive Authentication; a valid signature over an
    /// unauthenticated key is `.verifiedUnauthenticatedKey`.
    /// - Returns: A `PassportModel` with all parsed data.
    /// - Throws: The first read error when nothing could be read, or when DG1 was
    ///   requested but could not be read (DG1 is mandatory, ICAO 9303-10 §4.7).
    open func readPassport(
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

        onProgress?(String(localized: "Reading passport…", bundle: .module))
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
        onProgress?(String(localized: "Connecting to passport…", bundle: .module))
        NFCLog.debug("SELECT eMRTD application", source: "Passport")
        let selectAPDU = CommandAPDU.selectPassportApplication()
        let selectResponse = try await transport.sendAPDU(selectAPDU)

        guard selectResponse.isSuccess else {
            throw NFCError.bacFailed("SELECT eMRTD failed: SW=\(String(format: "%04X", selectResponse.statusWord))")
        }

        // Step 2: Prefer PACE when EF.CardAccess advertises parameters this library
        // supports, otherwise fall back to BAC. ICAO 9303-11 §4.2 lets the inspection
        // system pick any advertised parameter set, so an unsupported first entry does
        // not rule PACE out.
        var smTransport: SecureMessagingTransport?
        if let cardAccess, cardAccess.supportsPACE, PACEHandler.selectPACEInfo(from: cardAccess) == nil {
            let reasons = cardAccess.paceInfos.compactMap(PACEHandler.unsupportedReason(for:))
            paceStage = PassportSecurityStageResult(
                status: .fallback,
                detail: "None of the PACE parameters in EF.CardAccess is supported "
                    + "(\(reasons.joined(separator: " "))). Falling back to BAC."
            )
        }
        if let paceInfo = cardAccess.flatMap(PACEHandler.selectPACEInfo(from:)) {
            onProgress?(String(localized: "Authenticating…", bundle: .module))
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
            onProgress?(String(localized: "Authenticating…", bundle: .module))
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
        // EF.COM and the SOD are read first; a data group is skipped only when the SOD
        // does not list it and COM does not either (ICAO 9303-10 §4.6.1: the SOD hash
        // list is the authoritative index on LDS 1.8 chips, and COM may be incomplete).
        // Selecting an absent file draws a
        // plain 6A82, and ICAO 9303-11 §9.8 lets the chip end secure messaging on any
        // unprotected reply. DG1 follows, then the other non-EAC data groups, then
        // DG15 and Active Authentication; EAC-protected DG3/DG4 (likely a plain 6982
        // under BAC/PACE) go last, so an ICAO-strict chip ending the session there
        // cannot cost DG1/DG2/SOD or Active Authentication.
        var session = DataGroupReadSession(transport: smTransport)
        let readOrder = Self.readOrder(for: dataGroups)
        let eacPass = readOrder.filter(Self.isEACProtected)
        let mainPass = readOrder.filter { !Self.isEACProtected($0) }
        var step = 0

        // EF.COM alone never rules a data group out (it may be incomplete). When COM
        // omits one and the SOD was not requested, the SOD is read once as the
        // authoritative index; it is then kept in the model like any other file.
        func readSODIndexIfNeeded(before dgId: DataGroupId) async throws {
            guard session.needsSODIndex(before: dgId) else { return }
            onProgress?(String(localized: "Reading security data…", bundle: .module))
            try await session.read(.sod) { try await readDataGroup(.sod, transport: smTransport) }
        }

        for dgId in mainPass {
            try Task.checkCancellation()
            step += 1
            try await readSODIndexIfNeeded(before: dgId)
            guard session.shouldSelect(dgId) else { continue }
            onProgress?(String(localized: "Reading \(dgId.name) (\(step)/\(readOrder.count))…", bundle: .module))
            try await session.read(dgId) { try await readDataGroup(dgId, transport: smTransport) }
        }

        // Step 4: If AA was requested but DG15 wasn't in the list, read it when present.
        if performActiveAuth, !readOrder.contains(.dg15) {
            try await readSODIndexIfNeeded(before: .dg15)
        }
        if performActiveAuth, !readOrder.contains(.dg15), session.isListed(.dg15) ?? true,
           session.secureMessagingEnded == nil
        {
            try Task.checkCancellation()
            onProgress?(String(localized: "Reading chip key…", bundle: .module))
            try await session.read(.dg15) { try await readDataGroup(.dg15, transport: smTransport) }
        }

        // Step 5: Active Authentication, before any EAC data group can end the session.
        //
        // Once DG15 is present, anything short of a valid signature is a failed stage,
        // never a skipped one: a clone without the AA private key can refuse INTERNAL
        // AUTHENTICATE (or drop secure messaging) at will.
        var activeAuthResult: ActiveAuthenticationResult?
        var activeAuthFailure: String?
        let activeAuthPublicKey = session.rawDataGroups[.dg15].flatMap { try? DG15Parser.parse($0) }
        if performActiveAuth, let publicKey = activeAuthPublicKey {
            if let reason = session.secureMessagingEnded {
                activeAuthFailure = "Active Authentication could not run although DG15 is present: secure messaging "
                    + "ended before INTERNAL AUTHENTICATE (\(reason)), so the chip's authenticity is unproven."
            } else {
                try Task.checkCancellation()
                onProgress?(String(localized: "Verifying chip authenticity…", bundle: .module))
                do {
                    activeAuthResult = try await performActiveAuthentication(
                        publicKey: publicKey,
                        subjectPublicKeyInfo: session.rawDataGroups[.dg15].flatMap(DG15Parser.subjectPublicKeyInfo),
                        securityInfos: session.rawDataGroups[.dg14].flatMap { try? DG14Parser.parse($0) },
                        transport: smTransport
                    )
                } catch {
                    if isSessionTerminating(error) { throw error }
                    if case let NFCError.unexpectedStatusWord(sw1, sw2) = error {
                        // A plain status word to INTERNAL AUTHENTICATE is a refusal: a genuine
                        // chip with DG15 signs the challenge.
                        activeAuthResult = ActiveAuthenticationResult(
                            success: false,
                            details: "The chip refused INTERNAL AUTHENTICATE although DG15 is present "
                                + "(unprotected SW=\(String(format: "%02X%02X", sw1, sw2)))",
                            status: .commandFailed
                        )
                    } else if let reason = await smTransport.sessionEndedReason {
                        activeAuthResult = ActiveAuthenticationResult(
                            success: false,
                            details: "The chip refused INTERNAL AUTHENTICATE although DG15 is present: "
                                + "secure messaging ended (\(reason))",
                            status: .commandFailed
                        )
                    } else {
                        activeAuthResult = ActiveAuthenticationResult(
                            success: false,
                            details: "Active Authentication transport failed: \(error.localizedDescription)",
                            status: .commandFailed
                        )
                    }
                }
                if let reason = await smTransport.sessionEndedReason {
                    session.markSecureMessagingEnded(reason)
                }
            }
        }

        // Step 6: EAC-protected data groups last.
        for dgId in eacPass {
            try Task.checkCancellation()
            step += 1
            try await readSODIndexIfNeeded(before: dgId)
            guard session.shouldSelect(dgId) else { continue }
            onProgress?(String(localized: "Reading \(dgId.name) (\(step)/\(readOrder.count))…", bundle: .module))
            try await session.read(dgId) { try await readDataGroup(dgId, transport: smTransport) }
        }

        // A read that could not deliver anything, or not the mandatory DG1 when it was
        // requested, is a failed read, not a partial one.
        if let failure = session.firstFailure, session.rawDataGroups.isEmpty {
            throw failure
        }
        if readOrder.contains(.dg1), session.rawDataGroups[.dg1] == nil {
            throw session.firstFailure ?? NFCError.dataGroupNotAvailable(
                "DG1 (MRZ) was requested but not read: \(session.status[.dg1]?.detail ?? "not selected")"
            )
        }
        let rawDataGroups = session.rawDataGroups

        // Step 7: Parse and assemble
        onProgress?(String(localized: "Processing…", bundle: .module))
        let parsed = assemblePassportModel(
            rawDataGroups: rawDataGroups,
            trustAnchorsDER: trustAnchorsDER,
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            securityReport: PassportSecurityReport(),
            dataGroupReadStatus: session.status
        )

        let activeAuthenticationStage: PassportSecurityStageResult = if performActiveAuth, let activeAuthFailure {
            PassportSecurityStageResult(status: .failed, detail: activeAuthFailure)
        } else {
            Self.activeAuthenticationStage(
                requested: performActiveAuth,
                publicKeyPresent: parsed.activeAuthPublicKey != nil,
                dg15Evidence: Self.dg15Evidence(rawDataGroups: rawDataGroups, sod: parsed.sod, com: parsed.availableDataGroups),
                result: activeAuthResult,
                passiveAuthResult: parsed.passiveAuthResult
            )
        }
        let paceCompleted = paceStage.status == .succeeded
        let checkedPACEStage = Self.paceStage(
            paceStage,
            paceCompleted: paceCompleted,
            dg14SecurityInfos: rawDataGroups[.dg14] != nil ? parsed.securityInfos : nil,
            passiveAuthResult: parsed.passiveAuthResult
        )

        return parsed.replacing(
            activeAuthResult: activeAuthResult?.classified(by: parsed.passiveAuthResult),
            securityReport: PassportSecurityReport(
                cardAccess: cardAccessStage,
                pace: checkedPACEStage,
                bac: bacStage,
                chipAuthentication: buildChipAuthenticationStage(parsed.securityInfos),
                passiveAuthentication: .passiveAuthentication(
                    parsed.passiveAuthResult,
                    sodPresent: rawDataGroups[.sod] != nil
                ),
                activeAuthentication: activeAuthenticationStage
            )
        )
    }

    // MARK: - Steps

    /// Select and read a complete DataGroup file.
    open func readDataGroup(_ dgId: DataGroupId, transport: SecureMessagingTransport) async throws -> Data {
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
    public static let fileUnavailableStatusWords: Set<UInt16> = [0x6A82, 0x6982, 0x6A88, 0x6986]

    /// Send `apdu`, turning a plain (unprotected) "file unavailable" status word into
    /// ``NFCError/dataGroupNotAvailable(_:)``. Chips commonly answer those errors without
    /// Secure Messaging.
    open func sendMappingUnavailable(
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
    open class func maxFileLength(for dgId: DataGroupId) -> Int {
        switch dgId {
        case .dg2, .dg3, .dg4, .dg5, .dg6, .dg7:
            largeFileMaxLength
        default:
            smallFileMaxLength
        }
    }

    public static let smallFileMaxLength = 64 * 1024
    public static let largeFileMaxLength = 10 * 1024 * 1024

    /// Read the entire contents of the currently selected EF using READ BINARY.
    ///
    /// First reads the TLV header to determine the total length, then reads
    /// in chunks of `PassportConstants.maxReadLength` bytes.
    ///
    /// Handles multi-byte length fields (0x81, 0x82, 0x83) by reading additional
    /// header bytes if the initial 4-byte read doesn't contain the complete
    /// tag + length header.
    open func readBinaryAll(transport: any NFCTagTransport, maxLength: Int) async throws -> Data {
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
    open func readBinaryChunk(
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
    ///
    /// Uses the same parsing as ``PassportModel/init(rawDataGroups:cardAccessRaw:performPassiveAuthentication:trustAnchorsDER:dataGroupReadStatus:)``,
    /// keeping the given `cardAccess` and `securityReport`; `activeAuthResult` is `nil`.
    open func assemblePassportModel(
        rawDataGroups: [DataGroupId: Data],
        trustAnchorsDER: [Data],
        cardAccess: SecurityInfos?,
        cardAccessRaw: Data?,
        securityReport: PassportSecurityReport,
        dataGroupReadStatus: [DataGroupId: PassportDataGroupReadResult]
    ) -> PassportModel {
        PassportModel(
            parsing: rawDataGroups,
            cardAccess: cardAccess,
            cardAccessRaw: cardAccessRaw,
            trustAnchorsDER: trustAnchorsDER,
            securityReport: securityReport,
            dataGroupReadStatus: dataGroupReadStatus
        )
    }

    open func readCardAccess(transport: any NFCTagTransport) async throws -> Data {
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

    open func buildChipAuthenticationStage(_ securityInfos: SecurityInfos?) -> PassportSecurityStageResult {
        .chipAuthentication(advertisedBy: securityInfos)
    }

    /// Security stage for Active Authentication.
    ///
    /// Covers AA being disabled, DG15 missing and AA not completing, then defers to
    /// ``PassportSecurityStageResult/activeAuthentication(_:passiveAuthentication:)``:
    /// `.succeeded` only when Passive Authentication is fully verified (Document Signer
    /// certificate validated to a trusted CSCA) and the DG15 hash matched.
    ///
    /// `.skipped` means AA was disabled, `.notAdvertised` that the chip has no DG15
    /// (`dg15Evidence` is `nil`). Without a usable DG15 key while `dg15Evidence` says
    /// DG15 exists, the stage is `.failed`: a clone can hide DG15 to avoid AA.
    open class func activeAuthenticationStage(
        requested: Bool,
        publicKeyPresent: Bool,
        dg15Evidence: String? = nil,
        result: ActiveAuthenticationResult?,
        passiveAuthResult: PassiveAuthenticationResult?
    ) -> PassportSecurityStageResult {
        guard requested else {
            return PassportSecurityStageResult(
                status: .skipped,
                detail: "Active Authentication was disabled by configuration."
            )
        }

        guard publicKeyPresent else {
            if let dg15Evidence {
                return PassportSecurityStageResult(
                    status: .failed,
                    detail: "Active Authentication could not run: \(dg15Evidence), but no usable Active "
                        + "Authentication public key was read from it, so the chip's authenticity is unproven."
                )
            }
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

        return .activeAuthentication(result, passiveAuthentication: passiveAuthResult)
    }

    /// Why DG15 is known to exist on the chip, or `nil` when nothing says it does: DG15
    /// was read, the SOD has a hash for it, or EF.COM lists it.
    public static func dg15Evidence(
        rawDataGroups: [DataGroupId: Data],
        sod: SODContent?,
        com: [DataGroupId]
    ) -> String? {
        if rawDataGroups[.dg15] != nil { return "DG15 was read" }
        if sod?.dataGroupHashes[.dg15] != nil { return "EF.SOD lists DG15" }
        if com.contains(.dg15) { return "EF.COM lists DG15" }
        return nil
    }

    // MARK: - PACE downgrade

    /// PACE stage after the DG14 cross-check.
    ///
    /// ICAO 9303-11 §9.2.11: "The full set of SecurityInfos (including SecurityInfos
    /// contained in EF.CardAccess not specified in Doc 9303) SHALL additionally be
    /// stored in EF.DG14 of the eMRTD Application" and "While the authenticity of
    /// SecurityInfos stored in EF.DG14 and EF.CardSecurity is protected by Passive
    /// Authentication, the file EF.CardAccess is unprotected." So when DG14 lists a
    /// PACEInfo this reader supports but PACE did not complete (EF.CardAccess missing,
    /// stripped or altered, or PACE failed and BAC was used), the session may have been
    /// downgraded and the stage is `.failed`. BAC still ran and the data is returned;
    /// the stage records the downgrade. DG14 PACEInfos the reader does not support
    /// leave `negotiated` unchanged.
    open class func paceStage(
        _ negotiated: PassportSecurityStageResult,
        paceCompleted: Bool,
        dg14SecurityInfos: SecurityInfos?,
        passiveAuthResult: PassiveAuthenticationResult?
    ) -> PassportSecurityStageResult {
        guard !paceCompleted, let dg14SecurityInfos else { return negotiated }
        let supported = dg14SecurityInfos.paceInfos.filter(PACEHandler.isSupported)
        guard !supported.isEmpty else { return negotiated }

        let protocols = supported.map(\.protocolOID).joined(separator: ", ")
        let dg14Authenticity = passiveAuthResult?.dataGroupHashResults[.dg14] == true
            ? "DG14 matches its hash in EF.SOD"
            : "DG14 is not verified by Passive Authentication"
        return PassportSecurityStageResult(
            status: .failed,
            detail: "Possible PACE-to-BAC downgrade: DG14 advertises PACE (\(protocols)) that this reader "
                + "supports, but PACE was not completed (\(negotiated.detail)) (\(dg14Authenticity))."
        )
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
    open func performActiveAuthentication(
        publicKey: ActiveAuthenticationPublicKey,
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
                details: "The chip refused INTERNAL AUTHENTICATE although DG15 is present "
                    + "(SW=\(String(format: "%04X", response.statusWord)))",
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
