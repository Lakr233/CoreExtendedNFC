import Foundation

/// Unauthenticated DESFire dump: list applications, list files, read every
/// file that is readable with free access.
///
/// - Each file is keyed by `AID (3 bytes) ‖ fileID (1 byte)` so files with the
///   same ID in different applications stay distinct.
/// - Applications or files that refuse access (91 AE / 91 9D / 91 40) are
///   skipped and counted instead of aborting the whole dump.
/// - Record files with zero records (91 BE on READ_RECORDS) are dumped as
///   empty files.
/// - Transaction MAC files (type 0x05) and files whose settings cannot be
///   parsed are counted but not read.
/// - Task cancellation is honoured between applications and files.
struct DESFireDump: Sendable {
    let commands: DESFireCommands

    func dumpAll(cardInfo: CardInfo) async throws -> MemoryDump {
        var files: [MemoryDump.FileData] = []
        var lockedApplications = 0
        var lockedFiles = 0
        var skippedFiles = 0

        let aids: [Data]
        var applicationListLocked = false
        do {
            aids = try await commands.getApplicationIDs()
        } catch let error as NFCError where Self.isAccessDenied(error) {
            aids = []
            applicationListLocked = true
        }

        for aid in aids {
            try Task.checkCancellation()

            let fileIDs: [UInt8]
            do {
                try await commands.selectApplication(aid)
                fileIDs = try await commands.getFileIDs()
            } catch let error as NFCError where Self.isAccessDenied(error) {
                lockedApplications += 1
                continue
            }

            for fileID in fileIDs {
                try Task.checkCancellation()

                let settings: DESFireFileSettings
                do {
                    settings = try await commands.getFileSettings(fileID)
                } catch let error as NFCError where Self.isAccessDenied(error) {
                    lockedFiles += 1
                    continue
                } catch NFCError.invalidResponse {
                    // Unknown or malformed file type: keep dumping the rest.
                    skippedFiles += 1
                    continue
                }

                do {
                    guard let data = try await readContents(fileID: fileID, settings: settings) else {
                        skippedFiles += 1
                        continue
                    }
                    files.append(
                        MemoryDump.FileData(
                            identifier: aid + Data([fileID]),
                            data: data,
                            name: "App \(aid.hexString) / File \(String(format: "%02X", fileID))"
                        )
                    )
                } catch let error as NFCError where Self.isAccessDenied(error) {
                    lockedFiles += 1
                }
            }
        }

        var facts: [MemoryDump.Fact] = [
            .init(key: "Applications", value: applicationListLocked ? "Locked" : "\(aids.count)"),
            .init(key: "Accessible Files", value: "\(files.count)"),
        ]
        if lockedApplications > 0 {
            facts.append(.init(key: "Locked Applications", value: "\(lockedApplications)"))
        }
        if lockedFiles > 0 {
            facts.append(.init(key: "Locked Files", value: "\(lockedFiles)"))
        }
        if skippedFiles > 0 {
            facts.append(.init(key: "Skipped Files", value: "\(skippedFiles)"))
        }

        return MemoryDump(
            cardInfo: cardInfo,
            files: files,
            facts: facts,
            capabilities: files.isEmpty ? [.authenticationRequired, .partiallyReadable] : [.partiallyReadable]
        )
    }

    /// Read a file's contents, or `nil` for file types that are not dumped.
    private func readContents(fileID: UInt8, settings: DESFireFileSettings) async throws -> Data? {
        switch settings.fileType {
        case .standardData, .backupData:
            return try await commands.readData(fileID: fileID)
        case .linearRecord, .cyclicRecord:
            // A record file with no records yet is a valid, empty file. The
            // PICC answers READ_RECORDS on it with 91 BE (BOUNDARY_ERROR: no
            // record at the requested offset), so don't ask, and don't abort
            // if the settings were stale.
            if settings.currentRecords == 0 {
                return Data()
            }
            do {
                return try await commands.readRecords(fileID: fileID)
            } catch NFCError.desfireError(.boundaryError) {
                return Data()
            }
        case .valueFile:
            let value = UInt32(bitPattern: try await commands.getValue(fileID: fileID))
            return Data([
                UInt8(truncatingIfNeeded: value),
                UInt8(truncatingIfNeeded: value >> 8),
                UInt8(truncatingIfNeeded: value >> 16),
                UInt8(truncatingIfNeeded: value >> 24),
            ])
        case .transactionMAC:
            return nil
        }
    }

    /// DESFire statuses that mean "not readable without authentication".
    static func isAccessDenied(_ error: NFCError) -> Bool {
        switch error {
        case .desfireError(.authenticationError),
             .desfireError(.permissionDenied),
             .desfireError(.noSuchKey):
            true
        default:
            false
        }
    }
}
