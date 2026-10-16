import CoreExtendedNFC
import Foundation

extension Notification.Name {
    static let appLogsDidChange = Notification.Name("CENFC.AppLogsDidChange")
}

nonisolated enum AppLogLevel: String, CaseIterable, Codable {
    case debug = "DEBUG"
    case info = "INFO"
    case warning = "WARN"
    case error = "ERROR"
}

nonisolated struct AppLogEntry: Identifiable, Hashable, Codable {
    let id: UUID
    let timestamp: Date
    let level: AppLogLevel
    let source: String
    let message: String

    init(
        id: UUID = UUID(),
        timestamp: Date = .now,
        level: AppLogLevel,
        source: String,
        message: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.message = message
    }
}

nonisolated struct AppLogExportArtifact {
    let suggestedFilename: String
    let data: Data
}

private nonisolated struct AppLogExportEnvelope: Codable {
    let exportedAt: Date
    let entryCount: Int
    let entries: [AppLogEntry]
}

@MainActor
class AppLogStore {
    static let shared = AppLogStore()

    private(set) var entries: [AppLogEntry] = []
    private let formatter = ISO8601DateFormatter()

    func debug(_ message: String, source: String) {
        append(level: .debug, message: message, source: source)
    }

    func info(_ message: String, source: String) {
        append(level: .info, message: message, source: source)
    }

    func warning(_ message: String, source: String) {
        append(level: .warning, message: message, source: source)
    }

    func error(_ message: String, source: String) {
        append(level: .error, message: message, source: source)
    }

    func clear() {
        entries.removeAll()
        NotificationCenter.default.post(name: .appLogsDidChange, object: self)
    }

    func exportText() -> String {
        entries.reversed().map {
            "[\(formatter.string(from: $0.timestamp))] [\($0.level.rawValue)] [\($0.source)] \($0.message)"
        }
        .joined(separator: "\n")
    }

    func exportStructuredJSON() throws -> String {
        let envelope = AppLogExportEnvelope(
            exportedAt: .now,
            entryCount: entries.count,
            entries: entries.reversed()
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(envelope)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return json
    }

    func exportArtifacts() throws -> [AppLogExportArtifact] {
        let structuredJSON = try exportStructuredJSON()
        return [
            AppLogExportArtifact(
                suggestedFilename: "cenfc-logs.txt",
                data: Data(exportText().utf8)
            ),
            AppLogExportArtifact(
                suggestedFilename: "cenfc-logs.json",
                data: Data(structuredJSON.utf8)
            ),
        ]
    }

    private static let maxEntries = 1000

    private func append(level: AppLogLevel, message: String, source: String) {
        entries.insert(AppLogEntry(level: level, source: source, message: message), at: 0)
        if entries.count > Self.maxEntries {
            entries.removeLast(entries.count - Self.maxEntries)
        }
        NotificationCenter.default.post(name: .appLogsDidChange, object: self)
    }
}

/// Bridges ``NFCLogger`` output from the library into ``AppLogStore``.
///
/// Debug messages carry raw APDUs and responses (card UIDs, transit history,
/// authentication exchanges), so they are forwarded only in Debug builds;
/// Release builds keep info and error messages only.
nonisolated struct AppNFCLogBridge: NFCLogger {
    /// Whether this build forwards ``LogLevel/debug`` messages.
    static var forwardsDebugMessages: Bool {
        #if DEBUG
            true
        #else
            false
        #endif
    }

    var includesDebugMessages = Self.forwardsDebugMessages

    /// Whether a message at `level` reaches the in-app log.
    static func shouldForward(_ level: LogLevel, includesDebugMessages: Bool) -> Bool {
        switch level {
        case .debug: includesDebugMessages
        case .info, .error: true
        }
    }

    func log(_ level: LogLevel, _ message: String, source: String) {
        guard Self.shouldForward(level, includesDebugMessages: includesDebugMessages) else { return }
        Task { @MainActor in
            switch level {
            case .debug:
                AppLogStore.shared.debug(message, source: source)
            case .info:
                AppLogStore.shared.info(message, source: source)
            case .error:
                AppLogStore.shared.error(message, source: source)
            }
        }
    }
}
