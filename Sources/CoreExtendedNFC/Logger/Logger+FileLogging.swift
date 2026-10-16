import Foundation
import OSLog

/// Picks a log category from an explicit name or, failing that, the caller's file ID.
public enum LogCategoryResolver {
    public static func resolve(category: String?, fileID: String) -> String {
        if let category, !category.isEmpty { return category }

        let lowercased = fileID.lowercased()
        if lowercased.contains("model") { return "Model" }
        if lowercased.contains("network") { return "Network" }
        if lowercased.contains("ui") || lowercased.contains("view") || lowercased.contains("controller") { return "UI" }
        if lowercased.contains("storage") || lowercased.contains("database") { return "Database" }
        return "App"
    }
}

public extension Logger {
    func nfcDebugFile(_ message: String, category: String? = nil, fileID: String = #fileID) {
        logToFile(.debug, message, category: category, fileID: fileID)
    }

    func nfcInfoFile(_ message: String, category: String? = nil, fileID: String = #fileID) {
        logToFile(.info, message, category: category, fileID: fileID)
    }

    func nfcErrorFile(_ message: String, category: String? = nil, fileID: String = #fileID) {
        logToFile(.error, message, category: category, fileID: fileID)
    }

    private func logToFile(_ level: LogLevel, _ message: String, category: String?, fileID: String) {
        log(level: level.osLogType, "\(message)")
        let resolvedCategory = LogCategoryResolver.resolve(category: category, fileID: fileID)
        LogStore.shared.append(level: level, category: resolvedCategory, message: message)
    }
}

public extension LogLevel {
    /// The matching `OSLogType`.
    var osLogType: OSLogType {
        switch self {
        case .debug: .debug
        case .info: .info
        case .error: .error
        }
    }
}
