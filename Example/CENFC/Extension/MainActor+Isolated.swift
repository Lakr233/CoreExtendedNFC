import Foundation

extension MainActor {
    /// A safe alternative to `assumeIsolated` that dispatches to the main thread
    /// synchronously when not already on it, avoiding crashes from incorrect
    /// thread assumptions.
    static func isolated<T>(_ operation: @MainActor () throws -> T) rethrows -> T {
        if Thread.isMainThread {
            return try MainActor.assumeIsolated(operation)
        } else {
            return try DispatchQueue.main.sync {
                try MainActor.assumeIsolated(operation)
            }
        }
    }
}
