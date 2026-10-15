import Foundation

/// Runs at most one task at a time.
///
/// Screens use it for NFC actions so a fast double tap cannot start a second
/// reader session while the first one is still being set up, and so a screen
/// can cancel its pending work when it is popped.
@MainActor
final class SingleTaskRunner {
    private var task: Task<Void, Never>?
    private var generation = 0

    var isRunning: Bool {
        task != nil
    }

    /// Starts `operation` unless another operation is still running.
    /// - Returns: `false` when the call was ignored because a task is already running.
    @discardableResult
    func run(_ operation: @escaping @MainActor () async -> Void) -> Bool {
        guard task == nil else { return false }
        generation += 1
        let current = generation
        task = Task { [weak self] in
            await operation()
            guard let self, generation == current else { return }
            task = nil
        }
        return true
    }

    /// Cancels the running task, if any, and allows a new one to start.
    func cancel() {
        task?.cancel()
        task = nil
    }
}
