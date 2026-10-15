import Foundation

/// A value guarded by a lock so it can be shared across threads and tasks.
///
/// The package targets iOS 15, where `Mutex` (iOS 18) and
/// `OSAllocatedUnfairLock` (iOS 16) are unavailable, so this wraps `NSLock`.
/// Keep critical sections short and never call out to user code or `await`
/// while holding the lock.
final class LockedValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    /// Run `body` with exclusive access to the stored value.
    func withLock<Result>(_ body: (inout Value) throws -> Result) rethrows -> Result {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }
}
