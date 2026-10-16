import Foundation

/// Captures stdout output and forwards it to AppLogStore.
///
/// Uses `Pipe` + `dup2` to intercept file descriptor writes,
/// similar to Flowdown's approach. Call ``start()`` once at app launch.
nonisolated enum PrintRedirection {
    @MainActor private static var pipe: Pipe?

    @MainActor
    static func start() {
        guard pipe == nil else { return }

        let newPipe = Pipe()
        pipe = newPipe

        // Save original stdout so we can still write to Xcode console.
        // The handler below runs on a background queue, so it captures only this
        // immutable descriptor and never touches main-actor state directly.
        let originalStdout = dup(STDOUT_FILENO)

        // Redirect stdout to pipe
        dup2(newPipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)

        newPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }

            // Forward to original stdout (Xcode console) so debug output isn't lost
            if originalStdout >= 0 {
                data.withUnsafeBytes { bytes in
                    guard let baseAddress = bytes.baseAddress else { return }
                    _ = write(originalStdout, baseAddress, bytes.count)
                }
            }

            guard let text = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
                !text.isEmpty
            else { return }

            Task { @MainActor in
                AppLogStore.shared.debug(text, source: "Print")
            }
        }
    }
}
