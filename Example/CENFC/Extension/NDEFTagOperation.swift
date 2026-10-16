import CoreExtendedNFC
import UIKit

/// An NDEF write or format run in one reader session.
nonisolated enum NDEFTagOperation: Sendable {
    /// Writes a fresh Capability Container and an empty NDEF message.
    case format
    case write(NDEFMessage, summary: String?)
    /// Formats the tag, then writes the message in the same session.
    case formatAndWrite(NDEFMessage, summary: String?)

    /// Whether the operation erases the tag.
    var isDestructive: Bool {
        switch self {
        case .format, .formatAndWrite: true
        case .write: false
        }
    }

    /// Whether `error` from a write means the tag has no NDEF Capability
    /// Container yet (a factory-blank Ultralight / NTAG / ICODE), so formatting
    /// it would let the write succeed.
    ///
    /// CoreExtendedNFC reports this as ``NFCError/unsupportedOperation(_:)``
    /// with a "not NDEF formatted" reason.
    static func isNotFormattedError(_ error: Error) -> Bool {
        guard case let .unsupportedOperation(reason)? = error as? NFCError else { return false }
        return reason.range(of: "not NDEF formatted", options: .caseInsensitive) != nil
    }
}

extension UIViewController {
    /// Runs `operation` on a tag the user taps, through `runner`.
    ///
    /// Formatting erases the tag, so a destructive operation first asks for
    /// confirmation. A write that fails because the tag is not NDEF formatted
    /// offers to format the tag and write again (with the same confirmation).
    func runNDEFTagOperation(_ operation: NDEFTagOperation, runner: SingleTaskRunner) {
        guard operation.isDestructive else {
            runner.run { [weak self] in
                await self?.performNDEFTagOperation(operation, runner: runner)
            }
            return
        }
        confirmFormat(writesAfterwards: !operation.isFormatOnly) { [weak self] in
            runner.run {
                await self?.performNDEFTagOperation(operation, runner: runner)
            }
        }
    }

    private func performNDEFTagOperation(_ operation: NDEFTagOperation, runner: SingleTaskRunner) async {
        let manager = NFCSessionManager()
        do {
            let (coarseInfo, transport) = try await manager.scan(for: [.all])
            // The screen may have been closed while the system sheet was up.
            try Task.checkCancellation()
            let info = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)
            switch operation {
            case .format:
                manager.setAlertMessage(String(localized: "Formatting…"))
                try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)
                manager.setAlertMessage(String(localized: "Format complete"))
            case let .write(message, summary):
                manager.setAlertMessage(String(localized: "Writing NDEF…"))
                try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
                manager.setAlertMessage(Self.writeCompleteMessage(summary: summary))
            case let .formatAndWrite(message, summary):
                manager.setAlertMessage(String(localized: "Formatting…"))
                try await CoreExtendedNFC.formatNDEF(info: info, transport: transport)
                manager.setAlertMessage(String(localized: "Writing NDEF…"))
                try await CoreExtendedNFC.writeNDEF(message, info: info, transport: transport)
                manager.setAlertMessage(Self.writeCompleteMessage(summary: summary))
            }
            manager.invalidate()
        } catch {
            manager.invalidate(after: error)
            if presentNFCErrorAlertIfNeeded(for: error, session: manager) {
                return
            }
            if case let .write(message, summary) = operation, NDEFTagOperation.isNotFormattedError(error) {
                offerFormatAndWrite(message, summary: summary, runner: runner)
            } else {
                presentErrorAlert(for: error)
            }
        }
    }

    private static func writeCompleteMessage(summary: String?) -> String {
        guard let summary else { return String(localized: "Write complete") }
        return String(localized: "Write complete (\(summary))")
    }

    private func offerFormatAndWrite(_ message: NDEFMessage, summary: String?, runner: SingleTaskRunner) {
        let alert = UIAlertController(
            title: String(localized: "Tag Not Formatted"),
            message: String(localized: "This tag has no NDEF data area yet. Format it for NDEF and then write the message?"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Format…"), style: .default) { [weak self] _ in
            self?.runNDEFTagOperation(.formatAndWrite(message, summary: summary), runner: runner)
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        presentQueued(alert)
    }

    private func confirmFormat(writesAfterwards: Bool, onConfirm: @escaping () -> Void) {
        let alert = UIAlertController(
            title: String(localized: "Format Tag?"),
            message: writesAfterwards
                ? String(localized: "Formatting erases everything stored in the tag's user memory and writes a new NDEF data area, then writes your message. This cannot be undone.")
                : String(localized: "Formatting erases everything stored in the tag's user memory and writes a new, empty NDEF data area. This cannot be undone."),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "Format"), style: .destructive) { _ in
            onConfirm()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        presentQueued(alert)
    }
}

private nonisolated extension NDEFTagOperation {
    var isFormatOnly: Bool {
        if case .format = self { return true }
        return false
    }
}
