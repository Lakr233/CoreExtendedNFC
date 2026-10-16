import Foundation
import UniformTypeIdentifiers

nonisolated enum OpenURLDestination: Equatable {
    case scanner
    case ndef
    case passport
}

nonisolated enum OpenURLRouter {
    static func destination(for url: URL) -> OpenURLDestination? {
        if let destination = destinationForDeclaredType(of: url) {
            return destination
        }
        if let destination = destinationForPathExtension(url.pathExtension) {
            return destination
        }
        return destinationByInspectingFileContents(at: url)
    }

    private static func destinationForDeclaredType(of url: URL) -> OpenURLDestination? {
        guard let contentType = try? url.resourceValues(forKeys: [.contentTypeKey]).contentType else {
            return nil
        }
        if contentType.conforms(to: .cenfc) {
            return .scanner
        }
        if contentType.conforms(to: .cndef) {
            return .ndef
        }
        if contentType.conforms(to: .cenfcPassport) {
            return .passport
        }
        return nil
    }

    private static func destinationForPathExtension(_ pathExtension: String) -> OpenURLDestination? {
        switch pathExtension.lowercased() {
        case "cenfc":
            .scanner
        case "cndef":
            .ndef
        case "cenfcpass":
            .passport
        default:
            nil
        }
    }

    private static func destinationByInspectingFileContents(at url: URL) -> OpenURLDestination? {
        guard let data = try? readData(from: url) else { return nil }
        if (try? NDEFDocument.importRecord(from: data)) != nil {
            return .ndef
        }
        if (try? PassportDocument.importRecord(from: data)) != nil {
            return .passport
        }
        if (try? CardDocument.importEnvelope(from: data)) != nil {
            return .scanner
        }
        return nil
    }

    private static func readData(from url: URL) throws -> Data {
        // Only sniffing: the import screen the file is routed to reads it again
        // and then deletes the Inbox copy.
        try ImportFileReader.read(url, consumingInboxCopy: false)
    }
}
