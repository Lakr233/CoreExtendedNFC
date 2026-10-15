@testable import CoreExtendedNFC
import Foundation
import Testing

struct LogStoreTests {
    @Test
    func `append writes formatted line and readTail returns it`() throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        store.append(level: .info, category: "Tests", message: "hello world")
        store.flush()

        let text = store.readTail()
        #expect(text.contains("[INFO]"))
        #expect(text.contains("[Tests]"))
        #expect(text.contains("hello world"))
    }

    @Test
    func `readTail limits output to requested byte count`() throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        // Markers must not occur inside the ISO 8601 timestamp: a bare "0-" matched
        // dates such as "2026-10-15" and made this test fail every October.
        let message = String(repeating: "x", count: 40)
        for index in 0 ..< 5 {
            store.append(level: .debug, category: "Tail", message: "entry#\(index)#\(message)")
        }
        store.flush()

        let tail = store.readTail(maxBytes: 128)
        #expect(!tail.contains("entry#0#"))
        #expect(!tail.contains("entry#3#"))
        #expect(tail.contains("entry#4#"))
        #expect(tail.utf8.count <= 128)
        #expect(tail.hasSuffix("\n"))
    }

    @Test
    func `readTail survives a cut inside a multibyte character`() throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        // "é" is C3 A9. 10 × 2 bytes + "\nlast\n" = 26 bytes; a 25-byte tail starts on 0xA9.
        let content = Data(String(repeating: "é", count: 10).utf8) + Data("\nlast\n".utf8)
        #expect(FileManager.default.createFile(atPath: store.logFileURL.path, contents: content))

        let tail = store.readTail(maxBytes: 25)
        #expect(tail == "last\n")
    }

    @Test
    func `readTail of a single partial line skips continuation bytes`() {
        let data = Data([0xA9, 0xC3, 0xA9, 0x41])
        #expect(LogStore.decodeTail(data, isTruncated: true) == "éA")
        #expect(LogStore.decodeTail(Data("ok".utf8), isTruncated: false) == "ok")
    }

    @Test
    func `clear does not trap when maxFiles is zero`() throws {
        let (store, directory) = try makeStore(maxFiles: 0)
        defer { try? FileManager.default.removeItem(at: directory) }

        store.append(level: .info, category: "Zero", message: "one")
        store.flush()
        store.clear()

        #expect(store.readTail().isEmpty)
    }

    @Test
    func `synchronous calls on the store's own queue do not deadlock`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let queue = DispatchQueue(label: "LogStoreTests.custom")
        let store = LogStore(directory: directory, queue: queue)

        store.append(level: .info, category: "Queue", message: "on-queue")
        let finished = DispatchSemaphore(value: 0)
        let tail = LockedValue("")
        queue.async {
            store.flush()
            let text = store.readTail()
            tail.withLock { $0 = text }
            store.clear()
            finished.signal()
        }

        #expect(finished.wait(timeout: .now() + 5) == .success)
        #expect(tail.withLock { $0 }.contains("on-queue"))
    }

    @Test
    func `logger configuration tolerates concurrent reads and writes`() async {
        let previous = NFCLogConfiguration.logger
        defer { NFCLogConfiguration.logger = previous }

        await withTaskGroup(of: Void.self) { group in
            for index in 0 ..< 64 {
                group.addTask {
                    if index.isMultiple(of: 2) {
                        NFCLogConfiguration.logger = CountingLogger()
                    } else {
                        NFCLog.debug("probe", source: "Tests")
                    }
                }
            }
        }
        #expect(NFCLogConfiguration.logger != nil)
    }

    @Test
    func `log files rotate once max size is reached`() throws {
        let (store, directory) = try makeStore(maxFileSize: 128, maxFiles: 2)
        defer { try? FileManager.default.removeItem(at: directory) }
        let manager = FileManager.default

        for index in 0 ..< 12 {
            store.append(level: .info, category: "Rotate", message: "line-\(index)")
        }
        store.flush()

        #expect(manager.fileExists(atPath: store.logFileURL.path))
        #expect(manager.fileExists(atPath: store.rotatedFileURL(index: 1).path))
        #expect(manager.fileExists(atPath: store.rotatedFileURL(index: 2).path))
        #expect(!manager.fileExists(atPath: store.rotatedFileURL(index: 3).path))
    }

    @Test
    func `rotate keeps newest content in base file after rolling over`() throws {
        let (store, directory) = try makeStore(maxFileSize: 96, maxFiles: 2)
        defer { try? FileManager.default.removeItem(at: directory) }

        for index in 0 ..< 6 { // likely triggers rotation at least once
            store.append(level: .info, category: "Rotate", message: "entry-\(index)")
        }
        // Write once more after rotation to ensure base file has fresh content
        store.append(level: .info, category: "Rotate", message: "latest-entry")
        store.flush()

        let tail = store.readTail(maxBytes: 256)
        #expect(tail.contains("latest-entry"))
    }

    @Test
    func `clear removes files even after rotation happened`() throws {
        let (store, directory) = try makeStore(maxFileSize: 96, maxFiles: 2)
        defer { try? FileManager.default.removeItem(at: directory) }

        for index in 0 ..< 6 {
            store.append(level: .info, category: "Rotate", message: "entry-\(index)")
        }
        store.flush()

        store.clear()

        let contents = (try? FileManager.default.contentsOfDirectory(at: store.logDirectory, includingPropertiesForKeys: nil)) ?? []
        #expect(contents.isEmpty)
    }

    @Test
    func `readTail returns empty string when file does not exist`() throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        store.clear()
        let tail = store.readTail()
        #expect(tail.isEmpty)
    }

    @Test
    func `clear removes base and rotated log files`() throws {
        let (store, directory) = try makeStore(maxFileSize: 128, maxFiles: 2)
        defer { try? FileManager.default.removeItem(at: directory) }

        store.append(level: .error, category: "Cleanup", message: "boom")
        store.append(level: .error, category: "Cleanup", message: "boom2")
        store.flush()

        store.clear()

        let contents = (try? FileManager.default.contentsOfDirectory(at: store.logDirectory, includingPropertiesForKeys: nil)) ?? []
        #expect(contents.isEmpty)
    }

    @Test
    func `category resolver infers sensible defaults`() {
        #expect(LogCategoryResolver.resolve(category: nil, fileID: "/tmp/ModelInference.swift") == "Model")
        #expect(LogCategoryResolver.resolve(category: nil, fileID: "/tmp/NetworkService.swift") == "Network")
        #expect(LogCategoryResolver.resolve(category: nil, fileID: "/tmp/UserInterfaceView.swift") == "UI")
        #expect(LogCategoryResolver.resolve(category: nil, fileID: "/tmp/DatabaseManager.swift") == "Database")
        #expect(LogCategoryResolver.resolve(category: nil, fileID: "/tmp/Other.swift") == "App")
        #expect(LogCategoryResolver.resolve(category: "Custom", fileID: "/tmp/Other.swift") == "Custom")
    }
}

private struct CountingLogger: NFCLogger {
    func log(_: LogLevel, _: String, source _: String) {}
}

private func makeStore(maxFileSize: Int = 512, maxFiles: Int = 3) throws -> (LogStore, URL) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = LogStore(directory: directory, fileManager: .default, maxFileSize: maxFileSize, maxFiles: maxFiles)
    return (store, directory)
}
